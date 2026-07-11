"""OIDC authorization-server flow endpoints (Login with Herm).

Mounted at the issuer root: /herm-auth/oidc/*. Gated behind
OIDC_PROVIDER_ENABLED AND OIDC_FLOWS_ENABLED so a half-built flow is never live.

This module currently implements /authorize (2-B). /authorize is SESSION-BLIND:
it never inspects the consumer session (the app-origin refresh cookie is not
sent to api.herm.io). It validates the request, sets a browser-binding cookie,
and hands off to the consent page. Login detection happens on the consent page.
"""
import base64
import hashlib
import hmac
import json
import logging
from typing import Optional
from urllib.parse import urlencode, urlsplit, urlunsplit

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.middleware.rate_limit import enforce_rate_limit, rate_limit_oidc_authorize
from app.models.oauth_client import OAuthClient
from app.models.oauth_refresh_token import OAuthRefreshToken
from app.models.user import User
from app.repositories.oauth_client_repository import OAuthClientRepository
from app.repositories.oauth_consent_repository import OAuthConsentRepository
from app.repositories.user_repository import UserRepository
from app.services.oidc_key_service import oidc_key_service
from app.services.oidc_state_service import oidc_state_service, new_token
from app.services.oidc_token_service import oidc_token_service, ACCESS_TOKEN_AUD

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oidc", tags=["oidc"])

BINDING_COOKIE = "__Host-oidc_bind"
SUPPORTED_SCOPES = {"openid", "email", "profile"}


def _require_flows() -> None:
    if not _flows_enabled():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


def _no_referrer(resp: RedirectResponse) -> RedirectResponse:
    # The global security middleware already sets Referrer-Policy to
    # strict-origin-when-cross-origin (origin-only Referer → the code/state in
    # the query never leak cross-site); we also request no-referrer here.
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


class ConsentContext(BaseModel):
    client_name: str
    logo_url: Optional[str] = None
    scopes: list[str]
    already_granted: bool


class ConsentDecision(BaseModel):
    request_id: str
    approved: bool


def _flows_enabled() -> bool:
    return settings.OIDC_PROVIDER_ENABLED and settings.OIDC_FLOWS_ENABLED


def _error_page(code: str) -> RedirectResponse:
    """Terminal error on our own origin — never redirects to a client URL."""
    url = f"{settings.OIDC_ERROR_URL}?{urlencode({'error': code})}"
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


def _client_redirect_error(redirect_uri: str, error: str, state: str | None) -> RedirectResponse:
    """Redirect back to a VALIDATED redirect_uri with an OAuth error (RFC 6749 §4.1.2.1)."""
    params = {"error": error}
    if state:
        params["state"] = state
    parts = urlsplit(redirect_uri)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return RedirectResponse(urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), status_code=status.HTTP_302_FOUND)


@router.get("/authorize")
async def authorize(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _rl: None = Depends(rate_limit_oidc_authorize),
):
    if not _flows_enabled():
        return _error_page("temporarily_unavailable")

    q = request.query_params
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    response_type = q.get("response_type")
    scope = q.get("scope", "")
    state = q.get("state")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")
    nonce = q.get("nonce")

    # --- client + redirect_uri: validate BEFORE any redirect (open-redirect guard)
    if not client_id or not redirect_uri:
        return _error_page("invalid_request")
    client = await OAuthClientRepository(db).get_by_client_id(client_id)
    if client is None or not client.is_usable:
        return _error_page("unauthorized_client")
    if redirect_uri not in (client.redirect_uris or []):
        return _error_page("invalid_redirect_uri")

    # --- from here redirect_uri is trusted; OAuth errors go back to the client
    if response_type != "code":
        return _client_redirect_error(redirect_uri, "unsupported_response_type", state)
    if not state:
        return _client_redirect_error(redirect_uri, "invalid_request", None)
    if code_challenge_method != "S256" or not code_challenge:
        # PKCE S256 is mandatory for all clients.
        return _client_redirect_error(redirect_uri, "invalid_request", state)

    requested = [s for s in scope.split(" ") if s]
    if "openid" not in requested:
        return _client_redirect_error(redirect_uri, "invalid_scope", state)
    if set(requested) - set(client.allowed_scopes or []):
        return _client_redirect_error(redirect_uri, "invalid_scope", state)

    # --- valid: park the request, bind the browser, hand off to consent
    request_id = new_token()
    binding = new_token()
    await oidc_state_service.put_request(request.app.state.redis, request_id, {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scopes": requested,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
        "browser_binding": binding,
    })

    resp = RedirectResponse(f"{settings.OIDC_CONSENT_URL}#request_id={request_id}", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=BINDING_COOKIE,
        value=binding,
        max_age=settings.OIDC_BINDING_COOKIE_TTL_SECONDS,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    logger.info("oidc authorize client_id=%s request_id=%s", client_id, request_id)
    return resp


@router.get("/consent/context", response_model=ConsentContext)
async def consent_context(
    request: Request,
    request_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Details for the consent screen. Only reveals data for a valid request_id."""
    _require_flows()
    req = await oidc_state_service.peek_request(request.app.state.redis, request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown or expired request")
    client = await OAuthClientRepository(db).get_by_client_id(req["client_id"])
    if client is None or not client.is_usable:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown client")

    consent = await OAuthConsentRepository(db).get(user.id, req["client_id"])
    already = bool(
        consent and consent.revoked_at is None
        and set(req["scopes"]).issubset(set(consent.granted_scopes or []))
    )
    return ConsentContext(
        client_name=client.client_name,
        logo_url=client.logo_url,
        scopes=req["scopes"],
        already_granted=already,
    )


@router.post("/consent/decision")
async def consent_decision(
    request: Request,
    payload: ConsentDecision,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Record the consumer's approve/deny and return the AS finish URL.

    The authorization code is NEVER produced here (would put it in the SPA's
    JS). We consume the request (single-use), persist consent on approval, and
    mint a one-time verifier the browser presents to /authorize/finish.
    """
    _require_flows()
    req = await oidc_state_service.take_request(request.app.state.redis, payload.request_id)
    if req is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown or expired request")

    data = {
        "approved": bool(payload.approved),
        "redirect_uri": req["redirect_uri"],
        "state": req.get("state"),
        "browser_binding": req["browser_binding"],
    }
    if payload.approved:
        await OAuthConsentRepository(db).upsert(user.id, req["client_id"], req["scopes"])
        data.update({
            "client_id": req["client_id"],
            "user_id": str(user.id),
            "scopes": req["scopes"],
            "code_challenge": req["code_challenge"],
            "code_challenge_method": req["code_challenge_method"],
            "nonce": req.get("nonce"),
        })
        logger.info("oidc consent approved user=%s client=%s", user.id, req["client_id"])
    else:
        logger.info("oidc consent denied user=%s client=%s", user.id, req["client_id"])

    verifier = new_token()
    await oidc_state_service.put_verifier(request.app.state.redis, verifier, data)
    return {"finish_url": f"{settings.OIDC_ISSUER}/oidc/authorize/finish?{urlencode({'verifier': verifier})}"}


@router.get("/authorize/finish")
async def authorize_finish(request: Request, verifier: str):
    """Consume the verifier, enforce browser binding, and emit the AS-controlled
    302 to the client (code+state+iss on approval, error on denial)."""
    _require_flows()
    data = await oidc_state_service.take_verifier(request.app.state.redis, verifier)
    if data is None:
        return _error_page("invalid_request")

    # Browser binding: the cookie set at /authorize must match. Blocks a
    # cross-browser verifier replay / forced-login (attacker-minted verifier
    # opened in the victim's browser).
    cookie = request.cookies.get(BINDING_COOKIE)
    if not cookie or not hmac.compare_digest(cookie, data.get("browser_binding", "")):
        return _error_page("access_denied")

    redirect_uri = data["redirect_uri"]
    state = data.get("state")

    if not data.get("approved"):
        return _no_referrer(_client_redirect_error(redirect_uri, "access_denied", state))

    code = new_token()
    await oidc_state_service.put_code(request.app.state.redis, code, {
        "client_id": data["client_id"],
        "user_id": data["user_id"],
        "scopes": data["scopes"],
        "redirect_uri": redirect_uri,
        "code_challenge": data["code_challenge"],
        "code_challenge_method": data["code_challenge_method"],
        "nonce": data.get("nonce"),
    })
    params = {"code": code, "state": state, "iss": settings.OIDC_ISSUER}
    parts = urlsplit(redirect_uri)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    resp = RedirectResponse(urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), status_code=status.HTTP_302_FOUND)
    logger.info("oidc finish issued code client=%s user=%s", data["client_id"], data["user_id"])
    return _no_referrer(resp)


# --- /token ---------------------------------------------------------------------

def _token_error(error: str, code: int = 400) -> JSONResponse:
    return JSONResponse(status_code=code, content={"error": error}, headers={"Cache-Control": "no-store"})


def _client_credentials(request: Request, form) -> tuple[Optional[str], Optional[str]]:
    """Extract (client_id, client_secret) from HTTP Basic or the form body."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Basic "):
        try:
            cid, _, secret = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
            return cid, secret
        except Exception:
            return None, None
    return form.get("client_id"), form.get("client_secret")


def _verify_pkce(code_verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, challenge)


@router.post("/token")
async def token(request: Request, db: AsyncSession = Depends(get_db)):
    _require_flows()
    form = await request.form()
    grant_type = form.get("grant_type")

    if grant_type == "refresh_token" and not settings.OIDC_OFFLINE_ACCESS_ENABLED:
        return _token_error("unsupported_grant_type")
    if grant_type != "authorization_code":
        return _token_error("unsupported_grant_type")

    # --- client authentication
    client_id, client_secret = _client_credentials(request, form)
    if not client_id:
        return _token_error("invalid_client", 401)
    client = await OAuthClientRepository(db).get_by_client_id(client_id)
    if client is None or not client.is_usable:
        return _token_error("invalid_client", 401)
    if client.client_type == "confidential":
        if not client_secret or not client.client_secret_hash or not hmac.compare_digest(
            OAuthClient.hash_secret(client_secret), client.client_secret_hash
        ):
            return _token_error("invalid_client", 401)

    await enforce_rate_limit(request, f"oidc_token:{client_id}", max_requests=60, window_seconds=60)

    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    code_verifier = form.get("code_verifier")
    if not code:
        return _token_error("invalid_grant")

    # --- consume the code (single-use); detect replay
    record = await oidc_state_service.take_code(request.app.state.redis, code)
    if record is None:
        if await oidc_state_service.was_code_used(request.app.state.redis, code):
            code_hash = hashlib.sha256(code.encode("ascii")).hexdigest()
            await db.execute(
                update(OAuthRefreshToken)
                .where(OAuthRefreshToken.code_hash == code_hash, OAuthRefreshToken.revoked_at.is_(None))
                .values(revoked_at=func.now())
            )
            logger.warning("SECURITY oidc authorization code REPLAY detected client=%s", client_id)
        return _token_error("invalid_grant")
    await oidc_state_service.mark_code_used(request.app.state.redis, code)

    # --- bind the code to this client + redirect_uri
    if record["client_id"] != client_id:
        return _token_error("invalid_grant")
    if record["redirect_uri"] != redirect_uri:
        return _token_error("invalid_grant")

    # --- PKCE (mandatory) with two-way downgrade protection
    challenge = record.get("code_challenge")
    if challenge:
        if not code_verifier or not _verify_pkce(code_verifier, challenge):
            return _token_error("invalid_grant")
    elif code_verifier:
        return _token_error("invalid_grant")

    # --- mint tokens
    key = await oidc_key_service.ensure_active_key(db)
    user = await UserRepository(db).get_by_id(record["user_id"])
    if user is None:
        return _token_error("invalid_grant")

    scopes = record["scopes"]
    jti = new_token()
    id_token = oidc_token_service.build_id_token(
        kid=key.kid, key_arn=key.kms_key_arn, client_id=client_id, user_id=str(user.id),
        scopes=scopes, email=user.email, email_verified=user.is_verified, nonce=record.get("nonce"),
    )
    access_token = oidc_token_service.build_access_token(
        kid=key.kid, key_arn=key.kms_key_arn, client_id=client_id, user_id=str(user.id), scopes=scopes, jti=jti,
    )
    # Map the access token (by jti) to the user for /userinfo — the token's `sub`
    # is a non-reversible PPID, so the resource lookup needs this server-side link.
    await oidc_state_service.put_access(request.app.state.redis, jti, {
        "user_id": str(user.id), "scopes": scopes, "client_id": client_id,
    })
    logger.info("oidc token issued client=%s user=%s", client_id, user.id)
    return JSONResponse(
        status_code=200,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": settings.OIDC_ACCESS_TOKEN_TTL_SECONDS,
            "id_token": id_token,
            "scope": " ".join(scopes),
        },
    )


# --- /userinfo + /revoke --------------------------------------------------------

def _unauthorized() -> JSONResponse:
    return JSONResponse(
        status_code=401, content={"error": "invalid_token"},
        headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
    )


async def _decode_access_token(token: str, db: AsyncSession) -> Optional[dict]:
    """Verify an access token: RS256 signature (active JWKS key), aud + typ.
    Rejects id_tokens (aud=client_id / typ=JWT)."""
    try:
        key = await oidc_key_service.ensure_active_key(db)
        pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key.public_jwk))
        claims = jwt.decode(token, pub, algorithms=["RS256"], audience=ACCESS_TOKEN_AUD)
    except Exception:
        return None
    try:
        if jwt.get_unverified_header(token).get("typ") != "at+jwt":
            return None
    except Exception:
        return None
    return claims


@router.get("/userinfo")
async def userinfo(request: Request, db: AsyncSession = Depends(get_db)):
    _require_flows()
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return _unauthorized()
    claims = await _decode_access_token(auth[7:], db)
    if not claims:
        return _unauthorized()
    jti = claims.get("jti")
    mapping = await oidc_state_service.get_access(request.app.state.redis, jti) if jti else None
    if not mapping:
        return _unauthorized()  # expired or revoked
    await enforce_rate_limit(request, f"oidc_userinfo:{jti}", max_requests=120, window_seconds=60)
    user = await UserRepository(db).get_by_id(mapping["user_id"])
    if user is None:
        return _unauthorized()
    scopes = mapping.get("scopes", [])
    out = {"sub": claims["sub"]}
    if "email" in scopes:
        out["email"] = user.email
        out["email_verified"] = user.is_verified
    return JSONResponse(status_code=200, content=out, headers={"Cache-Control": "no-store"})


@router.post("/revoke")
async def revoke(request: Request, db: AsyncSession = Depends(get_db)):
    """RFC 7009 token revocation. Always 200, even for unknown tokens."""
    _require_flows()
    form = await request.form()
    client_id, client_secret = _client_credentials(request, form)
    if not client_id:
        return _token_error("invalid_client", 401)
    client = await OAuthClientRepository(db).get_by_client_id(client_id)
    if client is None or not client.is_usable:
        return _token_error("invalid_client", 401)
    if client.client_type == "confidential":
        if not client_secret or not client.client_secret_hash or not hmac.compare_digest(
            OAuthClient.hash_secret(client_secret), client.client_secret_hash
        ):
            return _token_error("invalid_client", 401)

    token = form.get("token")
    if token:
        claims = await _decode_access_token(token, db)
        if claims and claims.get("client_id") == client_id and claims.get("jti"):
            await oidc_state_service.del_access(request.app.state.redis, claims["jti"])
        # Refresh token (offline_access) — best-effort revoke by hash, scoped to client.
        thash = hashlib.sha256(token.encode("ascii")).hexdigest()
        await db.execute(
            update(OAuthRefreshToken)
            .where(
                OAuthRefreshToken.token_hash == thash,
                OAuthRefreshToken.client_id == client_id,
                OAuthRefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=func.now())
        )
    return JSONResponse(status_code=200, content={}, headers={"Cache-Control": "no-store"})
