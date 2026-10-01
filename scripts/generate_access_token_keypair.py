#!/usr/bin/env python3
"""Generate an RSA key for RS256 access tokens and print the keyset JSON.

stdout carries ONLY the JSON keyset ({"active": kid, "keys": {kid: PEM}}), so
it can be piped straight into Secrets Manager without touching disk:

    python scripts/generate_access_token_keypair.py \
      | aws secretsmanager create-secret \
          --name prod/herm/auth/access-token-signing-keys \
          --secret-string file:///dev/stdin

Rotation is two-phase so no auth task ever signs with a kid that another
(older) task's JWKS does not publish yet:

  phase A - publish the new key, keep the current one active:
    aws secretsmanager get-secret-value --secret-id prod/herm/auth/access-token-signing-keys \
          --query SecretString --output text \
      | python scripts/generate_access_token_keypair.py --add-to - --no-activate \
      | aws secretsmanager put-secret-value --secret-id prod/herm/auth/access-token-signing-keys \
          --secret-string file:///dev/stdin
    (redeploy auth)
  phase B - make it active:          ... --add-to - --no-new --set-active <new kid> ...
  phase C - retire the old key:      ... --add-to - --no-new --drop <old kid> ...
    (each followed by an auth redeploy; phase C only after the old kid's
    tokens expired)

stderr shows kids only; stdout is only the JSON. See projects/docs/rs256-gecis-plani.md.
"""
import argparse
import json
import secrets
import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bits", type=int, choices=(2048, 3072, 4096), default=2048,
                        help="RSA size (2048 default: matches the OIDC KMS key; 3072 signs ~2.5x slower and adds ~170 chars per token)")
    parser.add_argument("--kid", help="kid for the new key (default at-YYYYMMDD-<random>)")
    parser.add_argument("--add-to", metavar="FILE", help="existing keyset JSON to extend ('-' = stdin)")
    parser.add_argument("--drop", metavar="KID", action="append", default=[], help="remove KID from the keyset")
    parser.add_argument("--no-new", action="store_true", help="do not generate a key")
    parser.add_argument("--no-activate", action="store_true", help="add the new key without making it active")
    parser.add_argument("--set-active", metavar="KID", help="make an existing KID the active key")
    args = parser.parse_args()

    keyset = {"active": None, "keys": {}}
    if args.add_to:
        src = sys.stdin if args.add_to == "-" else open(args.add_to, encoding="utf-8")
        with src:
            keyset = json.load(src)

    if not args.no_new:
        kid = args.kid or f"at-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3)}"
        if not kid.startswith("at-"):
            parser.error("kid must start with 'at-'")
        if kid in keyset["keys"]:
            parser.error(f"kid {kid} already exists")
        key = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
        keyset["keys"][kid] = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        if not args.no_activate or not keyset["active"]:
            keyset["active"] = kid

    if args.set_active:
        if args.set_active not in keyset["keys"]:
            parser.error(f"kid {args.set_active} is not in the keyset")
        keyset["active"] = args.set_active

    for kid in args.drop:
        if kid == keyset["active"]:
            parser.error(f"refusing to drop the active kid {kid}")
        keyset["keys"].pop(kid, None)

    if keyset["active"] not in keyset["keys"]:
        parser.error("resulting keyset has no active key")
    json.dump(keyset, sys.stdout)
    sys.stdout.write("\n")
    # kids only, on stderr, so stdout stays pure JSON
    print(f"active={keyset['active']} kids={sorted(keyset['keys'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
