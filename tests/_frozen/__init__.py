"""Frozen copies of code deployed before the RS256 change, used as test oracles.

Do NOT edit these files. They exist so the RS256 tests can prove that the
OIDC part of discovery/JWKS is unchanged:

  auth_main_well_known.py
      herm-consumer-auth-service origin/main @ 80a78a6 (the discovery/JWKS
      router as deployed before the RS256 change; verbatim).

The HS256 signer/verifier copies (auth_main_security.py, auth_main_jwt_keys.py,
consumer_service_security.py, consumer_service_jwt_keys.py) were removed in
step 4b: HS256 is no longer issued or accepted anywhere, so byte-equality with
the HS256 code is no longer a contract.
"""
