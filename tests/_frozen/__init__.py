"""Frozen copies of code that is deployed today, used as test oracles.

Do NOT edit these files (other than the single import line that points each
security module at its sibling frozen jwt_keys copy). They exist so the
RS256 tests can prove that the default HS256 mode is unchanged:

  auth_main_security.py / auth_main_jwt_keys.py / auth_main_well_known.py
      herm-consumer-auth-service origin/main @ 80a78a6 (the signer and the
      discovery/JWKS router as deployed before the RS256 change;
      auth_main_well_known.py is verbatim, no import changes).
  consumer_service_security.py / consumer_service_jwt_keys.py
      herm-consumer-service origin/main @ ac157f9 (one of the nine HS256
      verifiers; jwt_keys.py is copied verbatim into every verifier).
"""
