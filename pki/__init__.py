"""Cryptographic transport primitives that make the PKI meaningful.

  - envelope.py    — signed request envelopes (proof-of-possession per call);
                     only the public certificate and a signature travel.
                     Private keys are never exposed.
  - delegation.py  — user-signed delegation assertions; instead of the user
                     passing their cert, they sign a delegation that agents
                     carry with them instead, that says "I am authorized to
                     act on behalf of this end-user.
  - ocsp.py        — shared fail-closed OCSP revocation check.
  - keys.py        — extracts (cert_pem, key_pem) from a stored P12.
"""
