"""Bouw ``backend/data/yubico_fido_roots.pem`` uit de officiële Yubico-PKI-bestanden (Koblitz).

Reproduceerbaar (docs/HARDWARE_KEYS.md §12.4)::

    mkdir -p /tmp/ykpki && cd /tmp/ykpki
    for f in yubico-fido-ca-1.pem yubico-fido-ca-2.pem yubico-ca-1.pem yubico-intermediate.pem; do
        curl -sSLO https://developers.yubico.com/PKI/$f
    done
    python -I backend/tools/build_yubico_roots.py /tmp/ykpki --fetched-at 2026-10-10

Alleen FIDO-relevant materiaal komt in het bestand:

- de self-signed roots die FIDO-attestation tekenen (U2F Root CA 457200631, FIDO Root CA
  450203556, Attestation Root 1);
- de FIDO-intermediates onder Attestation Root 1 (YubiKey-firmware 5.7.4+ kan alleen het
  leafcertificaat in ``x5c`` meesturen). PIV/OpenPGP/SD/HSM-intermediates blijven eruit.

Elke intermediate moet aantoonbaar door een opgenomen certificaat getekend zijn; anders stopt het
script. Publiek materiaal, geen secrets.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

BASE_URL = "https://developers.yubico.com/PKI/"
ROOT_FILES = ("yubico-fido-ca-1.pem", "yubico-fido-ca-2.pem", "yubico-ca-1.pem")
INTERMEDIATE_FILE = "yubico-intermediate.pem"
FIDO_INTERMEDIATE_CNS = (
    "Yubico Attestation Intermediate A 1",
    "Yubico Attestation Intermediate B 1",
    "Yubico FIDO Attestation A 1",
    "Yubico FIDO Attestation B 1",
    "Yubico FIDO Attestation B2 1",
)


def _cn(c: x509.Certificate) -> str:
    attrs = c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else c.subject.rfc4514_string()


def _block(c: x509.Certificate, source: str, fetched_at: str, role: str) -> str:
    fp = c.fingerprint(hashes.SHA256()).hex(":").upper()
    return (
        f"# {role}: {c.subject.rfc4514_string()}\n"
        f"#   uitgever:  {c.issuer.rfc4514_string()}\n"
        f"#   geldig:    {c.not_valid_before_utc.date()} t/m {c.not_valid_after_utc.date()}\n"
        f"#   bron:      {source} (opgehaald {fetched_at})\n"
        f"#   SHA-256:   {fp}\n" + c.public_bytes(Encoding.PEM).decode("ascii")
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("srcdir", type=Path, help="map met de gedownloade Yubico-PKI-bestanden")
    ap.add_argument(
        "--out", type=Path, default=Path(__file__).parent.parent / "data" / "yubico_fido_roots.pem"
    )
    ap.add_argument("--fetched-at", default=dt.date.today().isoformat())
    a = ap.parse_args(argv)

    roots: list[tuple[x509.Certificate, str]] = []
    for name in ROOT_FILES:
        for c in x509.load_pem_x509_certificates((a.srcdir / name).read_bytes()):
            if c.issuer != c.subject:
                raise SystemExit(f"{name}: {_cn(c)} is niet self-signed")
            c.verify_directly_issued_by(c)
            roots.append((c, BASE_URL + name))
    inters: list[tuple[x509.Certificate, str]] = []
    pool = x509.load_pem_x509_certificates((a.srcdir / INTERMEDIATE_FILE).read_bytes())
    for c in pool:
        if _cn(c) in FIDO_INTERMEDIATE_CNS:
            inters.append((c, BASE_URL + INTERMEDIATE_FILE))
    if {_cn(c) for c, _ in inters} != set(FIDO_INTERMEDIATE_CNS):
        raise SystemExit("niet alle verwachte FIDO-intermediates gevonden")
    known = [c for c, _ in roots]
    for c, _ in inters:  # volgorde in het bestand: Intermediate A/B vóór FIDO A/B/B2
        issuer = next((k for k in known if k.subject == c.issuer), None)
        if issuer is None:
            raise SystemExit(f"{_cn(c)}: uitgever niet gevonden")
        c.verify_directly_issued_by(issuer)
        known.append(c)

    head = (
        "# HorseSafe v0.2.0-Koblitz - Yubico FIDO-attestation-vertrouwensanker\n"
        "# Gegenereerd door backend/tools/build_yubico_roots.py; niet met de hand bewerken.\n"
        f"# Bron: {BASE_URL} (ondertekende index: {BASE_URL}yubico-ca-certs.txt)\n"
        "# Roots + FIDO-intermediates; PIV/OpenPGP/SD/HSM bewust weggelaten.\n\n"
    )
    body = "\n".join(_block(c, s, a.fetched_at, "root") for c, s in roots)
    body += "\n" + "\n".join(_block(c, s, a.fetched_at, "intermediate") for c, s in inters)
    a.out.write_text(head + body, encoding="ascii")
    print(f"{len(roots)} roots + {len(inters)} intermediates -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
