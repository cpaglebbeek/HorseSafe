"""Bouw ``backend/data/android_attestation_roots.pem`` uit de Android-documentatie (Miller).

Reproduceerbaar (docs/HARDWARE_KEYS.md §13.5 stap 4)::

    mkdir -p /tmp/androidroots && cd /tmp/androidroots
    curl -sSL -o page.html https://developer.android.com/privacy-and-security/security-key-attestation
    curl -sSL -o roots.json https://android.googleapis.com/attestation/root
    python -I backend/tools/build_android_roots.py /tmp/androidroots/page.html \\
        --json /tmp/androidroots/roots.json --fetched-at 2026-10-14

Het script neemt de certificaten uit de sectie "Root Certificates" van de documentatiepagina (de
vertrouwensankers die Google voorschrijft) en stopt bij "Previously Issued Root Certificates". Met
``--json`` moet de verzameling exact gelijk zijn aan de JSON-array die de pagina linkt; anders stopt
het script. Elke root moet self-signed zijn.

Opgehaald 14-10-2026 (2 roots):

- RSA-4096 ``serialNumber=f92009e853b6b045`` (geldig 2022-03-20 t/m 2042-03-15),
  SHA-256 ``cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc``
- EC P-384 ``CN=Key Attestation CA1`` (geldig 2025-07-17 t/m 2035-07-15; tekent vanaf 1-2-2026),
  SHA-256 ``6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0``

De eerder uitgegeven RSA-roots op dezelfde pagina hebben dezelfde publieke sleutel als de huidige
RSA-root; de server vergelijkt het anker op publieke sleutel (SPKI), dus ketens die op zo'n eerdere
uitgave eindigen worden ook herkend. Publiek materiaal, geen secrets.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

PAGE_URL = "https://developer.android.com/privacy-and-security/security-key-attestation"
JSON_URL = "https://android.googleapis.com/attestation/root"
START = "Root Certificates"
STOP = "Previously Issued Root Certificates"
PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def _certs_from_page(page: str) -> list[x509.Certificate]:
    text = html.unescape(page)
    stop = text.find(STOP)
    if stop < 0:
        raise SystemExit(f"sectie '{STOP}' niet gevonden; is de pagina gewijzigd?")
    start = text.rfind(START, 0, stop - 1)
    while start >= 0 and text[start - len("Previously Issued ") : start] == "Previously Issued ":
        start = text.rfind(START, 0, start)
    if start < 0:
        raise SystemExit(f"sectie '{START}' niet gevonden")
    pems = [re.sub(r"<[^>]+>", "", p) for p in PEM_RE.findall(text[start:stop])]
    return [x509.load_pem_x509_certificate(p.encode("ascii")) for p in pems]


def _block(c: x509.Certificate, fetched_at: str) -> str:
    fp = c.fingerprint(hashes.SHA256()).hex(":").upper()
    return (
        f"# root: {c.subject.rfc4514_string()}\n"
        f"#   sleutel:   {type(c.public_key()).__name__}\n"
        f"#   geldig:    {c.not_valid_before_utc.date()} t/m {c.not_valid_after_utc.date()}\n"
        f"#   bron:      {PAGE_URL} (opgehaald {fetched_at})\n"
        f"#   SHA-256:   {fp}\n" + c.public_bytes(Encoding.PEM).decode("ascii")
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("page", type=Path, help="opgeslagen HTML van de documentatiepagina")
    ap.add_argument("--json", type=Path, help="opgeslagen JSON-array van " + JSON_URL)
    ap.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "android_attestation_roots.pem",
    )
    ap.add_argument("--fetched-at", default=dt.date.today().isoformat())
    a = ap.parse_args(argv)

    roots = _certs_from_page(a.page.read_text(encoding="utf-8"))
    if not roots:
        raise SystemExit("geen root-certificaten gevonden")
    for c in roots:
        if c.issuer != c.subject:
            raise SystemExit(f"{c.subject.rfc4514_string()} is niet self-signed")
        c.verify_directly_issued_by(c)
    if a.json is not None:
        listed = {
            x509.load_pem_x509_certificate(p.encode("ascii")).fingerprint(hashes.SHA256())
            for p in json.loads(a.json.read_text(encoding="utf-8"))
        }
        if listed != {c.fingerprint(hashes.SHA256()) for c in roots}:
            raise SystemExit("roots op de pagina wijken af van de JSON-array")

    head = (
        "# HorseSafe v0.3.4-Miller - Google hardware-attestation-roots (Android key attestation)\n"
        "# Gegenereerd door backend/tools/build_android_roots.py; niet met de hand bewerken.\n"
        f"# Bron: {PAGE_URL} (sectie 'Root Certificates'),\n"
        f"#       gecontroleerd tegen {JSON_URL}\n"
        "# Publiek materiaal, geen secrets.\n\n"
    )
    a.out.write_text(head + "\n".join(_block(c, a.fetched_at) for c in roots), encoding="ascii")
    print(f"{len(roots)} roots -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
