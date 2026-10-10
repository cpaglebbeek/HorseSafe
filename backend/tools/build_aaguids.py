"""Bouw ``backend/data/aaguids.json`` uit een gedownloade FIDO MDS3-blob (v0.2.0-Koblitz).

Reproduceerbaar (docs/HARDWARE_KEYS.md §12.4)::

    curl -sSL -o /tmp/mds/blob.jwt https://mds3.fidoalliance.org/
    curl -sSL -o /tmp/mds/root-r3.crt http://secure.globalsign.com/cacert/root-r3.crt
    python -I backend/tools/build_aaguids.py /tmp/mds/blob.jwt --root /tmp/mds/root-r3.crt \\
        --out backend/data/aaguids.json

De JWT-handtekening en de x5c-keten worden gecontroleerd tot de opgegeven MDS-root (GlobalSign
Root CA - R3, SHA-256 CB:B5:22:D7:B7:F1:27:AD:6A:01:13:86:5B:DF:1C:D4:10:2E:7D:07:59:AF:63:5A:7C:F4:72:0D:C9:63:C5:3B). Alleen Yubico-entries komen in de lijst:

- ``bio``: ``fingerprint_internal`` in userVerificationDetails én "Bio" in de beschrijving;
- ``yubikey5``: beschrijving begint met "YubiKey 5" (incl. FIPS/CCN/Nano/NFC), zonder vinger.

Entries waarvan de laatste statusrapportage niet ``FIDO_CERTIFIED*`` is (preview, RC, revoked,
compromised) blijven buiten de lijst (fail-closed). Alleen standaardbibliotheek + cryptography.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_blob(jwt: str, root_pem: bytes) -> dict[str, Any]:
    """Controleer handtekening + keten; return de payload."""
    head_b64, payload_b64, sig_b64 = jwt.strip().split(".")
    header = json.loads(_b64u(head_b64))
    chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header["x5c"]]
    root = x509.load_pem_x509_certificate(root_pem)
    for cert, issuer in zip(chain, [*chain[1:], root], strict=True):
        cert.verify_directly_issued_by(issuer)
    signed = f"{head_b64}.{payload_b64}".encode("ascii")
    sig = _b64u(sig_b64)
    key = chain[0].public_key()
    alg = header.get("alg")
    if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
        key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey):
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"niet-ondersteund alg {alg!r}")
    return dict(json.loads(_b64u(payload_b64)))


def classify(entry: dict[str, Any]) -> str | None:
    ms = entry.get("metadataStatement") or {}
    desc = str(ms.get("description", "")).strip()
    if not entry.get("aaguid") or "yubikey" not in desc.lower():
        return None
    reports = entry.get("statusReports") or []
    last = str(reports[-1].get("status", "")) if reports else ""
    if not last.startswith("FIDO_CERTIFIED"):
        return None
    has_fp = "fingerprint_internal" in json.dumps(ms.get("userVerificationDetails", []))
    if has_fp and "bio" in desc.lower():
        return "bio"
    if not has_fp and desc.lower().startswith("yubikey 5"):
        return "yubikey5"
    return None


def build(payload: dict[str, Any], fetched_at: str) -> dict[str, Any]:
    out: dict[str, dict[str, str]] = {}
    for e in payload.get("entries", []):
        cls = classify(e)
        if cls:
            desc = str(e["metadataStatement"]["description"]).strip()
            out[str(e["aaguid"]).lower()] = {"class": cls, "description": desc}
    return {
        "source": "FIDO MDS3",
        "mds_no": int(payload.get("no", 0)),
        "fetched_at": fetched_at,
        "aaguids": dict(sorted(out.items(), key=lambda kv: (kv[1]["class"], kv[1]["description"], kv[0]))),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("blob", type=Path, help="gedownloade MDS3-blob (JWT)")
    ap.add_argument("--root", type=Path, help="MDS-root (PEM/DER); verplicht tenzij --no-verify")
    ap.add_argument("--no-verify", action="store_true", help="alleen voor tests: niet controleren")
    ap.add_argument("--out", type=Path, default=Path(__file__).parent.parent / "data" / "aaguids.json")
    ap.add_argument("--fetched-at", default=dt.date.today().isoformat())
    a = ap.parse_args(argv)
    jwt = a.blob.read_text(encoding="ascii")
    if a.no_verify:
        payload = json.loads(_b64u(jwt.split(".")[1]))
    else:
        if not a.root:
            ap.error("--root is verplicht (of --no-verify)")
        raw = a.root.read_bytes()
        if b"-----BEGIN" not in raw:
            from cryptography.hazmat.primitives.serialization import Encoding

            raw = x509.load_der_x509_certificate(raw).public_bytes(Encoding.PEM)
        payload = verify_blob(jwt, raw)
    result = build(payload, a.fetched_at)
    a.out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for v in result["aaguids"].values():
        counts[v["class"]] = counts.get(v["class"], 0) + 1
    print(f"MDS no {result['mds_no']}: {counts} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
