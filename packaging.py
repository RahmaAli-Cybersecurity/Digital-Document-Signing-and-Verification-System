import os
import json
import base64
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Any

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def write_package(out_dir: str, base_filename: str, algorithm: str,
                  salt: bytes, iv: bytes, tag: bytes, ciphertext: bytes,
                  signature: bytes) -> None:
    """
    Writes a flat package in out_dir:
      - <base_filename>.package.json (includes signature)
      - <base_filename>.payload.bin
    """
    os.makedirs(out_dir, exist_ok=True)
    manifest_path = Path(out_dir) / f"{base_filename}.package.json"
    payload_path  = Path(out_dir) / f"{base_filename}.payload.bin"

    payload_path.write_bytes(ciphertext)

    manifest: Dict[str, Any] = {
        "version": 1,
        "algorithm": algorithm,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "original_filename": base_filename,
        "salt_b64": _b64(salt),
        "iv_b64": _b64(iv),
        "tag_b64": _b64(tag),
        "signature_b64": _b64(signature)
    }

    manifest_path.write_text(json.dumps(manifest, indent=2))

def read_package(out_dir: str, base_filename: str) -> Tuple[Dict[str, Any], bytes, bytes, bytes, bytes, bytes]:
    """
    Reads a package:
    Returns (manifest, salt, iv, tag, ciphertext, signature)
    """
    manifest_path = Path(out_dir) / f"{base_filename}.package.json"
    payload_path  = Path(out_dir) / f"{base_filename}.payload.bin"

    manifest = json.loads(manifest_path.read_text())
    ciphertext = payload_path.read_bytes()

    salt = _b64d(manifest["salt_b64"])
    iv   = _b64d(manifest["iv_b64"])
    tag  = _b64d(manifest["tag_b64"])
    signature = _b64d(manifest["signature_b64"])

    return manifest, salt, iv, tag, ciphertext, signature
