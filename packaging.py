import base64, json, os
from datetime import datetime
from typing import Dict, Any, Tuple

_b64  = lambda b: base64.b64encode(b).decode("ascii")
_b64d = lambda s: base64.b64decode(s.encode("ascii"))

def write_package(out_dir: str, base_filename: str, algorithm: str,
                  salt: bytes, iv: bytes, tag: bytes, ciphertext: bytes) -> None:
    """
    Writes a flat package in out_dir:
      - <base_filename>.package.json
      - <base_filename>.payload.bin
    """
    os.makedirs(out_dir, exist_ok=True)
    manifest_path = os.path.join(out_dir, f"{base_filename}.package.json")
    payload_path  = os.path.join(out_dir, f"{base_filename}.payload.bin")

    with open(payload_path, "wb") as f:
        f.write(ciphertext)

    manifest: Dict[str, Any] = {
        "version": 1,
        "algorithm": algorithm,
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "original_filename": base_filename,  # exact filename for restore
        "salt_b64": _b64(salt),
        "iv_b64": _b64(iv),
        "tag_b64": _b64(tag)
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

def read_package(out_dir: str, base_filename: str) -> Tuple[Dict[str, Any], bytes, bytes, bytes, bytes, str]:
    """
    Reads a flat package from out_dir:
      - <base_filename>.package.json
      - <base_filename>.payload.bin
    Returns (manifest, salt, iv, tag, ciphertext, original_filename)
    """
    manifest_path = os.path.join(out_dir, f"{base_filename}.package.json")
    payload_path  = os.path.join(out_dir, f"{base_filename}.payload.bin")

    with open(manifest_path, "r", encoding="utf-8") as f:
        m = json.load(f)
    with open(payload_path, "rb") as f:
        ciphertext = f.read()

    salt = _b64d(m["salt_b64"])
    iv   = _b64d(m["iv_b64"])
    tag  = _b64d(m["tag_b64"])

    return m, salt, iv, tag, ciphertext, m.get("original_filename", base_filename)

