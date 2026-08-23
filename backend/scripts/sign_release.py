#!/usr/bin/env python3
"""Signs an agent release. Runs on a release owner's machine, never in CI.

    python backend/scripts/sign_release.py --version 2.1.0 --key ~/.assetly/release_key.pem

The private key never enters this repository, CI, or an environment variable.
That is deliberate and it is the control: CI can build the Windows executable
but cannot sign it, so a compromise of the GitHub account yields an artifact
no agent in the field will install. Automating this step would give that
compromise back its power.

Generate a keypair once with:

    openssl genrsa -out release_key.pem 4096
    openssl rsa -in release_key.pem -pubout -outform DER | base64

and put the base64 public key in UPDATE_SIGNING_PUBLIC_KEY, in the agents'
embedded constant, and nowhere else. Back up the private key out of band:
losing it means minting a new keypair and re-downloading the whole fleet.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# Same env var and same default as app/config.py's UPDATES_DIR, so the round-trip
# test can point signer and verifier at a tmpdir instead of writing into tracked
# repository paths.
UPDATES_DIR = Path(
    os.environ.get("UPDATES_DIR", str(REPO_ROOT / "backend" / "static" / "updates"))
)

# Source artifact -> the name the manifest and the agents use for it.
ARTIFACTS = {
    "windows_exe": REPO_ROOT / "backend" / "static" / "AssetlyAgent_Windows.exe",
    "posix_py": REPO_ROOT / "inventory_agent.py",
}


def _windows_base_bytes(data: bytes) -> bytes:
    """The Windows exe with any trailing embedded config block removed.

    An installed agent carries its URL and enrollment credential in a block
    appended after the PE image, and Invoke-SelfUpdateExe re-appends the
    running agent's own block to whatever it downloads. So the hash that
    identifies a RELEASE must cover the base image only -- otherwise every
    machine would compute a different hash for the same release and update
    forever.

    The marker matches WINDOWS_CONFIG_BEGIN in backend/app/routers/admin.py
    (the embedder) and the $begin split in Split-EmbeddedConfig in
    AssetlyAgent_Windows.ps1 (the reader): b"ASSETLY-CONFIG-BEGIN:". The
    brief for this task named a different placeholder marker
    ("### ASSETLY-CONFIG-BEGIN ###"); it does not match either of those two
    call sites and was not used here -- using it would have made every
    installed Windows machine compute a different release hash than the one
    signed here and update forever.
    """
    marker = b"ASSETLY-CONFIG-BEGIN:"
    index = data.rfind(marker)
    return data if index < 0 else data[:index]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="e.g. 2.1.0")
    parser.add_argument("--key", required=True, type=Path, help="PEM private key")
    args = parser.parse_args()

    private_key = serialization.load_pem_private_key(
        args.key.read_bytes(), password=None
    )

    UPDATES_DIR.mkdir(parents=True, exist_ok=True)
    artifacts = {}
    for name, source in ARTIFACTS.items():
        raw = source.read_bytes()
        payload = _windows_base_bytes(raw) if name == "windows_exe" else raw
        destination = UPDATES_DIR / source.name
        destination.write_bytes(payload)
        artifacts[name] = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "path": f"/static/updates/{source.name}",
        }
        print(f"{name}: {artifacts[name]['sha256']} ({len(payload)} bytes)")

    manifest = {
        "version": args.version,
        "released_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "artifacts": artifacts,
    }

    # Write first, then sign the bytes that were written. Signing a
    # re-serialisation would risk covering different bytes than the ones the
    # endpoint serves and the agent verifies.
    manifest_path = UPDATES_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_bytes = manifest_path.read_bytes()

    signature = private_key.sign(manifest_bytes, padding.PKCS1v15(), hashes.SHA256())
    (UPDATES_DIR / "manifest.sig").write_text(base64.b64encode(signature).decode() + "\n")

    print(f"\nSigned {manifest_path}")
    print("Commit backend/static/updates/ and deploy.")


if __name__ == "__main__":
    main()
