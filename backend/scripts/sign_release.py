#!/usr/bin/env python3
"""Signs an agent release. Runs on a release owner's machine, never in CI.

    backend/venv/bin/python backend/scripts/sign_release.py \
        --version 2.1.0 --key ~/.assetly/release_key.pem

Run it with the venv interpreter, not a bare `python`: this script needs
`cryptography`. That used to be a dev-only dependency, and this comment used
to say so -- it is now a RUNTIME dependency in the root requirements.txt,
because app/mfa.py imports Fernet to encrypt stored TOTP seeds. The agents
still verify signatures with stdlib only; it is the backend, not the agent,
that gained the dependency.

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
    os.environ.get("UPDATES_DIR", str(REPO_ROOT / "backend" / "app" / "static" / "updates"))
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

    This function must stay behaviourally identical to Split-EmbeddedConfig
    in AssetlyAgent_Windows.ps1 -- they are a matched pair. If they ever
    diverge on what counts as "the base image", a real installed .exe and
    this signer will disagree about the hash of the same release, and every
    machine in the Windows fleet will sit in a permanent "update available"
    loop, downloading and re-applying forever.

    Split-EmbeddedConfig requires two things before it strips anything, and
    this mirrors both rather than assuming either:
      1. The file must literally END with b":ASSETLY-CONFIG-END". If it
         doesn't, the file is returned unmodified -- Split-EmbeddedConfig
         never even looks for the begin-marker in that case.
      2. Only then does it search for b"ASSETLY-CONFIG-BEGIN:", and only in
         the last 8192 bytes -- because ps2exe embeds this script as plain
         text, so a decoy copy of the marker sits ~15 KB into a real build,
         and matching that one would cut the binary in half.
    """
    begin = b"ASSETLY-CONFIG-BEGIN:"
    end = b":ASSETLY-CONFIG-END"

    if not data.endswith(end):
        return data

    tail_start = max(0, len(data) - 8192)
    index = data.rfind(begin, tail_start)
    if index < 0:
        return data
    return data[:index]


def _authenticode_sign(payload: bytes, cert_path: str, password: str) -> bytes:
    """Authenticode-signs Windows exe bytes with signtool.exe (native) or
    osslsigncode (cross-signing from Linux/macOS), whichever is on PATH.

    Runs locally, same custody model as the RSA update-signing key above:
    never invoked automatically, never in CI. See docs/RELEASE_SIGNING.md.
    """
    import shutil
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        unsigned_path = Path(tmp) / "unsigned.exe"
        signed_path = Path(tmp) / "signed.exe"
        unsigned_path.write_bytes(payload)

        if shutil.which("signtool.exe") or shutil.which("signtool"):
            signtool = shutil.which("signtool.exe") or shutil.which("signtool")
            cmd = [
                signtool, "sign", "/f", cert_path, "/p", password,
                "/fd", "SHA256", "/tr", "http://timestamp.digicert.com",
                "/td", "SHA256", str(unsigned_path),
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return unsigned_path.read_bytes()

        if shutil.which("osslsigncode"):
            cmd = [
                "osslsigncode", "sign", "-pkcs12", cert_path, "-pass", password,
                "-h", "sha256", "-t", "http://timestamp.digicert.com",
                "-in", str(unsigned_path), "-out", str(signed_path),
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            return signed_path.read_bytes()

        raise RuntimeError(
            "WINDOWS_CODESIGN_CERT_PATH is set but neither signtool nor "
            "osslsigncode is on PATH. Install one or unset the variable to "
            "ship unsigned (see docs/RELEASE_SIGNING.md)."
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="e.g. 2.1.0")
    parser.add_argument("--key", required=True, type=Path, help="PEM private key")
    args = parser.parse_args()

    private_key = serialization.load_pem_private_key(
        args.key.read_bytes(), password=None
    )

    UPDATES_DIR.mkdir(parents=True, exist_ok=True)
    windows_codesign_cert = os.environ.get("WINDOWS_CODESIGN_CERT_PATH")
    windows_codesign_password = os.environ.get("WINDOWS_CODESIGN_PASSWORD", "")

    artifacts = {}
    for name, source in ARTIFACTS.items():
        raw = source.read_bytes()
        payload = _windows_base_bytes(raw) if name == "windows_exe" else raw
        unsigned_sha256 = hashlib.sha256(payload).hexdigest()

        signed_payload = payload
        if name == "windows_exe" and windows_codesign_cert:
            signed_payload = _authenticode_sign(
                payload, windows_codesign_cert, windows_codesign_password
            )
        elif name == "windows_exe":
            print("  (WINDOWS_CODESIGN_CERT_PATH not set — shipping unsigned, as before)")

        destination = UPDATES_DIR / source.name
        destination.write_bytes(signed_payload)
        entry = {
            "sha256": hashlib.sha256(signed_payload).hexdigest(),
            "size": len(signed_payload),
            # Must match the /static mount in app/main.py, which serves
            # backend/app/static/ -- UPDATES_DIR above is under that tree
            # specifically so this path is actually reachable.
            "path": f"/static/updates/{source.name}",
        }
        if name == "windows_exe":
            entry["unsigned_sha256"] = unsigned_sha256
        artifacts[name] = entry
        print(f"{name}: {entry['sha256']} ({entry['size']} bytes)")

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
    print("Commit backend/app/static/updates/ and deploy.")


if __name__ == "__main__":
    main()
