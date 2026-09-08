"""Tampered downloads must never replace an existing executable."""

import hashlib
import importlib.util
import io
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "install_opa", Path(__file__).resolve().parents[1] / "ci" / "install_opa.py"
)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def setup_download(monkeypatch, payload, expected):
    monkeypatch.setattr(installer.platform, "system", lambda: "Linux")
    monkeypatch.setattr(installer.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(
        installer, "ASSETS", {("Linux", "x86_64"): ("synthetic-opa", expected)}
    )
    monkeypatch.setattr(
        installer.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload)
    )


def test_tampered_download_preserves_existing_binary(tmp_path, monkeypatch):
    target = tmp_path / "opa"
    target.write_bytes(b"original")
    setup_download(monkeypatch, b"tampered", hashlib.sha256(b"reviewed").hexdigest())
    with pytest.raises(ValueError, match="checksum mismatch"):
        installer.install(target)
    assert target.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [target]


def test_verified_download_installs_executable(tmp_path, monkeypatch):
    payload = b"synthetic executable"
    setup_download(monkeypatch, payload, hashlib.sha256(payload).hexdigest())
    target = tmp_path / "bin" / "opa"
    installer.install(target)
    assert target.read_bytes() == payload
    assert target.stat().st_mode & 0o111 == 0o111
