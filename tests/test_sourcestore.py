"""Source bundle storage: normal archives extract; path-traversal ("zip-slip") entries
are refused; symlinks are skipped; unsupported formats rejected."""
from __future__ import annotations

import io
import zipfile

import pytest
from vapt_api.config import get_settings
from vapt_api.sourcestore import UnsafeArchive, store_bundle


@pytest.fixture()
def source_root(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_SOURCE_ROOT", str(tmp_path))
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


def _zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_normal_zip_extracts(source_root):
    data = _zip({"app/db.py": "import os\n", "README.md": "hi"})
    meta = store_bundle("eng-1", "src.zip", data)
    assert meta["file_count"] == 2
    import os
    assert os.path.exists(os.path.join(meta["extracted_path"], "app", "db.py"))
    assert len(meta["sha256"]) == 64
    assert meta["byte_length"] == len(data)


def test_zip_slip_is_refused(source_root):
    data = _zip({"../escape.txt": "pwned"})
    with pytest.raises(UnsafeArchive):
        store_bundle("eng-2", "evil.zip", data)


def test_unsupported_format_rejected(source_root):
    with pytest.raises(UnsafeArchive):
        store_bundle("eng-3", "notes.txt", b"just some bytes, not an archive")
