"""Store and safely extract an uploaded source bundle (BAR-27).

The archive is written once and extracted into a per-bundle directory under the
configured source root. Extraction is hardened against path traversal ("zip-slip"):
any member that would resolve outside the destination is refused and the whole upload
is rejected. Symlinks are skipped rather than materialized."""
from __future__ import annotations

import hashlib
import os
import tarfile
import uuid
import zipfile
from pathlib import Path

from .config import get_settings


class UnsafeArchive(ValueError):
    """An archive member tried to escape the extraction directory, or the archive is
    an unsupported format."""


def _within(root: str, target: str) -> bool:
    root_r = os.path.realpath(root)
    tgt_r = os.path.realpath(target)
    return tgt_r == root_r or tgt_r.startswith(root_r + os.sep)


def _safe_extract_zip(path: str, dest: str) -> int:
    count = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            if name.endswith("/"):
                continue  # directory entry
            out = os.path.join(dest, name)
            if not _within(dest, out):
                raise UnsafeArchive(f"zip entry escapes destination: {name!r}")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with zf.open(info) as src, open(out, "wb") as dst:
                dst.write(src.read())
            count += 1
    return count


def _safe_extract_tar(path: str, dest: str) -> int:
    count = 0
    with tarfile.open(path) as tf:
        for member in tf.getmembers():
            if member.isdir():
                continue
            if member.issym() or member.islnk():
                continue  # never materialize links from an untrusted archive
            if not member.isfile():
                continue
            out = os.path.join(dest, member.name)
            if not _within(dest, out):
                raise UnsafeArchive(f"tar entry escapes destination: {member.name!r}")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            with open(out, "wb") as dst:
                dst.write(extracted.read())
            count += 1
    return count


def store_bundle(engagement_id: str, filename: str, data: bytes) -> dict:
    """Persist + extract an uploaded archive. Returns metadata for the SourceBundle row.
    Raises UnsafeArchive on traversal or an unsupported format."""
    settings = get_settings()
    bundle_id = str(uuid.uuid4())
    base = Path(settings.source_root) / engagement_id / bundle_id
    extracted = base / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)

    safe_name = os.path.basename(filename) or "bundle"
    archive_path = str(base / safe_name)
    with open(archive_path, "wb") as f:
        f.write(data)

    lower = safe_name.lower()
    if lower.endswith(".zip") or zipfile.is_zipfile(archive_path):
        file_count = _safe_extract_zip(archive_path, str(extracted))
    elif lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2")) or tarfile.is_tarfile(archive_path):
        file_count = _safe_extract_tar(archive_path, str(extracted))
    else:
        raise UnsafeArchive("unsupported archive format (use .zip, .tar, .tar.gz, .tgz)")

    return {
        "id": bundle_id,
        "storage_key": archive_path,
        "extracted_path": str(extracted),
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
        "file_count": file_count,
    }
