"""Safe extraction of untrusted zip / tar archives (zip-slip, bombs, links)."""

from __future__ import annotations

import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from aegischain.exceptions import ArchiveError

_CHUNK = 64 * 1024


@dataclass(frozen=True)
class ArchiveLimits:
    max_members: int = 20_000
    max_total_bytes: int = 200 * 1024 * 1024
    max_member_bytes: int = 50 * 1024 * 1024


def _safe_relative(name: str) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise ArchiveError(f"unsafe member name: {name!r}")
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("..", "") for part in p.parts if part != "."):
        raise ArchiveError(f"unsafe member path: {name!r}")
    if p.parts and len(p.parts[0]) == 2 and p.parts[0][1] == ":":
        raise ArchiveError(f"drive-qualified member path: {name!r}")
    return p


def _copy_limited(src, dst, member_limit: int, budget: list[int]) -> None:  # type: ignore[no-untyped-def]
    written = 0
    while chunk := src.read(_CHUNK):
        written += len(chunk)
        budget[0] -= len(chunk)
        if written > member_limit or budget[0] < 0:
            raise ArchiveError("archive exceeds the allowed uncompressed size")
        dst.write(chunk)


def extract_archive(archive: Path, dest: Path, limits: ArchiveLimits | None = None) -> int:
    """Extract ``archive`` into ``dest`` (must exist). Returns the number of files written."""
    limits = limits or ArchiveLimits()
    dest = dest.resolve(strict=True)
    budget = [limits.max_total_bytes]
    count = 0

    def target_for(name: str) -> Path:
        rel = _safe_relative(name)
        target = (dest / Path(*rel.parts)).resolve()
        try:
            target.relative_to(dest)
        except ValueError as exc:
            raise ArchiveError(f"member escapes destination: {name!r}") from exc
        return target

    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_members:
                raise ArchiveError("archive has too many members")
            for info in infos:
                mode = info.external_attr >> 16
                ftype = stat.S_IFMT(mode)
                if ftype and ftype not in (stat.S_IFREG, stat.S_IFDIR):
                    raise ArchiveError(
                        f"links and special files are not allowed: {info.filename!r}"
                    )
                target = target_for(info.filename)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "xb") as dst:
                    _copy_limited(src, dst, limits.max_member_bytes, budget)
                count += 1
        return count
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as tf:
            n = 0
            for member in tf:
                n += 1
                if n > limits.max_members:
                    raise ArchiveError("archive has too many members")
                if not (member.isfile() or member.isdir()):
                    raise ArchiveError(f"links and special files are not allowed: {member.name!r}")
                target = target_for(member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                tar_src = tf.extractfile(member)
                if tar_src is None:
                    raise ArchiveError(f"cannot read member: {member.name!r}")
                with tar_src, open(target, "xb") as dst:
                    _copy_limited(tar_src, dst, limits.max_member_bytes, budget)
                count += 1
        return count
    raise ArchiveError("unsupported archive format (expected zip, tar, tar.gz, tar.bz2 or tar.xz)")
