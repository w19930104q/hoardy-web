# Copyright (c) 2024 Jan Malakhovski <oxij@oxij.org>
#
# This file is a part of `hoardy-web` project.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

"""Read-only audit inventory of `WRR`/`WRRB` archives.

This module implements the `audit` subcommand of `hoardy-web`. It
enumerates the given inputs in stable lexicographic order, stream-parses
each file (without ever modifying it), classifies the result, and writes
deterministic reports plus an append-only checkpoint journal into the
given state directory. An interrupted run can be resumed: files whose
`(device, inode, size, mtime)` did not change since the previous run are
not re-audited.
"""

import dataclasses as _dc
import gzip as _gzip
import hashlib as _hashlib
import json as _json
import os as _os
import os.path as _op
import stat as _stat
import typing as _t

import cbor2 as _cbor2

from kisstdlib.compression import ungzip_fileobj_maybe

JOURNAL_VERSION = 1
JOURNAL_NAME = "audit.journal"
MANIFEST_NAME = "manifest.jsonl"
QUARANTINE_NAME = "quarantine.jsonl"
DUPLICATES_NAME = "duplicates.jsonl"
SUMMARY_NAME = "summary.json"
REPORT_NAMES = (MANIFEST_NAME, QUARANTINE_NAME, DUPLICATES_NAME, SUMMARY_NAME)

# statuses of files that end up in the quarantine report
QUARANTINE_STATUSES = frozenset(["truncated", "corrupt", "error"])

_GZIP_MAGIC = b"\x1f\x8b"


@_dc.dataclass
class AuditEntry:
    """Result of auditing a single input file."""

    path: str
    status: str  # "ok" | "empty" | "truncated" | "corrupt" | "error"
    format: str  # "wrr" | "wrrb", with a "+gzip" suffix when gzipped
    compressed: bool
    size: int
    file_size: int
    dev: int
    ino: int
    mtime_ns: int
    records: int
    payload_bytes: int
    fingerprint: str | None
    record_fingerprints: list[str]
    error: str | None

    def to_row(self) -> dict[str, _t.Any]:
        return {
            "path": self.path,
            "status": self.status,
            "format": self.format,
            "compressed": self.compressed,
            "size": self.size,
            "file_size": self.file_size,
            "dev": self.dev,
            "ino": self.ino,
            "mtime_ns": self.mtime_ns,
            "records": self.records,
            "payload_bytes": self.payload_bytes,
            "fingerprint": self.fingerprint,
            "record_fingerprints": self.record_fingerprints,
            "error": self.error,
        }

    @classmethod
    def from_row(cls, row: dict[str, _t.Any]) -> "AuditEntry":
        return cls(
            path=str(row["path"]),
            status=str(row["status"]),
            format=str(row["format"]),
            compressed=bool(row["compressed"]),
            size=int(row["size"]),
            file_size=int(row["file_size"]),
            dev=int(row["dev"]),
            ino=int(row["ino"]),
            mtime_ns=int(row["mtime_ns"]),
            records=int(row["records"]),
            payload_bytes=int(row["payload_bytes"]),
            fingerprint=None if row["fingerprint"] is None else str(row["fingerprint"]),
            record_fingerprints=[str(e) for e in row["record_fingerprints"]],
            error=None if row["error"] is None else str(row["error"]),
        )

    def stat_key(self) -> tuple[int, int, int, int]:
        return (self.dev, self.ino, self.size, self.mtime_ns)


def _error_entry(path: str, error: str) -> AuditEntry:
    return AuditEntry(
        path=path,
        status="error",
        format="wrrb" if path.endswith(".wrrb") else "wrr",
        compressed=False,
        size=0,
        file_size=0,
        dev=0,
        ino=0,
        mtime_ns=0,
        records=0,
        payload_bytes=0,
        fingerprint=None,
        record_fingerprints=[],
        error=error,
    )


def _stat_key_of(path: str, follow_symlinks: bool) -> tuple[int, int, int, int]:
    """The key under which the journal checkpoints `path`.

    Must agree with the `dev`/`ino`/`size`/`mtime_ns` fields of the
    `AuditEntry` `audit_path` produces for the same file, so that
    unchanged files are recognized on a subsequent run. Files that will
    be classified as `error` all share the all-zero key.
    """
    try:
        st = _os.stat(path) if follow_symlinks else _os.lstat(path)
    except OSError:
        return (0, 0, 0, 0)
    if not _stat.S_ISREG(st.st_mode):
        return (0, 0, 0, 0)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def audit_path(path: str, follow_symlinks: bool = False) -> AuditEntry:
    """Audit a single file, never raising on I/O or parsing failures."""
    try:
        st = _os.stat(path) if follow_symlinks else _os.lstat(path)
    except OSError as exc:
        return _error_entry(path, "input path not accessible: `%s`" % (type(exc).__name__,))
    if _stat.S_ISLNK(st.st_mode):
        # can only happen when not following symlinks
        return _error_entry(
            path, "input path is a symlink and following symlinks is disabled"
        )
    if not _stat.S_ISREG(st.st_mode):
        return _error_entry(path, "input path is not a regular file")

    format_base = "wrrb" if path.endswith(".wrrb") else "wrr"
    gzipped = False
    compressed = False
    records = 0
    payload_bytes = 0
    recfps: list[bytes] = []
    status = "ok"
    error = None
    try:
        with open(path, "rb") as raw:
            gzipped = raw.peek(2)[:2] == _GZIP_MAGIC
            compressed = gzipped
            fobj = ungzip_fileobj_maybe(raw)
            while True:
                p = fobj.peek(1)
                if p == b"":
                    break
                before = fobj.tell()
                struct = _cbor2.load(fobj)
                after = fobj.tell()
                payload_bytes += after - before
                recfps.append(_hashlib.sha256(_cbor2.dumps(struct)).digest())
                records += 1
    except EOFError as exc:
        # includes `cbor2.CBORDecodeEOF`
        status = "truncated"
        error = "stream ended prematurely: `%s`" % (type(exc).__name__,)
    except _gzip.BadGzipFile:
        # must be caught before `OSError`, from which it inherits
        status = "corrupt"
        error = "broken compression stream: `BadGzipFile`"
        compressed = False
    except _cbor2.CBORDecodeError as exc:
        status = "corrupt"
        error = "CBOR parsing failure: `%s`" % (type(exc).__name__,)
    except OSError as exc:
        status = "error"
        what = "input path not accessible" if records == 0 else "read failure"
        error = "%s: `%s`" % (what, type(exc).__name__)

    if error is not None:
        payload_bytes = 0
    elif records == 0:
        status = "empty"

    if len(recfps) == 0:
        fingerprint = None
    elif len(recfps) == 1:
        fingerprint = recfps[0].hex()
    else:
        fingerprint = _hashlib.sha256(b"".join(recfps)).hexdigest()

    return AuditEntry(
        path=path,
        status=status,
        format=format_base + ("+gzip" if gzipped else ""),
        compressed=compressed,
        size=st.st_size,
        file_size=st.st_size,
        dev=st.st_dev,
        ino=st.st_ino,
        mtime_ns=st.st_mtime_ns,
        records=records,
        payload_bytes=payload_bytes,
        fingerprint=fingerprint,
        record_fingerprints=[fp.hex() for fp in recfps],
        error=error,
    )


def enumerate_paths(paths: list[str], follow_symlinks: bool = False) -> list[str]:
    """Enumerate all given files and directories (recursively) into a
    stably sorted list of candidate paths.

    Unreadable, missing, and otherwise problematic paths are included in
    the result: `audit_path` will classify them as `error` later.
    Incomplete (`.part`) files are skipped.
    """
    out: list[str] = []
    seen_dirs: set[tuple[int, int]] = set()

    def walk(path: str) -> None:
        try:
            st = _os.stat(path) if follow_symlinks else _os.lstat(path)
        except OSError:
            out.append(path)
            return
        if _stat.S_ISDIR(st.st_mode):
            key = (st.st_dev, st.st_ino)
            if key in seen_dirs:
                return  # a directory cycle via symlinks
            seen_dirs.add(key)
            try:
                names = sorted(_os.listdir(path))
            except OSError:
                out.append(path)
                return
            for name in names:
                walk(_op.join(path, name))
        elif _stat.S_ISREG(st.st_mode):
            if path.endswith(".part"):
                return  # incomplete download, skip
            out.append(path)
        else:
            # symlinks (when not following them), fifos, sockets, etc:
            # let `audit_path` classify them
            out.append(path)

    for path in paths:
        walk(path)
    out.sort()
    return out


def _load_journal(journal_path: str) -> dict[str, AuditEntry]:
    """Load the checkpoint journal, tolerating a torn tail line and
    otherwise malformed rows (the journal is append-only, so a crash can
    leave a partial last line)."""
    result: dict[str, AuditEntry] = {}
    try:
        fobj = open(journal_path, "r", encoding="utf-8")
    except OSError:
        return result
    with fobj:
        for line in fobj:
            try:
                doc = _json.loads(line)
                if not isinstance(doc, dict) or doc.get("version") != JOURNAL_VERSION:
                    continue
                row = doc["audit"]
                if not isinstance(row, dict):
                    continue
                entry = AuditEntry.from_row(row)
            except (KeyError, TypeError, ValueError):
                continue
            result[entry.path] = entry
    return result


def _fsync_maybe(fobj: _t.IO[_t.Any], fsync: bool) -> None:
    fobj.flush()
    if fsync:
        _os.fsync(fobj.fileno())


def run_audit(
    paths: list[str],
    state_dir: str,
    follow_symlinks: bool = False,
    restart: bool = False,
    fsync: bool = True,
    should_continue: _t.Callable[[], None] | None = None,
) -> tuple[list[AuditEntry], dict[str, str]]:
    """Audit all `paths` into `state_dir`, returning the list of per-file
    entries (in traversal order) and a dict mapping report names to their
    absolute paths.

    This function never modifies anything under `paths`; it only ever
    creates and updates files under `state_dir`.
    """
    _os.makedirs(state_dir, exist_ok=True)
    journal_path = _op.join(state_dir, JOURNAL_NAME)
    if restart:
        try:
            _os.unlink(journal_path)
        except FileNotFoundError:
            pass
    journaled = _load_journal(journal_path)

    candidates = enumerate_paths(paths, follow_symlinks)

    entries: list[AuditEntry] = []
    with open(journal_path, "a", encoding="utf-8") as journal:
        for path in candidates:
            if should_continue is not None:
                should_continue()
            entry = journaled.get(path)
            if entry is not None and entry.stat_key() == _stat_key_of(path, follow_symlinks):
                # unchanged since the previous run, reuse the checkpoint
                entries.append(entry)
                continue
            entry = audit_path(path, follow_symlinks)
            entries.append(entry)
            journal.write(
                _json.dumps(
                    {"audit": entry.to_row(), "version": JOURNAL_VERSION}, sort_keys=True
                )
                + "\n"
            )
            _fsync_maybe(journal, fsync)

    rows = [entry.to_row() for entry in entries]
    rows.sort(key=lambda row: (row["path"], row["records"]))

    counts = {"ok": 0, "empty": 0, "truncated": 0, "corrupt": 0, "error": 0}
    for row in rows:
        counts[row["status"]] += 1

    # group identical contents by semantic fingerprint, which is
    # independent of the compression shell, bundling, and path
    groups: dict[str, list[dict[str, _t.Any]]] = {}
    for row in rows:
        if row["status"] == "ok" and row["fingerprint"] is not None:
            groups.setdefault(row["fingerprint"], []).append(row)
    duplicates = []
    for fingerprint in sorted(groups):
        members = groups[fingerprint]
        if len(members) < 2:
            continue
        first = members[0]
        duplicates.append(
            {
                "fingerprint": fingerprint,
                "copies": len(members),
                "paths": sorted(member["path"] for member in members),
                "records": first["records"],
                "payload_bytes": first["payload_bytes"],
            }
        )

    summary = {
        "files": len(rows),
        "ok": counts["ok"],
        "empty": counts["empty"],
        "truncated": counts["truncated"],
        "corrupt": counts["corrupt"],
        "error": counts["error"],
        "quarantined": counts["truncated"] + counts["corrupt"] + counts["error"],
        "duplicate_groups": len(duplicates),
        "records": sum(row["records"] for row in rows if row["status"] == "ok"),
        "payload_bytes": sum(row["payload_bytes"] for row in rows),
        "file_size": sum(row["file_size"] for row in rows),
    }

    def dumps_row(row: _t.Any) -> str:
        return _json.dumps(row, sort_keys=True) + "\n"

    manifest = dumps_row({"summary": summary, "version": JOURNAL_VERSION}) + "".join(
        dumps_row(row) for row in rows
    )
    quarantine = "".join(
        dumps_row(row) for row in rows if row["status"] in QUARANTINE_STATUSES
    )
    duplicates_data = "".join(dumps_row(group) for group in duplicates)
    summary_data = _json.dumps(summary, indent=2, sort_keys=True) + "\n"

    reports: dict[str, str] = {}
    for name, data in (
        (MANIFEST_NAME, manifest),
        (QUARANTINE_NAME, quarantine),
        (DUPLICATES_NAME, duplicates_data),
        (SUMMARY_NAME, summary_data),
    ):
        report_path = _op.join(state_dir, name)
        with open(report_path, "w", encoding="utf-8") as fobj:
            fobj.write(data)
            _fsync_maybe(fobj, fsync)
        reports[name] = _op.abspath(report_path)

    return entries, reports
