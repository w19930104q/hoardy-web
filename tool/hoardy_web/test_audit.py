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

"""Tests for `hoardy_web.audit` (the `audit` subcommand)."""

import gzip
import io
import json
import os
import os.path as op

import pytest

from hoardy_web.audit import run_audit
from hoardy_web.wrr import parse_url, trivial_Reqres, wrr_dumps


def _rr(url, body):
    return trivial_Reqres(parse_url(url), data=body)


def _whole_gzip(data):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, filename="", mtime=0, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


def make_archive(root):
    """Build the fixed acceptance matrix: normal plain/gzip/bundle files,
    truncated and corrupt files, an empty file, duplicates across paths,
    extensions, and compression shells, a readable per-element gzip bundle,
    a mixed-compression bundle, and a `.part` file that must be skipped."""

    def write(rel, data):
        path = op.join(root, rel)
        os.makedirs(op.dirname(path), exist_ok=True)
        with open(path, "wb") as fobj:
            fobj.write(data)

    a = _rr("https://example.org/a", b"alpha-payload-" * 64)
    write("normal/a.wrr", wrr_dumps(a, compress=True))

    b1 = _rr("https://example.org/b/1", b"bravo-" * 100)
    b2 = _rr("https://example.org/b/2", b"charlie-" * 100)
    write("normal/bundle.wrrb", wrr_dumps(b1, compress=False) + wrr_dumps(b2, compress=False))

    write("dupes/a-copy.wrrb", wrr_dumps(a, compress=False))
    write("dupes/a-wholefile.wrr.gz", _whole_gzip(wrr_dumps(a, compress=False)))

    good = wrr_dumps(_rr("https://example.org/cut", b"cutme-" * 128), compress=True)
    write("broken/truncated.wrr", good[: len(good) // 2])

    lead = wrr_dumps(_rr("https://example.org/lead", b"lead-payload-" * 32), compress=False)
    tail = wrr_dumps(_rr("https://example.org/tail", b"tail-payload-" * 128), compress=False)
    write("broken/midcut.wrrb", lead + tail[: len(tail) // 2])

    m1 = wrr_dumps(_rr("https://example.org/mixed/1", b"mixed-one-" * 48), compress=True)
    m2 = wrr_dumps(_rr("https://example.org/mixed/2", b"mixed-two-" * 48), compress=False)
    write("normal/mixed.wrrb", m1 + m2)

    g1 = wrr_dumps(_rr("https://example.org/gz/1", b"gzip-one-" * 48), compress=True)
    g2 = wrr_dumps(_rr("https://example.org/gz/2", b"gzip-two-" * 48), compress=True)
    write("normal/gzmembers.wrrb", g1 + g2)

    write("broken/corrupt.wrrb", b"\x1f\x8b" + b"\x00" * 12)
    write("broken/empty.wrr", b"")
    write("incoming/partial.wrr.part", good)


def load_rows(state_dir, name):
    with open(op.join(state_dir, name), encoding="utf-8") as fobj:
        return [json.loads(line) for line in fobj]


def by_relpath(rows, root):
    return {op.relpath(r["path"], root): r for r in rows if "path" in r}


def state_snapshot(state_dir):
    return {n: open(op.join(state_dir, n), "rb").read() for n in os.listdir(state_dir)}


@pytest.fixture()
def archive(tmp_path):
    root = str(tmp_path / "archive")
    make_archive(root)
    return root


def test_audit_classification_and_quarantine(archive, tmp_path):
    state = str(tmp_path / "state")
    entries, reports = run_audit([archive], state, fsync=False)
    assert set(reports) == {"manifest.jsonl", "quarantine.jsonl", "duplicates.jsonl", "summary.json"}

    rows = by_relpath(load_rows(state, "manifest.jsonl"), archive)
    expect = {
        "broken/corrupt.wrrb": ("corrupt", "wrrb+gzip", 0),
        "broken/empty.wrr": ("empty", "wrr", 0),
        "broken/midcut.wrrb": ("truncated", "wrrb", 1),
        "broken/truncated.wrr": ("truncated", "wrr+gzip", 0),
        "normal/mixed.wrrb": ("corrupt", "wrrb+gzip", 1),
        "normal/gzmembers.wrrb": ("ok", "wrrb+gzip", 2),
        "normal/bundle.wrrb": ("ok", "wrrb", 2),
        "normal/a.wrr": ("ok", "wrr+gzip", 1),
        "dupes/a-copy.wrrb": ("ok", "wrrb", 1),
        "dupes/a-wholefile.wrr.gz": ("ok", "wrr+gzip", 1),
    }
    assert set(rows) == set(expect)  # `.part` file is skipped
    for rel, (status, fmt, recs) in expect.items():
        row = rows[rel]
        assert (row["status"], row["format"], row["records"]) == (status, fmt, recs), rel
        # payload bytes are only accounted for cleanly read files
        assert (row["payload_bytes"] > 0) == (status == "ok"), rel

    # manifest is sorted by path
    paths = [r["path"] for r in load_rows(state, "manifest.jsonl") if "path" in r]
    assert paths == sorted(paths)

    # the four damaged files are quarantined, nothing else is
    qrows = by_relpath(load_rows(state, "quarantine.jsonl"), archive)
    assert set(qrows) == {
        "broken/corrupt.wrrb",
        "broken/midcut.wrrb",
        "broken/truncated.wrr",
        "normal/mixed.wrrb",
    }
    # quarantining did not block anything: all ten files were audited
    assert len(entries) == 10


def test_audit_semantic_fingerprint_dedup(archive, tmp_path):
    state = str(tmp_path / "state")
    run_audit([archive], state, fsync=False)

    dups = load_rows(state, "duplicates.jsonl")
    assert len(dups) == 1
    group = dups[0]
    assert group["copies"] == 3
    # the same contents under another path, another extension, and under a
    # whole-file gzip shell all share one semantic fingerprint
    assert {op.relpath(p, archive) for p in group["paths"]} == {
        "normal/a.wrr",
        "dupes/a-copy.wrrb",
        "dupes/a-wholefile.wrr.gz",
    }

    rows = by_relpath(load_rows(state, "manifest.jsonl"), archive)
    fps = {rows[op.relpath(p, archive)]["fingerprint"] for p in group["paths"]}
    assert fps == {group["fingerprint"]}
    # a single-record file uses the record digest directly as its fingerprint
    assert rows["normal/a.wrr"]["fingerprint"] == rows["normal/a.wrr"]["record_fingerprints"][0]


def test_audit_summary_totals(archive, tmp_path):
    state = str(tmp_path / "state")
    run_audit([archive], state, fsync=False)

    rows = load_rows(state, "manifest.jsonl")
    summary = rows[0]["summary"]
    with open(op.join(state, "summary.json"), encoding="utf-8") as fobj:
        assert json.load(fobj) == summary

    body = [r for r in rows if "path" in r]
    assert summary["files"] == len(body) == 10
    for status in ("ok", "empty", "truncated", "corrupt", "error"):
        assert summary[status] == sum(1 for r in body if r["status"] == status)
    assert summary["quarantined"] == summary["truncated"] + summary["corrupt"] + summary["error"]
    assert summary["records"] == sum(r["records"] for r in body if r["status"] == "ok")
    assert summary["payload_bytes"] == sum(r["payload_bytes"] for r in body)
    assert summary["file_size"] == sum(r["file_size"] for r in body)
    assert summary["duplicate_groups"] == 1


def test_audit_deterministic_and_resume(archive, tmp_path):
    state_a = str(tmp_path / "state-a")
    run_audit([archive], state_a, fsync=False)
    snap = state_snapshot(state_a)

    # a rerun over unchanged inputs reuses the journal and is byte-identical
    run_audit([archive], state_a, fsync=False)
    assert state_snapshot(state_a) == snap

    # an interrupted run checkpoints what it did ...
    state_b = str(tmp_path / "state-b")
    calls = {"n": 0}

    def stop_soon():
        calls["n"] += 1
        if calls["n"] == 4:
            raise KeyboardInterrupt("simulated interruption")

    with pytest.raises(KeyboardInterrupt):
        run_audit([archive], state_b, fsync=False, should_continue=stop_soon)
    with open(op.join(state_b, "audit.journal"), encoding="utf-8") as fobj:
        assert len(fobj.read().splitlines()) == 3

    # ... and resuming it reaches exactly the fresh-run result
    run_audit([archive], state_b, fsync=False)
    for name in ("manifest.jsonl", "quarantine.jsonl", "duplicates.jsonl", "summary.json"):
        assert open(op.join(state_b, name), "rb").read() == open(op.join(state_a, name), "rb").read()

    # `--restart` discards the journal and reproduces the same reports
    run_audit([archive], state_b, restart=True, fsync=False)
    assert open(op.join(state_b, "manifest.jsonl"), "rb").read() == open(
        op.join(state_a, "manifest.jsonl"), "rb"
    ).read()


def test_audit_tolerates_torn_journal(archive, tmp_path):
    state = str(tmp_path / "state")
    run_audit([archive], state, fsync=False)
    before = open(op.join(state, "manifest.jsonl"), "rb").read()

    # a crash can leave a partial last line in the append-only journal
    with open(op.join(state, "audit.journal"), "a", encoding="utf-8") as fobj:
        fobj.write('{"version": 1, "audit": {"path": "oops"\n')
    run_audit([archive], state, fsync=False)
    assert open(op.join(state, "manifest.jsonl"), "rb").read() == before


def test_audit_missing_path_is_quarantined(archive, tmp_path):
    state = str(tmp_path / "state")
    missing = str(tmp_path / "does-not-exist")
    entries, _reports = run_audit([archive, missing], state, fsync=False)

    # the missing path becomes an `error` entry instead of aborting the batch
    assert len(entries) == 11
    err = [e for e in entries if e.status == "error"]
    assert len(err) == 1
    assert err[0].path == missing
    assert "FileNotFoundError" in (err[0].error or "")

    qrows = load_rows(state, "quarantine.jsonl")
    assert any(r["status"] == "error" and r["path"] == missing for r in qrows)
    summary = load_rows(state, "manifest.jsonl")[0]["summary"]
    assert summary["error"] == 1
    assert summary["files"] == 11


def test_audit_symlink_policy(archive, tmp_path):
    link = str(tmp_path / "link-to-a.wrr")
    os.symlink(op.join(archive, "normal", "a.wrr"), link)

    entries, _ = run_audit([link], str(tmp_path / "state-nofollow"), fsync=False)
    assert len(entries) == 1
    assert entries[0].status == "error"
    assert "symlink" in (entries[0].error or "")

    entries, _ = run_audit(
        [link], str(tmp_path / "state-follow"), follow_symlinks=True, fsync=False
    )
    assert len(entries) == 1
    assert entries[0].status == "ok"
    rows = load_rows(str(tmp_path / "state-follow"), "manifest.jsonl")
    assert rows[1]["fingerprint"] == rows[1]["record_fingerprints"][0]
