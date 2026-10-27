"""The execution ledger must fill in LIVE — committed per super-step as each node finishes
— not all at once when the whole run completes. `_drive_graph` is the seam that guarantees
this: it streams the graph and commits after every super-step, and reports an interrupt via
the checkpoint's pending `next` nodes. These tests pin that contract without a real graph."""
from __future__ import annotations

from types import SimpleNamespace

from vapt_orch.tasks import _drive_graph


class _FakeGraph:
    """Minimal graph stand-in: yields the given state chunks from stream(), and reports
    `next_nodes` from get_state() (truthy ⇒ paused at an interrupt)."""
    def __init__(self, chunks, next_nodes=()):
        self._chunks = chunks
        self._next = next_nodes
        self.stream_calls = 0

    def stream(self, inputs, config, stream_mode="values"):
        self.stream_calls += 1
        assert stream_mode == "values"
        yield from self._chunks

    def get_state(self, config):
        return SimpleNamespace(next=self._next)


class _CountingDb:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def test_commits_once_per_superstep():
    # Three super-steps ⇒ three commits: the ledger is published incrementally, so a
    # reader on another connection sees each node's events as it finishes.
    db = _CountingDb()
    g = _FakeGraph([{"phase": "recon"}, {"phase": "scan"}, {"phase": "report"}])
    final = _drive_graph(g, {"run_id": "r"}, {"configurable": {"thread_id": "t"}}, db)
    assert db.commits == 3
    assert final == {"phase": "report"}          # last streamed state is the final state
    assert "__interrupt__" not in final


def test_paused_graph_reports_interrupt():
    # A graph paused at an approval leaves a pending `next` node; _drive_graph surfaces
    # that as __interrupt__ so _finalize marks the run awaiting_approval (not completed).
    db = _CountingDb()
    g = _FakeGraph([{"phase": "scan"}], next_nodes=("probe_services",))
    final = _drive_graph(g, {"run_id": "r"}, {"configurable": {"thread_id": "t"}}, db)
    assert final.get("__interrupt__") is True
    assert final["phase"] == "scan"
    assert db.commits == 1                        # the completed super-step was still published


def test_empty_stream_is_safe():
    db = _CountingDb()
    g = _FakeGraph([])                            # no super-steps yielded
    final = _drive_graph(g, {"run_id": "r"}, {"configurable": {"thread_id": "t"}}, db)
    assert final == {}
    assert db.commits == 0
