"""Durable LangGraph checkpointer backed by SQLAlchemy / MariaDB (plan §6, §8).

This closes the Week 1-3 spike: a paused run (interrupted for approval) survives a
worker restart and resumes on the same thread, because its checkpoint is in the
database rather than in process memory.

It mirrors LangGraph's own InMemorySaver storage model exactly, across three tables:

  graph_checkpoints        one row per (thread, ns, checkpoint_id): the serialized
                           checkpoint (minus channel values) + metadata + parent id
  graph_checkpoint_blobs   channel values, one row per (thread, ns, channel, version)
  graph_checkpoint_writes  pending writes, one row per (thread, ns, ckpt, task, idx)

Serialization uses the saver's own serde (JsonPlusSerializer by default), so the
on-disk bytes are exactly what LangGraph would store, and versioning is inherited
from BaseCheckpointSaver (monotonic integers).

The checkpointer uses a short-lived session per call, independent of the run's own
DB transaction: checkpoint durability is deliberately decoupled from the ledger, and
the ledger — not the checkpoint — remains the authority on what actually executed.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from typing import Any

from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)
from sqlalchemy import select
from sqlalchemy.orm import Session
from vapt_persistence.models import (
    GraphCheckpoint,
    GraphCheckpointBlob,
    GraphCheckpointWrite,
)

try:  # RunnableConfig is just a TypedDict/dict at runtime
    from langchain_core.runnables import RunnableConfig
except Exception:  # pragma: no cover
    RunnableConfig = dict  # type: ignore


class SqlAlchemyCheckpointer(BaseCheckpointSaver):
    """A persistent checkpoint saver. Construct with a session factory (e.g.
    vapt_persistence.db.SessionLocal). Synchronous API only — the orchestrator's
    Celery workers run the graph synchronously."""

    def __init__(self, session_factory: Callable[[], Session], *, serde=None):
        super().__init__(serde=serde)
        self._session_factory = session_factory

    # -- helpers --------------------------------------------------------------
    def _blob_map(self, db: Session, thread_id: str, ns: str) -> dict[tuple[str, str], tuple[str, bytes | None]]:
        rows = db.execute(
            select(GraphCheckpointBlob).where(
                GraphCheckpointBlob.thread_id == thread_id,
                GraphCheckpointBlob.checkpoint_ns == ns,
            )
        ).scalars().all()
        return {(r.channel, r.version): (r.type, r.blob) for r in rows}

    def _load_blobs(self, blobs: dict, versions: ChannelVersions) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for channel, ver in versions.items():
            key = (channel, str(ver))
            if key not in blobs:
                continue
            type_, data = blobs[key]
            if type_ == "empty":
                continue
            result[channel] = self.serde.loads_typed((type_, data or b""))
        return result

    def _writes_for(self, db: Session, thread_id: str, ns: str, checkpoint_id: str):
        rows = db.execute(
            select(GraphCheckpointWrite)
            .where(
                GraphCheckpointWrite.thread_id == thread_id,
                GraphCheckpointWrite.checkpoint_ns == ns,
                GraphCheckpointWrite.checkpoint_id == checkpoint_id,
            )
            .order_by(GraphCheckpointWrite.idx)
        ).scalars().all()
        return [(r.task_id, r.channel, self.serde.loads_typed((r.type, r.blob))) for r in rows]

    def _tuple_from_row(self, db: Session, row: GraphCheckpoint) -> CheckpointTuple:
        checkpoint_: Checkpoint = self.serde.loads_typed((row.type, row.checkpoint))
        blobs = self._blob_map(db, row.thread_id, row.checkpoint_ns)
        config = {
            "configurable": {
                "thread_id": row.thread_id,
                "checkpoint_ns": row.checkpoint_ns,
                "checkpoint_id": row.checkpoint_id,
            }
        }
        parent = (
            {
                "configurable": {
                    "thread_id": row.thread_id,
                    "checkpoint_ns": row.checkpoint_ns,
                    "checkpoint_id": row.parent_checkpoint_id,
                }
            }
            if row.parent_checkpoint_id
            else None
        )
        return CheckpointTuple(
            config=config,
            checkpoint={
                **checkpoint_,
                "channel_values": self._load_blobs(blobs, checkpoint_["channel_versions"]),
            },
            metadata=self.serde.loads_typed((row.metadata_type, row.checkpoint_metadata)),
            parent_config=parent,
            pending_writes=self._writes_for(db, row.thread_id, row.checkpoint_ns, row.checkpoint_id),
        )

    # -- reads ----------------------------------------------------------------
    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = get_checkpoint_id(config)
        db = self._session_factory()
        try:
            q = select(GraphCheckpoint).where(
                GraphCheckpoint.thread_id == thread_id,
                GraphCheckpoint.checkpoint_ns == ns,
            )
            if checkpoint_id:
                q = q.where(GraphCheckpoint.checkpoint_id == checkpoint_id)
            else:
                q = q.order_by(GraphCheckpoint.checkpoint_id.desc()).limit(1)
            row = db.execute(q).scalars().first()
            return self._tuple_from_row(db, row) if row else None
        finally:
            db.close()

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        db = self._session_factory()
        try:
            q = select(GraphCheckpoint)
            if config:
                q = q.where(GraphCheckpoint.thread_id == config["configurable"]["thread_id"])
                ns = config["configurable"].get("checkpoint_ns")
                if ns is not None:
                    q = q.where(GraphCheckpoint.checkpoint_ns == ns)
            if before and (bid := get_checkpoint_id(before)):
                q = q.where(GraphCheckpoint.checkpoint_id < bid)
            q = q.order_by(GraphCheckpoint.checkpoint_id.desc())
            if limit is not None:
                q = q.limit(limit)
            rows = db.execute(q).scalars().all()
            for row in rows:
                tup = self._tuple_from_row(db, row)
                if filter and not all(tup.metadata.get(k) == v for k, v in filter.items()):
                    continue
                yield tup
        finally:
            db.close()

    # -- writes ---------------------------------------------------------------
    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        c = checkpoint.copy()
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"]["checkpoint_ns"]
        values: dict[str, Any] = c.pop("channel_values")  # type: ignore[assignment]
        parent_id = config["configurable"].get("checkpoint_id")

        db = self._session_factory()
        try:
            # channel-value blobs, one per new version
            for channel, ver in new_versions.items():
                type_, data = (
                    self.serde.dumps_typed(values[channel]) if channel in values else ("empty", b"")
                )
                self._upsert_blob(db, thread_id, ns, channel, str(ver), type_, data)

            ck_type, ck_bytes = self.serde.dumps_typed(c)
            meta = get_checkpoint_metadata(config, metadata)
            meta_type, meta_bytes = self.serde.dumps_typed(meta)
            self._upsert_checkpoint(
                db, thread_id, ns, checkpoint["id"], parent_id,
                ck_type, ck_bytes, meta_type, meta_bytes,
            )
            db.commit()
        finally:
            db.close()

        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": ns,
                "checkpoint_id": checkpoint["id"],
            }
        }

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        thread_id = config["configurable"]["thread_id"]
        ns = config["configurable"].get("checkpoint_ns", "")
        checkpoint_id = config["configurable"]["checkpoint_id"]
        db = self._session_factory()
        try:
            for idx, (channel, value) in enumerate(writes):
                widx = WRITES_IDX_MAP.get(channel, idx)
                type_, data = self.serde.dumps_typed(value)
                self._upsert_write(
                    db, thread_id, ns, checkpoint_id, task_id, widx,
                    channel, type_, data, task_path,
                    # positive indices are append-only; special (negative) ones overwrite
                    overwrite=widx < 0,
                )
            db.commit()
        finally:
            db.close()

    # -- upserts (query-then-write; one worker per thread, so no race) --------
    def _upsert_blob(self, db, thread_id, ns, channel, version, type_, data):
        row = db.execute(
            select(GraphCheckpointBlob).where(
                GraphCheckpointBlob.thread_id == thread_id,
                GraphCheckpointBlob.checkpoint_ns == ns,
                GraphCheckpointBlob.channel == channel,
                GraphCheckpointBlob.version == version,
            )
        ).scalars().first()
        if row:
            row.type, row.blob = type_, data
        else:
            db.add(GraphCheckpointBlob(
                thread_id=thread_id, checkpoint_ns=ns, channel=channel,
                version=version, type=type_, blob=data,
            ))
        db.flush()

    def _upsert_checkpoint(self, db, thread_id, ns, checkpoint_id, parent_id,
                           ck_type, ck_bytes, meta_type, meta_bytes):
        row = db.execute(
            select(GraphCheckpoint).where(
                GraphCheckpoint.thread_id == thread_id,
                GraphCheckpoint.checkpoint_ns == ns,
                GraphCheckpoint.checkpoint_id == checkpoint_id,
            )
        ).scalars().first()
        if row:
            row.parent_checkpoint_id = parent_id
            row.type, row.checkpoint = ck_type, ck_bytes
            row.metadata_type, row.checkpoint_metadata = meta_type, meta_bytes
        else:
            db.add(GraphCheckpoint(
                thread_id=thread_id, checkpoint_ns=ns, checkpoint_id=checkpoint_id,
                parent_checkpoint_id=parent_id, type=ck_type, checkpoint=ck_bytes,
                metadata_type=meta_type, checkpoint_metadata=meta_bytes,
            ))
        db.flush()

    def _upsert_write(self, db, thread_id, ns, checkpoint_id, task_id, idx,
                      channel, type_, data, task_path, *, overwrite):
        row = db.execute(
            select(GraphCheckpointWrite).where(
                GraphCheckpointWrite.thread_id == thread_id,
                GraphCheckpointWrite.checkpoint_ns == ns,
                GraphCheckpointWrite.checkpoint_id == checkpoint_id,
                GraphCheckpointWrite.task_id == task_id,
                GraphCheckpointWrite.idx == idx,
            )
        ).scalars().first()
        if row:
            if overwrite:
                row.channel, row.type, row.blob, row.task_path = channel, type_, data, task_path
                db.flush()
            return  # positive-index writes are append-only
        db.add(GraphCheckpointWrite(
            thread_id=thread_id, checkpoint_ns=ns, checkpoint_id=checkpoint_id,
            task_id=task_id, idx=idx, channel=channel, type=type_, blob=data,
            task_path=task_path,
        ))
        db.flush()
