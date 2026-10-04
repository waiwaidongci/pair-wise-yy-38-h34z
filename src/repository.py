from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import calculate_hash, make_entry, utc_now
from .domain import ConflictError, NotFoundError, RepairBatchGapConflict, ValidationError
from .rules import ENTITY, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS repair_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','ready','applied')),
                    break_event_id INTEGER NOT NULL,
                    last_valid_hash TEXT NOT NULL,
                    quarantined_event_count INTEGER NOT NULL,
                    valid_event_count INTEGER NOT NULL,
                    corrupt_event_count INTEGER NOT NULL,
                    reconnected_event_count INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    chief_confirmed_by TEXT,
                    chief_confirmed_at TEXT,
                    inspector_confirmed_by TEXT,
                    inspector_confirmed_at TEXT,
                    applied_by TEXT,
                    applied_at TEXT
                );
                CREATE TABLE IF NOT EXISTS repair_batch_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repair_batch_id INTEGER NOT NULL REFERENCES repair_batches(id) ON DELETE CASCADE,
                    item_id INTEGER NOT NULL,
                    UNIQUE(repair_batch_id, item_id)
                );
                CREATE TABLE IF NOT EXISTS quarantined_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repair_batch_id INTEGER NOT NULL REFERENCES repair_batches(id) ON DELETE CASCADE,
                    original_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    self_valid INTEGER NOT NULL,
                    reconnected_event_id INTEGER,
                    UNIQUE(repair_batch_id, original_id)
                );
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _event_payload(row: sqlite3.Row) -> Optional[Dict[str, Any]]:
        try:
            detail = json.loads(row["detail"])
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(detail, dict):
            return None
        return {
            "action": row["action"], "entity_type": row["entity_type"],
            "entity_id": row["entity_id"], "actor": row["actor"],
            "detail": detail, "created_at": row["created_at"],
        }

    def _event_self_valid(self, row: sqlite3.Row) -> bool:
        payload = self._event_payload(row)
        if payload is None:
            return False
        return calculate_hash(row["previous_hash"], payload) == row["entry_hash"]

    def _audit_breakpoint(self) -> Optional[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            payload = self._event_payload(row)
            if payload is None or row["previous_hash"] != previous:
                return {"row": row, "last_valid_hash": previous}
            expected = calculate_hash(previous, payload)
            if expected != row["entry_hash"]:
                return {"row": row, "last_valid_hash": previous}
            previous = row["entry_hash"]
        return None

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            self._insert_audit_event(event)
            event_id = int(self.conn.execute(
                "SELECT last_insert_rowid()"
            ).fetchone()[0])
        event["id"] = event_id
        return event

    def _insert_audit_event(self, event: Dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._audit_row(row) for row in rows]

    @staticmethod
    def _audit_row(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["detail"] = json.loads(item["detail"])
        return item

    def verify_audit_chain(self) -> bool:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            payload = self._event_payload(row)
            if payload is None or row["previous_hash"] != previous:
                return False
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def start_repair_batch(self, batch_no: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            existing = self.conn.execute(
                "SELECT * FROM repair_batches WHERE batch_no=?", (batch_no,)
            ).fetchone()
            if existing is not None:
                raise ConflictError(f"修复批次{batch_no}已存在")
            active = self.conn.execute(
                "SELECT batch_no FROM repair_batches WHERE status IN ('open','ready') LIMIT 1"
            ).fetchone()
            if active is not None:
                raise ConflictError(f"修复批次{active['batch_no']}仍在确认中")
            breakpoint_data = self._audit_breakpoint()
            if breakpoint_data is None:
                raise ValidationError("审计链未发现断点，无需修复")
            break_row = breakpoint_data["row"]
            suffix = self.conn.execute(
                "SELECT * FROM audit_events WHERE id>=? ORDER BY id",
                (break_row["id"],),
            ).fetchall()
            valid_count = sum(1 for row in suffix if self._event_self_valid(row))
            corrupt_count = len(suffix) - valid_count
            affected_ids = [
                int(row["entity_id"]) for row in suffix if row["entity_type"] == ENTITY
            ]
            affected_ids = sorted(set(affected_ids))
            cur = self.conn.execute(
                """INSERT INTO repair_batches(batch_no, status, break_event_id,
                   last_valid_hash, quarantined_event_count, valid_event_count,
                   corrupt_event_count, created_by, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (batch_no, "open", break_row["id"], breakpoint_data["last_valid_hash"],
                 len(suffix), valid_count, corrupt_count, actor, now),
            )
            batch_id = int(cur.lastrowid)
            for item_id in affected_ids:
                self.conn.execute(
                    "INSERT INTO repair_batch_items(repair_batch_id,item_id) VALUES(?,?)",
                    (batch_id, item_id),
                )
            for row in suffix:
                self.conn.execute(
                    """INSERT INTO quarantined_audit_events(repair_batch_id, original_id,
                       action, entity_type, entity_id, actor, detail, previous_hash,
                       entry_hash, created_at, self_valid)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch_id, row["id"], row["action"], row["entity_type"],
                     row["entity_id"], row["actor"], row["detail"], row["previous_hash"],
                     row["entry_hash"], row["created_at"],
                     1 if self._event_self_valid(row) else 0),
                )
            self.conn.execute(
                "DELETE FROM audit_events WHERE id>=?", (break_row["id"],)
            )
        return self.get_repair_batch_by_no(batch_no)

    def confirm_repair_batch(self, batch_no: str, role: str, actor: str) -> Dict[str, Any]:
        current = self.get_repair_batch_by_no(batch_no)
        if current["status"] != "open":
            raise ConflictError("修复批次已完成双方确认")
        if role == "chief_engineer":
            column, actor_column = "chief_confirmed_at", "chief_confirmed_by"
        else:
            column, actor_column = "inspector_confirmed_at", "inspector_confirmed_by"
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                f"""UPDATE repair_batches SET {column}=?, {actor_column}=?
                    WHERE batch_no=? AND status='open' AND {column} IS NULL""",
                (now, actor, batch_no),
            )
            if cur.rowcount == 0:
                raise ConflictError("该角色已确认修复范围")
            self.conn.execute(
                """UPDATE repair_batches SET status='ready'
                   WHERE batch_no=? AND chief_confirmed_at IS NOT NULL
                     AND inspector_confirmed_at IS NOT NULL""",
                (batch_no,),
            )
        return self.get_repair_batch_by_no(batch_no)

    def apply_repair_batch(self, batch_no: str, actor: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            batch = self.conn.execute(
                "SELECT * FROM repair_batches WHERE batch_no=?", (batch_no,)
            ).fetchone()
            if batch is None:
                raise NotFoundError("修复批次不存在")
            if batch["status"] == "applied":
                raise RepairBatchGapConflict(batch_no)
            if batch["status"] != "ready":
                raise ConflictError("修复批次需总工和纪检分别确认范围")
            now = utc_now()
            cur = self.conn.execute(
                """UPDATE repair_batches SET status='applied', applied_by=?, applied_at=?
                   WHERE batch_no=? AND status='ready'""",
                (actor, now, batch_no),
            )
            if cur.rowcount == 0:
                refreshed = self.conn.execute(
                    "SELECT status FROM repair_batches WHERE batch_no=?", (batch_no,)
                ).fetchone()
                if refreshed is not None and refreshed["status"] == "applied":
                    raise RepairBatchGapConflict(batch_no)
                raise ConflictError("修复批次状态已变化，请刷新后重试")

            tail = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = tail["entry_hash"] if tail else "GENESIS"
            valid_rows = self.conn.execute(
                """SELECT * FROM quarantined_audit_events
                   WHERE repair_batch_id=? AND self_valid=1 ORDER BY original_id""",
                (batch["id"],),
            ).fetchall()
            begin_detail = {
                "batch_no": batch_no,
                "continued_from_hash": batch["last_valid_hash"],
                "live_tail_hash": previous,
                "quarantined_event_count": batch["quarantined_event_count"],
                "affected_item_ids": self._repair_item_ids(batch["id"]),
            }
            begin = make_entry("repair_begin", "repair_batch", batch["id"], actor,
                               begin_detail, previous, now)
            self._insert_audit_event(begin)
            previous = begin["entry_hash"]
            reconnected = 0
            for quarantined in valid_rows:
                detail = json.loads(quarantined["detail"])
                event = make_entry(
                    quarantined["action"], quarantined["entity_type"],
                    quarantined["entity_id"], quarantined["actor"], detail, previous,
                    quarantined["created_at"],
                )
                self._insert_audit_event(event)
                new_id = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
                self.conn.execute(
                    "UPDATE quarantined_audit_events SET reconnected_event_id=? WHERE id=?",
                    (new_id, quarantined["id"]),
                )
                previous = event["entry_hash"]
                reconnected += 1
            complete = make_entry(
                "repair_complete", "repair_batch", batch["id"], actor,
                {"batch_no": batch_no, "reconnected_event_count": reconnected,
                 "quarantined_event_count": batch["quarantined_event_count"],
                 "remaining_corrupt_count": batch["quarantined_event_count"] - reconnected},
                previous, now,
            )
            self._insert_audit_event(complete)
            self.conn.execute(
                "UPDATE repair_batches SET reconnected_event_count=? WHERE id=?",
                (reconnected, batch["id"]),
            )
        return self.get_repair_batch_by_no(batch_no)

    def _repair_item_ids(self, batch_id: int) -> List[int]:
        rows = self.conn.execute(
            "SELECT item_id FROM repair_batch_items WHERE repair_batch_id=? ORDER BY item_id",
            (batch_id,),
        ).fetchall()
        return [int(row["item_id"]) for row in rows]

    def _repair_batch(self, row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        result["affected_item_ids"] = self._repair_item_ids(result["id"])
        result["quarantined_events"] = self.list_quarantined_events(result["id"])
        return result

    def get_repair_batch_by_no(self, batch_no: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM repair_batches WHERE batch_no=?", (batch_no,)
            ).fetchone()
        if row is None:
            raise NotFoundError("修复批次不存在")
        return self._repair_batch(row)

    def list_repair_batches(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM repair_batches"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._repair_batch(row) for row in rows]

    def list_quarantined_events(self, batch_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                """SELECT * FROM quarantined_audit_events
                   WHERE repair_batch_id=? ORDER BY original_id""",
                (batch_id,),
            ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["self_valid"] = bool(event["self_valid"])
            event["detail"] = json.loads(event["detail"])
            events.append(event)
        return events

    def active_repair_batch_for_item(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT b.* FROM repair_batches b
                   JOIN repair_batch_items i ON i.repair_batch_id=b.id
                   WHERE i.item_id=? AND b.status IN ('open','ready')
                   ORDER BY b.id DESC LIMIT 1""",
                (item_id,),
            ).fetchone()
        return self._repair_batch(row) if row is not None else None

    def close(self) -> None:
        with self._lock:
            self.conn.close()
