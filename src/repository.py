from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, recompute_entry_hash, utc_now
from .domain import ConflictError, NotFoundError, PermissionDenied
from .rules import (BATCH_STATUS_CONFIRMED, BATCH_STATUS_OPEN,
                     BATCH_STATUS_REPAIRED, ENTITY, ID_PREFIX, STATES)


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
                    status TEXT NOT NULL DEFAULT 'open',
                    breakpoint_event_id INTEGER NOT NULL,
                    last_valid_hash TEXT NOT NULL,
                    quarantined_count INTEGER NOT NULL DEFAULT 0,
                    affected_item_ids TEXT NOT NULL DEFAULT '[]',
                    damaged_event_ids TEXT NOT NULL DEFAULT '[]',
                    undamaged_event_ids TEXT NOT NULL DEFAULT '[]',
                    chief_confirmed_by TEXT,
                    chief_confirmed_at TEXT,
                    inspector_confirmed_by TEXT,
                    inspector_confirmed_at TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS quarantined_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES repair_batches(id),
                    event_id INTEGER NOT NULL UNIQUE REFERENCES audit_events(id),
                    item_id INTEGER NOT NULL,
                    damaged INTEGER NOT NULL DEFAULT 0,
                    reconnected INTEGER NOT NULL DEFAULT 0,
                    original_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_quarantined_events_batch
                    ON quarantined_events(batch_id);
                CREATE INDEX IF NOT EXISTS idx_quarantined_events_item
                    ON quarantined_events(item_id);
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

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
            # 从最后一个未隔离事件续写，保证隔离期内活跃链仍然完整
            row = self.conn.execute(
                """SELECT e.entry_hash FROM audit_events e
                   LEFT JOIN quarantined_events q ON q.event_id = e.id
                   WHERE q.id IS NULL
                   ORDER BY e.id DESC LIMIT 1"""
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            # 只校验未隔离的活跃事件；隔离事件不参与活跃链
            rows = self.conn.execute(
                """SELECT e.* FROM audit_events e
                   LEFT JOIN quarantined_events q ON q.event_id = e.id
                   WHERE q.id IS NULL
                   ORDER BY e.id"""
            ).fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # -- 修复批次 -------------------------------------------------------------

    def find_breakpoint(self) -> Optional[Dict[str, Any]]:
        """定位活跃审计链上的首个断点（previous_hash 衔接失败或 entry_hash 被篡改）。
        链完整时返回 None。"""
        with self._lock:
            rows = self.conn.execute(
                """SELECT e.* FROM audit_events e
                   LEFT JOIN quarantined_events q ON q.event_id = e.id
                   WHERE q.id IS NULL
                   ORDER BY e.id"""
            ).fetchall()
        previous = "GENESIS"
        for row in rows:
            event = dict(row)
            event["detail"] = json.loads(event["detail"])
            if event["previous_hash"] != previous:
                return event
            if recompute_entry_hash(event) != event["entry_hash"]:
                return event
            previous = event["entry_hash"]
        return None

    def get_repair_batch(self, batch_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM repair_batches WHERE batch_no=?", (batch_no,)
            ).fetchone()
        if row is None:
            return None
        batch = dict(row)
        batch["affected_item_ids"] = json.loads(batch["affected_item_ids"])
        batch["damaged_event_ids"] = json.loads(batch["damaged_event_ids"])
        batch["undamaged_event_ids"] = json.loads(batch["undamaged_event_ids"])
        return batch

    def get_active_repair_batch(self) -> Optional[Dict[str, Any]]:
        """返回尚未完成（open 或 confirmed）的批次；同一时刻只允许一个活跃批次。"""
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM repair_batches WHERE status IN (?,?) ORDER BY id DESC LIMIT 1",
                (BATCH_STATUS_OPEN, BATCH_STATUS_CONFIRMED),
            ).fetchone()
        if row is None:
            return None
        return self.get_repair_batch(row["batch_no"])

    def list_repair_batches(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM repair_batches ORDER BY id DESC"
            ).fetchall()
        result = []
        for row in rows:
            batch = dict(row)
            batch["affected_item_ids"] = json.loads(batch["affected_item_ids"])
            batch["damaged_event_ids"] = json.loads(batch["damaged_event_ids"])
            batch["undamaged_event_ids"] = json.loads(batch["undamaged_event_ids"])
            result.append(batch)
        return result

    def create_repair_batch(self, actor: str) -> Dict[str, Any]:
        """定位首个断点，把断点及之后的事件隔离（不改写审计事件），生成修复批次。"""
        breakpoint = self.find_breakpoint()
        if breakpoint is None:
            raise ConflictError("审计链完整，无需修复")
        if self.get_active_repair_batch() is not None:
            raise ConflictError("存在未完成的修复批次，请先处理")
        now = utc_now()
        with self._lock, self.conn:
            # 最后一个有效哈希 = 断点前一个事件的 entry_hash
            last_valid_hash = "GENESIS"
            prev_row = self.conn.execute(
                "SELECT entry_hash FROM audit_events WHERE id < ? ORDER BY id DESC LIMIT 1",
                (breakpoint["id"],),
            ).fetchone()
            if prev_row is not None:
                last_valid_hash = prev_row["entry_hash"]
            # 断点及之后的全部事件隔离
            rows = self.conn.execute(
                "SELECT * FROM audit_events WHERE id >= ? ORDER BY id",
                (breakpoint["id"],),
            ).fetchall()
            quarantined: List[Dict[str, Any]] = []
            damaged_ids: List[int] = []
            undamaged_ids: List[int] = []
            affected_items: set = set()
            for row in rows:
                event = dict(row)
                event["detail"] = json.loads(event["detail"])
                is_damaged = recompute_entry_hash(event) != event["entry_hash"]
                quarantined.append({
                    "event_id": event["id"],
                    "item_id": event["entity_id"],
                    "damaged": 1 if is_damaged else 0,
                    "original_hash": event["entry_hash"],
                })
                if is_damaged:
                    damaged_ids.append(event["id"])
                else:
                    undamaged_ids.append(event["id"])
                affected_items.add(event["entity_id"])
            batch_no = f"RP-{uuid.uuid4().hex[:12]}"
            cur = self.conn.execute(
                """INSERT INTO repair_batches(batch_no, status, breakpoint_event_id,
                   last_valid_hash, quarantined_count, affected_item_ids,
                   damaged_event_ids, undamaged_event_ids, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (batch_no, BATCH_STATUS_OPEN, breakpoint["id"], last_valid_hash,
                 len(quarantined), json.dumps(sorted(affected_items)),
                 json.dumps(damaged_ids), json.dumps(undamaged_ids), actor, now, now),
            )
            batch_id = int(cur.lastrowid)
            for q in quarantined:
                self.conn.execute(
                    """INSERT INTO quarantined_events(batch_id, event_id, item_id,
                       damaged, reconnected, original_hash, created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (batch_id, q["event_id"], q["item_id"], q["damaged"], 0,
                     q["original_hash"], now),
                )
        return self.get_repair_batch(batch_no)

    def confirm_repair_batch(self, batch_no: str, role: str,
                             actor: str) -> Dict[str, Any]:
        """总工或纪检确认修复范围；按角色幂等，双方确认后批次转为 confirmed。"""
        now = utc_now()
        with self._lock, self.conn:
            batch = self.get_repair_batch(batch_no)
            if batch is None:
                raise NotFoundError("修复批次不存在")
            if batch["status"] == BATCH_STATUS_REPAIRED:
                raise ConflictError("修复批次已完成，无需确认")
            if role == "chief_engineer":
                if batch["chief_confirmed_by"] is not None:
                    return batch
                self.conn.execute(
                    "UPDATE repair_batches SET chief_confirmed_by=?, chief_confirmed_at=?, updated_at=? WHERE id=?",
                    (actor, now, now, batch["id"]),
                )
            elif role == "discipline_inspector":
                if batch["inspector_confirmed_by"] is not None:
                    return batch
                self.conn.execute(
                    "UPDATE repair_batches SET inspector_confirmed_by=?, inspector_confirmed_at=?, updated_at=? WHERE id=?",
                    (actor, now, now, batch["id"]),
                )
            else:
                raise PermissionDenied("当前角色无权确认修复批次")
            refreshed = self.get_repair_batch(batch_no)
            if refreshed["chief_confirmed_by"] and refreshed["inspector_confirmed_by"]:
                self.conn.execute(
                    "UPDATE repair_batches SET status=?, updated_at=? WHERE id=?",
                    (BATCH_STATUS_CONFIRMED, now, batch["id"]),
                )
        return self.get_repair_batch(batch_no)

    def execute_repair(self, batch_no: str, actor: str) -> Dict[str, Any]:
        """从最后一个有效哈希续写修复事件，把未损坏的隔离记录接回。
        按批次号幂等重试；并发提交时先到生效，后到看到缺口。"""
        now = utc_now()
        with self._lock, self.conn:
            batch = self.get_repair_batch(batch_no)
            if batch is None:
                raise NotFoundError("修复批次不存在")
            if batch["status"] == BATCH_STATUS_REPAIRED:
                # 后到者看到缺口：批次已修复，修复事件已写入
                raise ConflictError("修复批次已完成，请勿重复提交")
            if batch["status"] != BATCH_STATUS_CONFIRMED:
                raise ConflictError("修复批次尚未经总工和纪检确认，不能续写修复事件")
            # 幂等续写：只写尚未接回的未损坏事件
            quarantined = self.conn.execute(
                """SELECT * FROM quarantined_events
                   WHERE batch_id=? AND damaged=0 AND reconnected=0
                   ORDER BY event_id""",
                (batch["id"],),
            ).fetchall()
            # 从当前活跃链尾（最后一个有效哈希）续写
            tail = self.conn.execute(
                """SELECT e.entry_hash FROM audit_events e
                   LEFT JOIN quarantined_events q ON q.event_id = e.id
                   WHERE q.id IS NULL
                   ORDER BY e.id DESC LIMIT 1"""
            ).fetchone()
            last_hash = tail["entry_hash"] if tail is not None else batch["last_valid_hash"]
            for q in quarantined:
                event = make_entry("repair", ENTITY, q["item_id"], actor, {
                    "batch_no": batch_no,
                    "reconnect_event_id": q["event_id"],
                    "original_hash": q["original_hash"],
                }, last_hash)
                self.conn.execute(
                    """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                       previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                    (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                     json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                     event["previous_hash"], event["entry_hash"], event["created_at"]),
                )
                last_hash = event["entry_hash"]
                self.conn.execute(
                    "UPDATE quarantined_events SET reconnected=1 WHERE id=?",
                    (q["id"],),
                )
            # 乐观并发：仅当批次仍为 confirmed 时才置为 repaired
            cur = self.conn.execute(
                "UPDATE repair_batches SET status=?, updated_at=? WHERE id=? AND status=?",
                (BATCH_STATUS_REPAIRED, now, batch["id"], BATCH_STATUS_CONFIRMED),
            )
            if cur.rowcount == 0:
                raise ConflictError("修复批次已被其他提交者完成")
        return self.get_repair_batch(batch_no)

    def count_unrepaired_quarantine(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM quarantined_events WHERE item_id=? AND reconnected=0",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def close(self) -> None:
        with self._lock:
            self.conn.close()
