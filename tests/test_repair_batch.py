import json
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.rules import STATES, TRANSITION_ROLES
from src.service import Service


class RepairBatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self._build_chain()

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _build_chain(self):
        # itemA: 完整流程，事件 1-5，始终在断点之前（不受影响）
        self.item_a = self.service.create_item(
            {"title": "itemA", "description": "before breakpoint",
             "severity": "urgent", "quantity": 5, "threshold": 10,
             "external_ref": "A-1"}, "creator", "duty_officer")
        self.service.add_record(self.item_a["id"], {
            "kind": "evidence", "detail": "closed evidence",
            "status": "closed", "external_ref": "A-EV-1"},
            "recorder", "duty_officer")
        current = self.item_a
        for target in STATES[1:-1]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        self.item_a = current

        # itemB: 仅创建，事件 6 —— 将被篡改为断点
        self.item_b = self.service.create_item(
            {"title": "itemB", "description": "damaged event owner",
             "severity": "routine", "quantity": 1, "threshold": 10,
             "external_ref": "B-1"}, "creator", "duty_officer")

        # itemC: 完整流程，事件 7-11，在断点之后（被隔离，未损坏）
        self.item_c = self.service.create_item(
            {"title": "itemC", "description": "after breakpoint",
             "severity": "urgent", "quantity": 5, "threshold": 10,
             "external_ref": "C-1"}, "creator", "duty_officer")
        self.service.add_record(self.item_c["id"], {
            "kind": "evidence", "detail": "closed evidence",
            "status": "closed", "external_ref": "C-EV-1"},
            "recorder", "duty_officer")
        current = self.item_c
        for target in STATES[1:-1]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0])
        self.item_c = current

    def _corrupt_event(self, event_id):
        row = self.repo.conn.execute(
            "SELECT * FROM audit_events WHERE id=?", (event_id,)
        ).fetchone()
        detail = json.loads(row["detail"])
        detail["tampered"] = True
        with self.repo.conn:
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                (json.dumps(detail, ensure_ascii=False, sort_keys=True), event_id))

    def _event_ids(self):
        rows = self.repo.conn.execute(
            "SELECT id FROM audit_events ORDER BY id"
        ).fetchall()
        return [r["id"] for r in rows]

    def test_breakpoint_detection(self):
        # 完整链校验通过
        self.assertTrue(self.repo.verify_audit_chain())
        self.assertIsNone(self.repo.find_breakpoint())
        # 篡改 itemB 的创建事件（事件 6）
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        # 定位首个断点
        bp = self.repo.find_breakpoint()
        self.assertIsNotNone(bp)
        self.assertEqual(bp["id"], ids[5])
        # 完整链校验失败
        self.assertFalse(self.repo.verify_audit_chain())

    def test_quarantine_isolates_without_modifying_audit(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        before_count = len(ids)
        before_detail = self.repo.conn.execute(
            "SELECT detail FROM audit_events WHERE id=?", (ids[5],)
        ).fetchone()["detail"]
        batch = self.service.create_repair_batch("duty", "duty_officer")
        # 批次记录范围
        self.assertEqual(batch["breakpoint_event_id"], ids[5])
        self.assertEqual(batch["quarantined_count"], 6)
        self.assertIn(self.item_b["id"], batch["affected_item_ids"])
        self.assertIn(self.item_c["id"], batch["affected_item_ids"])
        self.assertNotIn(self.item_a["id"], batch["affected_item_ids"])
        # 旧事件不改写：审计事件数量不变，被篡改事件仍是被篡改状态
        after_count = self.repo.conn.execute(
            "SELECT COUNT(*) AS n FROM audit_events"
        ).fetchone()["n"]
        self.assertEqual(after_count, before_count)
        after_detail = self.repo.conn.execute(
            "SELECT detail FROM audit_events WHERE id=?", (ids[5],)
        ).fetchone()["detail"]
        self.assertEqual(after_detail, before_detail)
        # 隔离行：事件 6 损坏，事件 7-11 未损坏
        qrows = self.repo.conn.execute(
            "SELECT event_id, damaged, reconnected FROM quarantined_events ORDER BY event_id"
        ).fetchall()
        self.assertEqual(len(qrows), 6)
        self.assertEqual(qrows[0]["event_id"], ids[5])
        self.assertEqual(qrows[0]["damaged"], 1)
        for r in qrows[1:]:
            self.assertEqual(r["damaged"], 0)
            self.assertEqual(r["reconnected"], 0)

    def test_affected_items_pause_closing(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        self.service.create_repair_batch("duty", "duty_officer")
        # itemA 不受影响，可以关闭
        closed_a = self.service.transition(
            self.item_a["id"], "closed", self.item_a["version"],
            "boss", "chief_engineer")
        self.assertEqual(closed_a["status"], "closed")
        # itemC 受影响，暂停关闭
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.item_c["id"], "closed", self.item_c["version"],
                "boss", "chief_engineer")

    def test_repair_requires_dual_confirmation(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        batch = self.service.create_repair_batch("duty", "duty_officer")
        # 未确认时不能续写
        with self.assertRaises(ConflictError):
            self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
        # 总工确认
        self.service.confirm_repair_batch(batch["batch_no"], "eng", "chief_engineer")
        refreshed = self.service.get_repair_batch(batch["batch_no"], "viewer")
        self.assertEqual(refreshed["status"], "open")
        self.assertIsNotNone(refreshed["chief_confirmed_by"])
        self.assertIsNone(refreshed["inspector_confirmed_by"])
        # 仅总工确认仍不能续写
        with self.assertRaises(ConflictError):
            self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
        # 纪检确认后转为 confirmed
        self.service.confirm_repair_batch(batch["batch_no"], "ins", "discipline_inspector")
        refreshed = self.service.get_repair_batch(batch["batch_no"], "viewer")
        self.assertEqual(refreshed["status"], "confirmed")
        self.assertIsNotNone(refreshed["inspector_confirmed_by"])

    def test_repair_reconnects_undamaged_and_restores_chain(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        batch = self.service.create_repair_batch("duty", "duty_officer")
        self.service.confirm_repair_batch(batch["batch_no"], "eng", "chief_engineer")
        self.service.confirm_repair_batch(batch["batch_no"], "ins", "discipline_inspector")
        repaired = self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
        self.assertEqual(repaired["status"], "repaired")
        # 未损坏记录已接回，损坏记录仍隔离
        qrows = self.repo.conn.execute(
            "SELECT event_id, damaged, reconnected FROM quarantined_events ORDER BY event_id"
        ).fetchall()
        self.assertEqual(qrows[0]["damaged"], 1)
        self.assertEqual(qrows[0]["reconnected"], 0)
        for r in qrows[1:]:
            self.assertEqual(r["damaged"], 0)
            self.assertEqual(r["reconnected"], 1)
        # 修复事件从最后一个有效哈希续写
        repair_events = self.repo.conn.execute(
            "SELECT * FROM audit_events WHERE action='repair' ORDER BY id"
        ).fetchall()
        self.assertEqual(len(repair_events), 5)  # 事件 7-11
        # 活跃链完整
        self.assertTrue(self.repo.verify_audit_chain())
        self.assertIsNone(self.repo.find_breakpoint())
        # itemC 已接回，可以关闭
        closed_c = self.service.transition(
            self.item_c["id"], "closed", self.item_c["version"],
            "boss", "chief_engineer")
        self.assertEqual(closed_c["status"], "closed")
        # itemB 仍有损坏记录，暂停关闭
        with self.assertRaises(ConflictError):
            self.service.transition(
                self.item_b["id"], "closed", self.item_b["version"],
                "boss", "chief_engineer")

    def test_repair_is_idempotent_by_batch_no(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        batch = self.service.create_repair_batch("duty", "duty_officer")
        self.service.confirm_repair_batch(batch["batch_no"], "eng", "chief_engineer")
        self.service.confirm_repair_batch(batch["batch_no"], "ins", "discipline_inspector")
        self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
        repair_count_1 = self.repo.conn.execute(
            "SELECT COUNT(*) AS n FROM audit_events WHERE action='repair'"
        ).fetchone()["n"]
        # 按批次号重试，不重复写修复事件
        with self.assertRaises(ConflictError):
            self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
        repair_count_2 = self.repo.conn.execute(
            "SELECT COUNT(*) AS n FROM audit_events WHERE action='repair'"
        ).fetchone()["n"]
        self.assertEqual(repair_count_1, repair_count_2)

    def test_concurrent_submit_first_wins_later_sees_gap(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        batch = self.service.create_repair_batch("duty", "duty_officer")
        self.service.confirm_repair_batch(batch["batch_no"], "eng", "chief_engineer")
        self.service.confirm_repair_batch(batch["batch_no"], "ins", "discipline_inspector")
        results = []

        def submit():
            try:
                self.service.execute_repair(batch["batch_no"], "boss", "chief_engineer")
                results.append("ok")
            except ConflictError:
                results.append("conflict")

        threads = [threading.Thread(target=submit) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 先到生效，后到看到缺口
        self.assertEqual(sorted(results), ["conflict", "ok"])
        repaired = self.service.get_repair_batch(batch["batch_no"], "viewer")
        self.assertEqual(repaired["status"], "repaired")

    def test_confirmation_requires_correct_role(self):
        ids = self._event_ids()
        self._corrupt_event(ids[5])
        batch = self.service.create_repair_batch("duty", "duty_officer")
        # viewer 不能确认
        with self.assertRaises(PermissionDenied):
            self.service.confirm_repair_batch(batch["batch_no"], "nosy", "viewer")
        # dispatcher 不能确认
        with self.assertRaises(PermissionDenied):
            self.service.confirm_repair_batch(batch["batch_no"], "nosy", "dispatcher")


if __name__ == "__main__":
    unittest.main()
