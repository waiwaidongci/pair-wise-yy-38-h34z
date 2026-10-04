import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from src.domain import ConflictError, PermissionDenied, RepairBatchGapConflict, ValidationError
from src.http_api import make_handler
from src.repository import Repository
from src.rules import STATES, TRANSITION_ROLES
from src.service import Service


class RepairWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self._complete_to_executed("REPAIR-1", "repair item")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _complete_to_executed(self, ref, title):
        item = self.service.create_item({
            "title": title, "description": "repair scenario", "severity": "urgent",
            "quantity": 12, "threshold": 6, "external_ref": ref,
        }, "creator", "duty_officer")
        self.service.add_record(item["id"], {
            "kind": "evidence", "detail": "closed evidence", "status": "closed",
            "external_ref": ref + "-EV",
        }, "recorder", "duty_officer")
        current = item
        for target in STATES[1:-1]:
            current = self.service.transition(
                current["id"], target, current["version"], "reviewer",
                TRANSITION_ROLES[target][0],
            )
        return current

    def _corrupt_second_audit_event(self):
        with self.repo._lock, self.repo.conn:
            untouched = self.repo.conn.execute(
                "SELECT * FROM audit_events ORDER BY id LIMIT 1"
            ).fetchone()
            row = self.repo.conn.execute(
                "SELECT * FROM audit_events ORDER BY id LIMIT 1 OFFSET 1"
            ).fetchone()
            detail = json.loads(row["detail"])
            detail["tampered"] = True
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                (json.dumps(detail, ensure_ascii=False, sort_keys=True), row["id"]),
            )
        return dict(untouched), row["id"]

    def test_locates_breakpoint_quarantines_and_reconnects_from_last_valid_hash(self):
        untouched, corrupt_id = self._corrupt_second_audit_event()
        self.assertFalse(self.repo.verify_audit_chain())

        batch = self.service.start_repair_batch(
            {"batch_no": "RB-001"}, "duty", "duty_officer"
        )
        self.assertEqual(batch["status"], "open")
        self.assertEqual(batch["break_event_id"], corrupt_id)
        self.assertEqual(batch["quarantined_event_count"], 4)
        self.assertEqual(batch["valid_event_count"], 3)
        self.assertEqual(batch["corrupt_event_count"], 1)
        self.assertEqual(batch["affected_item_ids"], [self.item["id"]])

        live_events = self.service.audit("viewer")
        self.assertEqual(len(live_events), 1)
        for key, value in untouched.items():
            if key == "detail":
                continue
            self.assertEqual(live_events[0][key], value)
        self.assertEqual(live_events[0]["detail"], json.loads(untouched["detail"]))

        with self.assertRaises(PermissionDenied):
            self.service.confirm_repair_batch("RB-001", "duty", "duty_officer")
        batch = self.service.confirm_repair_batch("RB-001", "chief", "chief_engineer")
        self.assertEqual(batch["status"], "open")
        with self.assertRaises(ConflictError):
            self.service.apply_repair_batch({"batch_no": "RB-001"}, "duty", "duty_officer")
        batch = self.service.confirm_repair_batch(
            "RB-001", "inspector", "discipline_inspector"
        )
        self.assertEqual(batch["status"], "ready")

        with self.assertRaises(ConflictError):
            self.service.transition(
                self.item["id"], STATES[-1], self.item["version"], "chief",
                TRANSITION_ROLES[STATES[-1]][0],
            )

        batch = self.service.apply_repair_batch(
            {"batch_no": "RB-001"}, "duty", "duty_officer"
        )
        self.assertEqual(batch["status"], "applied")
        self.assertEqual(batch["reconnected_event_count"], 3)
        self.assertTrue(self.repo.verify_audit_chain())

        events = self.service.audit("viewer")
        self.assertEqual(events[1]["action"], "repair_begin")
        self.assertEqual(events[1]["previous_hash"], batch["last_valid_hash"])
        self.assertEqual(events[1]["detail"]["continued_from_hash"], batch["last_valid_hash"])
        self.assertEqual(events[1]["detail"]["live_tail_hash"], batch["last_valid_hash"])
        self.assertEqual(events[-1]["action"], "repair_complete")

        original_transition = next(
            event for event in batch["quarantined_events"]
            if event["original_id"] == corrupt_id
        )
        self.assertFalse(original_transition["self_valid"])
        self.assertIsNone(original_transition["reconnected_event_id"])
        self.assertIsNone(original_transition["reconnected_event_id"])
        first_reconnected = batch["quarantined_events"][1]
        reconnected = self.repo.get_repair_batch_by_no("RB-001")["quarantined_events"][1]
        self.assertEqual(events[2]["id"], reconnected["reconnected_event_id"])
        self.assertEqual(events[2]["action"], first_reconnected["action"])
        self.assertEqual(events[2]["detail"], first_reconnected["detail"])
        self.assertEqual(events[2]["created_at"], first_reconnected["created_at"])

        current = self.service.get_item(self.item["id"], "viewer")
        closed = self.service.transition(
            current["id"], STATES[-1], current["version"], "chief",
            TRANSITION_ROLES[STATES[-1]][0],
        )
        self.assertEqual(closed["status"], "closed")

    def test_normal_operations_continue_during_repair_and_close_block_is_scoped(self):
        self._corrupt_second_audit_event()
        batch = self.service.start_repair_batch(
            {"batch_no": "RB-002"}, "duty", "duty_officer"
        )

        normal_record = self.service.add_record(self.item["id"], {
            "kind": "field_note", "detail": "non-close work continues",
            "status": "closed", "external_ref": "REPAIR-1-NOTE",
        }, "dispatcher", "dispatcher")
        self.assertEqual(normal_record["status"], "closed")

        other = self._complete_to_executed("REPAIR-2", "unaffected item")
        other = self.service.transition(
            other["id"], STATES[-1], other["version"], "chief",
            TRANSITION_ROLES[STATES[-1]][0],
        )
        self.assertEqual(other["status"], "closed")

        self.service.confirm_repair_batch("RB-002", "chief", "chief_engineer")
        self.service.confirm_repair_batch("RB-002", "inspector", "discipline_inspector")
        batch = self.service.apply_repair_batch(
            {"batch_no": "RB-002"}, "duty", "duty_officer"
        )
        self.assertTrue(self.repo.verify_audit_chain())
        begin = next(event for event in self.service.audit("viewer")
                     if event["action"] == "repair_begin")
        self.assertEqual(
            begin["detail"]["continued_from_hash"], batch["last_valid_hash"]
        )
        self.assertEqual(begin["previous_hash"], begin["detail"]["live_tail_hash"])
        self.assertNotEqual(
            begin["detail"]["continued_from_hash"], begin["detail"]["live_tail_hash"]
        )

    def test_failed_write_can_retry_by_batch_number(self):
        self._corrupt_second_audit_event()
        self.service.start_repair_batch({"batch_no": "RB-003"}, "duty", "duty_officer")
        self.service.confirm_repair_batch("RB-003", "chief", "chief_engineer")
        self.service.confirm_repair_batch("RB-003", "inspector", "discipline_inspector")

        with mock.patch.object(
            Repository, "_insert_audit_event", side_effect=RuntimeError("write failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "write failed"):
                self.service.apply_repair_batch(
                    {"batch_no": "RB-003"}, "duty", "duty_officer"
                )

        self.assertTrue(self.repo.verify_audit_chain())
        retry = self.repo.get_repair_batch_by_no("RB-003")
        self.assertEqual(retry["status"], "ready")
        applied = self.service.apply_repair_batch(
            {"batch_no": "RB-003"}, "duty", "duty_officer"
        )
        self.assertEqual(applied["status"], "applied")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_same_batch_first_commit_wins_and_second_sees_gap(self):
        self._corrupt_second_audit_event()
        self.service.start_repair_batch({"batch_no": "RB-004"}, "duty", "duty_officer")
        self.service.confirm_repair_batch("RB-004", "chief", "chief_engineer")
        self.service.confirm_repair_batch("RB-004", "inspector", "discipline_inspector")

        entered = threading.Event()
        release = threading.Event()
        original_insert = Repository._insert_audit_event

        def first_insert(self, event):
            if event["action"] == "repair_begin":
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("timeout waiting to release repair write")
            return original_insert(self, event)

        results = []

        def apply(label):
            try:
                result = self.service.apply_repair_batch(
                    {"batch_no": "RB-004"}, label, "duty_officer"
                )
                results.append(("ok", result["status"]))
            except Exception as exc:
                results.append((type(exc).__name__, str(exc)))

        with mock.patch.object(Repository, "_insert_audit_event", first_insert):
            first = threading.Thread(target=apply, args=("first",))
            second = threading.Thread(target=apply, args=("second",))
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            release.set()
            first.join(2)
            second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertIn(("ok", "applied"), results)
        self.assertIn(("RepairBatchGapConflict", mock.ANY), results)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_repair_requires_breakpoint_and_duplicate_batch_is_conflict(self):
        with self.assertRaises(ValidationError):
            self.service.start_repair_batch({"batch_no": "RB-X"}, "duty", "duty_officer")
        self._corrupt_second_audit_event()
        self.service.start_repair_batch({"batch_no": "RB-005"}, "duty", "duty_officer")
        with self.assertRaises(ConflictError):
            self.service.start_repair_batch({"batch_no": "RB-005"}, "duty", "duty_officer")


class RepairHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "http.db"))
        self.service = Service(self.repo)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.service, str(Path(__file__).parents[1] / "static")),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.repo.close()
        self.tmp.cleanup()

    def request(self, method, path, payload=None, actor="actor", role="duty_officer"):
        data = None
        headers = {"X-Actor": actor, "X-Role": role}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_repair_batch_routes_and_duplicate_gap_response(self):
        item = self.service.create_item({
            "title": "http repair", "description": "http", "severity": "routine",
        }, "creator", "duty_officer")
        with self.repo._lock, self.repo.conn:
            row = self.repo.conn.execute(
                "SELECT * FROM audit_events ORDER BY id"
            ).fetchall()[-1]
            detail = json.loads(row["detail"])
            detail["tampered"] = True
            self.repo.conn.execute(
                "UPDATE audit_events SET detail=? WHERE id=?",
                (json.dumps(detail), row["id"]),
            )

        status, batch = self.request("POST", "/api/repair-batches", {"batch_no": "HTTP-1"})
        self.assertEqual(status, 201)
        self.assertEqual(batch["status"], "open")
        self.assertEqual(batch["affected_item_ids"], [item["id"]])

        status, body = self.request(
            "POST", "/api/repair-batches/HTTP-1/confirm", role="chief_engineer",
            actor="chief"
        )
        self.assertEqual((status, body["status"]), (200, "open"))
        status, body = self.request(
            "POST", "/api/repair-batches/HTTP-1/confirm", role="discipline_inspector",
            actor="inspector"
        )
        self.assertEqual((status, body["status"]), (200, "ready"))
        status, body = self.request(
            "POST", "/api/repair-batches/HTTP-1/apply", role="duty_officer"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "applied")
        status, body = self.request(
            "POST", "/api/repair-batches/HTTP-1/apply", role="duty_officer"
        )
        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "repair_batch_gap")

        status, body = self.request(
            "GET", "/api/repair-batches/HTTP-1", role="discipline_inspector"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["batch_no"], "HTTP-1")


if __name__ == "__main__":
    unittest.main()
