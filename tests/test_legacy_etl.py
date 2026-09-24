"""Legacy fixtures exercise cross-ledger links, audit stubs, and source integrity."""

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from connectd.legacy_etl import LegacySources, migrate_legacy
from connectd.store import Store


def make_source(path: Path, schema: str, rows: list[tuple[str, tuple]]):
    with sqlite3.connect(path) as db:
        db.executescript(schema)
        for statement, values in rows:
            db.execute(statement, values)


class LegacyEtlTests(unittest.TestCase):
    def test_selective_import_keeps_sources_and_expires_grants(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            agent, gov, tools, brain = (root / name for name in ("agent.db", "gov.db", "tools.db", "brain.db"))
            make_source(agent,
                "CREATE TABLE tasks(id TEXT,title TEXT,goal TEXT,status TEXT,metadata_json TEXT,created_at REAL);"
                "CREATE TABLE subtasks(id TEXT,parent_task_id TEXT,title TEXT,instructions TEXT,status TEXT);"
                "CREATE TABLE execution_records(task_id TEXT,work_request_id TEXT);",
                [("INSERT INTO tasks VALUES (?,?,?,?,?,?)", ("task-a", "Old task", "Goal", "completed",
                   '{"privacy_class":"repo_sensitive"}', 100.0)),
                 ("INSERT INTO subtasks VALUES (?,?,?,?,?)", ("step-a", "task-a", "Review", "Review files", "done")),
                 ("INSERT INTO execution_records VALUES (?,?)", ("task-a", "wr-linked"))])
            make_source(gov,
                "CREATE TABLE decision_records(id TEXT,work_request_id TEXT,outcome TEXT,request_json TEXT,evaluated_at TEXT);"
                "CREATE TABLE execution_grant_records(id TEXT,decision_record_id TEXT,grant_json TEXT,issued_at TEXT,not_after TEXT);",
                [("INSERT INTO decision_records VALUES (?,?,?,?,?)", ("d-linked", "wr-linked", "Allowed",
                   '{"tool_id":"old-tool"}', "2024-01-01T00:00:00+00:00")),
                 ("INSERT INTO decision_records VALUES (?,?,?,?,?)", ("d-orphan", "wr-orphan", "Denied",
                   '{"tool_id":"old-tool"}', "2024-01-01T00:00:00+00:00")),
                 ("INSERT INTO execution_grant_records VALUES (?,?,?,?,?)", ("g-linked", "d-linked", "{}",
                   "2024-01-01T00:00:00+00:00", "2024-01-01T00:01:00+00:00"))])
            body = '{"name":"old-tool","outcome":"success"}'
            at = "2024-01-01T00:00:10+00:00"
            genesis = "0" * 64
            digest = hashlib.sha256(f"outcome\x1f{body}\x1f{at}\x1f{genesis}".encode()).hexdigest()
            make_source(tools,
                "CREATE TABLE audit(seq INTEGER,kind TEXT,body TEXT,created_at TEXT,prev_hash TEXT,record_hash TEXT);"
                "CREATE TABLE meta(key TEXT,value TEXT);",
                [("INSERT INTO audit VALUES (?,?,?,?,?,?)", (1, "outcome", body, at, genesis, digest)),
                 ("INSERT INTO meta VALUES (?,?)", ("audit_head_seq", "1")),
                 ("INSERT INTO meta VALUES (?,?)", ("audit_head_hash", digest))])
            make_source(brain,
                "CREATE TABLE sources(id INTEGER,hash TEXT,path TEXT,url TEXT);"
                "CREATE TABLE claims(id INTEGER,text TEXT,source_id INTEGER,status TEXT,promoted_by TEXT,origin TEXT,scope_type TEXT,scope_id TEXT,created_at TEXT);",
                [("INSERT INTO sources VALUES (?,?,?,?)", (1, "abc", "source.md", None)),
                 ("INSERT INTO claims VALUES (?,?,?,?,?,?,?,?,?)", (1, "trusted", 1, "promoted",
                   "human", "human", "repo", "old", at)),
                 ("INSERT INTO claims VALUES (?,?,?,?,?,?,?,?,?)", (2, "pending", 1, "pending",
                   None, "agent", "repo", "old", at))])
            sources = LegacySources(agent, gov, tools, brain)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (agent, gov, tools, brain)}
            store = Store(root / "unified.db")
            counts = migrate_legacy(store, sources, missing_privacy_class="secret_sensitive",
                                    retain_audit_payload=False)
            self.assertEqual(counts["tasks"], 1)
            self.assertEqual(counts["audit_stubs"], 2)  # unmatched work request and unlinked tool outcome
            self.assertEqual(counts["memory_claims"], 1)
            self.assertEqual(before, {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in before})
            with store.connect() as db:
                self.assertEqual(db.execute("SELECT status FROM governance_grants").fetchone()[0], "legacy_expired")
                self.assertEqual(db.execute("SELECT body_json,prev_hash,record_hash FROM legacy_tool_audit").fetchone()[0], None)
                self.assertEqual(db.execute("SELECT count(*) FROM memory_claims").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT count(*) FROM tasks WHERE status='legacy_audit_stub'").fetchone()[0], 2)
            store.dispose()


if __name__ == "__main__":
    unittest.main()
