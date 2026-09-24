"""Memory recall retains authority metadata without widening worker trust."""

import tempfile
import unittest
from pathlib import Path

from connectd.memory import MemoryLedger
from connectd.store import Store


class MemoryTests(unittest.TestCase):
    def test_provenance_validity_and_contradiction_filter(self):
        with tempfile.TemporaryDirectory() as scratch:
            store = Store(Path(scratch) / "memory.db")
            store.initialize()
            ledger = MemoryLedger(store)
            first = ledger.capture("repo:connectd", "Primary claim", "operator",
                confidence=0.92, confidence_label="high", valid_until="2099-01-01T00:00:00Z",
                tags=["architecture"], sources=[{"source_id": "src-1", "source_uri": "notes.md",
                    "source_hash": "abc", "origin": "document", "title": "Notes"}])
            other = ledger.capture("repo:connectd", "Conflicting claim", "operator")
            ledger.promote(first, "human-1")
            ledger.promote(other, "human-1")
            records = ledger.recall_records("repo:connectd")
            selected = next(item for item in records if item["id"] == first)
            self.assertEqual(selected["confidence"], "high")
            self.assertEqual(selected["confidence_score"], 0.92)
            self.assertEqual(selected["validity"], "current")
            self.assertEqual(selected["sources"][0]["title"], "Notes")
            self.assertEqual(selected["tags"], ["architecture"])
            with store.connect() as db:
                db.execute("""INSERT INTO claim_contradictions(contradiction_id,existing_claim_id,
                    new_claim_id,status) VALUES (?,?,?,'open')""", ("conflict-1", first, other))
            self.assertEqual(ledger.recall("repo:connectd"), [])
            flagged = ledger.recall_records("repo:connectd", trusted_only=False)
            self.assertEqual(len(flagged), 2)
            self.assertFalse(flagged[0]["trusted"])
            self.assertEqual(flagged[0]["contradiction_warnings"][0]["contradiction_id"], "conflict-1")
            store.dispose()
