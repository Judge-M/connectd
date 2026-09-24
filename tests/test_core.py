import json
import unittest
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectd.compute import PlacementDenied, PrivacyClass, place
from connectd.auth import AuthService, AuthenticationError
from connectd.api import create_app
from connectd.config import ConnectdConfig, load_config
from connectd.governance import AuthorizationError, Governance, utcnow
from connectd.memory import MemoryLedger
from connectd.model import RoutingDecision, TypedDecisionRouter
from connectd.policy import CedarPolicy
from connectd.router import RouteError, one_tool_schema, traverse
from connectd.store import Store
from connectd.task import LeaseError, TaskManager
from connectd.worker import DirectWorker, Ticket
from connectd.launcher import SecurityBoundaryViolation, WorkerLauncher, select_runtime
from connectd.workbench import LocalWorkbench
from connectd.worker import LocalAuthority, WorkerError
from connectd.dispatch import DispatchError, StepDispatcher, validate_proxy_url
from connectd.worker import WorkerReport
from connectd.model_proxy import create_model_proxy


PAID_TOKENIZER = {"kind": "tiktoken", "encoding": "cl100k_base",
                  "message_overhead_tokens": 4, "tool_overhead_tokens": 8,
                  "safety_margin_tokens": 100}


class CoreTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).parents[1] / "work"
        scratch.mkdir(exist_ok=True)
        self.db_path = scratch / f"test-{uuid.uuid4()}.db"
        self.store = Store(self.db_path)
        self.store.initialize()
        with self.store.connect() as db:
            db.execute("""INSERT INTO tasks(task_id,title,privacy_class,memory_scope,created_at)
                VALUES (?,?,?,?,?)""", ("task-1", "Demo", "public", "repo:test", utcnow().isoformat()))
            for tool, tier in (("git_status", 0), ("worktree_patch", 1), ("cloud_deploy", 2)):
                db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,active)
                    VALUES (?,?,?,?,?,?)""",
                           (tool, tool, "code", "{}", tier, True))

    def tearDown(self):
        self.store.dispose()
        self.db_path.unlink(missing_ok=True)

    def test_profile_switch_and_default(self):
        config = ConnectdConfig()
        self.assertEqual(config.profile().grant_mode.value, "risk_tiered")
        self.assertEqual(config.profile("dev_fast").grant_mode.value, "auto_grant")
        self.assertEqual(config.profile("prod_secure").grant_mode.value, "strict_ed25519")
        with self.assertRaises(ValueError):
            ConnectdConfig(default_execution_profile="missing")
        loaded = load_config(Path(__file__).parents[1] / "config" / "connectd.yaml")
        self.assertEqual(loaded.profile("prod_secure").worker_runtime.value, "docker")

    def test_signed_grant_is_single_use_and_argument_bound(self):
        governance = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile("prod_secure"))
        grant = governance.issue("task-1", "worker-1", "worktree_patch", {"path": "a.py", "text": "ok"})
        with self.assertRaises(AuthorizationError):
            governance.redeem(grant, "task-1", "worker-1", "worktree_patch", {"path": "a.py", "text": "changed"})
        forged = dict(grant, expires_at="2099-01-01T00:00:00+00:00")
        with self.assertRaises(AuthorizationError):
            governance.redeem(forged, "task-1", "worker-1", "worktree_patch", {"path": "a.py", "text": "ok"})
        governance.redeem(grant, "task-1", "worker-1", "worktree_patch", {"path": "a.py", "text": "ok"})
        with self.assertRaises(AuthorizationError):
            governance.redeem(grant, "task-1", "worker-1", "worktree_patch", {"path": "a.py", "text": "ok"})

    def test_high_risk_respects_profile(self):
        governance = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile("balanced"))
        with self.assertRaises(AuthorizationError):
            governance.issue("task-1", "worker-1", "cloud_deploy", {})
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT result FROM governance_decisions").fetchone()[0], "deny")
        fast = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile("dev_fast"))
        self.assertEqual(fast.issue("task-1", "worker-1", "cloud_deploy", {})["tool_id"], "cloud_deploy")

    def test_task_finishes_only_after_all_steps(self):
        manager = TaskManager(self.store)
        first = manager.add_step("task-1", "First")
        second = manager.add_step("task-1", "Second")
        manager.complete(manager.claim(first, "worker-1"), "done")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM tasks WHERE task_id='task-1'").fetchone()[0],
                             "active")
        manager.finish(manager.claim(second, "worker-2"), "failed", "failed")
        with self.store.connect() as db:
            row = db.execute("SELECT status,is_terminal FROM tasks WHERE task_id='task-1'").fetchone()
            self.assertEqual((row["status"], bool(row["is_terminal"])), ("failed", True))

    def test_balanced_cedar_and_prod_operator_approval(self):
        policy = CedarPolicy('permit(principal, action == Action::"invoke", resource == Tool::"cloud_deploy");')
        balanced = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile("balanced"), policy.permit)
        self.assertEqual(balanced.issue("task-1", "worker-1", "cloud_deploy", {"target": "dev"})["tool_id"], "cloud_deploy")
        prod = Governance(self.store, Ed25519PrivateKey.generate(), ConnectdConfig().profile("prod_secure"), policy.permit)
        with self.assertRaises(AuthorizationError):
            prod.issue("task-1", "worker-1", "cloud_deploy", {"target": "dev"})
        prod.approve("task-1", "worker-1", "cloud_deploy", {"target": "dev"}, "human-1")
        with self.assertRaises(AuthorizationError):
            prod.issue("task-1", "worker-1", "cloud_deploy", {"target": "prod"})
        prod.issue("task-1", "worker-1", "cloud_deploy", {"target": "dev"})
        with self.assertRaises(AuthorizationError):
            prod.issue("task-1", "worker-1", "cloud_deploy", {"target": "dev"})

    def test_financial_gate_applies_to_dev_fast_and_tracks_budget(self):
        with self.store.connect() as db:
            db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,effect_tier,active,
                is_financial,cost_per_invocation_cents) VALUES (?,?,?,?,?,?,?,?)""",
                ("paid_call", "Paid call", "cloud", "{}", 2, True, True, 75))
        governance = Governance(self.store, Ed25519PrivateKey.generate(),
                                ConnectdConfig().profile("dev_fast"))
        with self.assertRaises(AuthorizationError):
            governance.issue("task-1", "worker-1", "paid_call", {"request": "one"})
        with self.store.connect() as db:
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,approved_by,created_at)
                VALUES (?,?,?,?,?,?)""", (str(uuid.uuid4()), "task-1", "daily", 100,
                                             "operator", utcnow().isoformat()))
        governance.issue("task-1", "worker-1", "paid_call", {"request": "one"})
        with self.assertRaises(AuthorizationError):
            governance.issue("task-1", "worker-1", "paid_call", {"request": "two"})
        governance.approve("task-1", "worker-1", "paid_call", {"request": "two"}, "operator")
        governance.issue("task-1", "worker-1", "paid_call", {"request": "two"})
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT SUM(amount_cents) FROM quota_records").fetchone()[0], 150)

    def test_cedar_matched_annotation_requires_approval(self):
        policy = CedarPolicy('''
            @require_human_approval("true")
            permit(principal, action == Action::"invoke", resource == Tool::"cloud_deploy");
            permit(principal, action == Action::"invoke", resource == Tool::"git_status");
        ''')
        self.assertTrue(policy.evaluate("task-1", "worker-1", "cloud_deploy", {}).require_human_approval)
        self.assertFalse(policy.evaluate("task-1", "worker-1", "git_status", {}).require_human_approval)

    def test_memory_stays_quarantined_until_promotion(self):
        memory = MemoryLedger(self.store)
        claim = memory.capture("repo:test", "Use SQLite", "worker-1")
        self.assertEqual(memory.recall("repo:test"), [])
        memory.promote(claim, "human-1")
        self.assertEqual(memory.recall("repo:test"), ["Use SQLite"])
        self.assertEqual(memory.recall("repo:other"), [])
        other = memory.capture("repo:test", "Use Postgres", "worker-2")
        memory.promote(other, "human-1")
        with self.store.connect() as db:
            db.execute("INSERT INTO claim_contradictions VALUES (?,?,?,?,?)",
                       (str(uuid.uuid4()), claim, other, "open", None))
        self.assertEqual(memory.recall("repo:test"), [])

    def test_privacy_gate(self):
        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,airgapped)
                VALUES (?,?,?,?,?)""", ("cloud", "api", "external", True, False))
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,airgapped)
                VALUES (?,?,?,?,?)""", ("local", "llama", "local_only", True, True))
        self.assertEqual(place(self.store, PrivacyClass.PUBLIC), "local")
        self.assertEqual(place(self.store, PrivacyClass.REPO_SENSITIVE), "local")
        self.assertEqual(place(self.store, PrivacyClass.SECRET_SENSITIVE), "local")
        with self.store.connect() as db:
            db.execute("UPDATE compute_nodes SET healthy=FALSE WHERE node_id='local'")
        with self.assertRaises(PlacementDenied):
            place(self.store, PrivacyClass.SECRET_SENSITIVE)
        self.assertEqual(place(self.store, PrivacyClass.SECRET_SENSITIVE, frozenset({"cloud"})), "cloud")

    def test_bounded_router_and_one_schema(self):
        tree = json.loads((Path(__file__).parents[1] / "config" / "oag_tree_registry.json").read_text())["trees"]["tool_routing"]
        route = traverse(tree, lambda node, options: {"domain": "code", "code_action": "inspect"}[node])
        self.assertEqual(len(route.hops), 2)
        self.assertEqual(one_tool_schema(route, {"workbench": {"name": "workbench"}}), {"name": "workbench"})
        with self.assertRaises(RouteError):
            traverse(tree, lambda _node, _options: "invented")

    def test_task_step_lease_is_single_claimer(self):
        manager = TaskManager(self.store)
        step = manager.add_step("task-1", "Inspect code")
        lease = manager.claim(step, "worker-1")
        with self.assertRaises(LeaseError):
            manager.claim(step, "worker-2")
        manager.complete(lease, "Inspected")
        with self.assertRaises(LeaseError):
            manager.complete(lease, "Repeated")

    def test_typed_router_rejects_invalid_choice(self):
        import httpx

        def respond(request):
            body = json.loads(request.content)
            self.assertEqual(body["questions"]["domain"]["criteria"], {"read": "Read"})
            return httpx.Response(200, json={"answers": {
                "domain": {"choice": "write", "confidence": 0.9},
                "detail": {"choice": "file", "confidence": 0.9}}})

        client = httpx.Client(transport=httpx.MockTransport(respond))
        chooser = TypedDecisionRouter("laya", "http://127.0.0.1:8000", 0.85, client=client)
        tree = {"root_node": "domain", "nodes": {"domain": {"hop": 1, "options": [
            {"id": "read", "label": "Read", "next_node": "detail"}]},
            "detail": {"hop": 2, "options": [{"id": "file", "label": "File", "next_node": "LEAF_RESOLVED",
                                               "resolved_tool_id": "workbench"}]}}}
        with self.assertRaises(RouteError):
            chooser.route(tree, "Read the file")

    def test_worker_token_cannot_act_as_operator(self):
        auth = AuthService(self.store, "o" * 40)
        worker = auth.issue_worker("task-1", "worker-1")
        self.assertEqual(auth.require_worker(worker, "task-1").worker_id, "worker-1")
        with self.assertRaises(AuthenticationError):
            auth.require_worker(worker, "another-task")
        with self.assertRaises(AuthenticationError):
            auth.require_operator(worker)
        auth.revoke_worker(worker)
        with self.assertRaises(AuthenticationError):
            auth.require_worker(worker)

    def test_api_separates_worker_and_operator(self):
        from fastapi.testclient import TestClient

        app = create_app(ConnectdConfig(), self.store, Ed25519PrivateKey.generate(), "o" * 40)
        client = TestClient(app)
        self.assertEqual(client.post("/api/v1/tasks", json={"title": "New", "privacy_class": "public", "memory_scope": "repo:test"}).status_code, 401)
        operator = {"Authorization": "Bearer " + "o" * 40}
        created = client.post("/api/v1/tasks", headers=operator, json={"title": "New", "privacy_class": "public", "memory_scope": "repo:test"})
        self.assertEqual(created.status_code, 201)
        task_id = created.json()["task_id"]
        token = client.post(f"/api/v1/tasks/{task_id}/worker-sessions", headers=operator, json={"worker_id": "agent"}).json()["token"]
        worker = {"Authorization": "Bearer " + token}
        captured = client.post(f"/api/v1/tasks/{task_id}/memory/capture", headers=worker, json={"claim_text": "Verified fact"})
        self.assertEqual(captured.status_code, 201)
        claim_id = captured.json()["claim_id"]
        self.assertEqual(client.post(f"/api/v1/memory/claims/{claim_id}/promote", headers=worker).status_code, 403)
        self.assertEqual(client.get(f"/api/v1/tasks/{task_id}/context-pack", headers=worker).json()["memory"], [])
        self.assertEqual(client.post(f"/api/v1/memory/claims/{claim_id}/promote", headers=operator).status_code, 200)
        self.assertEqual(client.get(f"/api/v1/tasks/{task_id}/context-pack", headers=worker).json()["memory"], ["Verified fact"])

    def test_task_profile_is_pinned_for_grant_policy(self):
        config = ConnectdConfig(worker_model={"base_url": "http://127.0.0.1:8080", "model_id": "fake"})
        governance = Governance(self.store, Ed25519PrivateKey.generate(), config.profile(),
                                profiles=config.execution_profiles)
        with self.store.connect() as db:
            db.execute("UPDATE tasks SET execution_profile='dev_fast' WHERE task_id='task-1'")
        self.assertEqual(governance.issue("task-1", "worker-1", "cloud_deploy", {})["tool_id"],
                         "cloud_deploy")
        with self.store.connect() as db:
            db.execute("UPDATE tasks SET execution_profile='prod_secure' WHERE task_id='task-1'")
        with self.assertRaises(AuthorizationError):
            governance.issue("task-1", "worker-1", "cloud_deploy", {})

    def test_direct_worker_has_one_tool_and_bounded_turns(self):
        import httpx

        seen = []
        calls = []

        def respond(request):
            payload = json.loads(request.content)
            self.assertEqual(len(payload["tools"]), 1)
            self.assertEqual(payload["max_tokens"], 1000)
            seen.append(payload)
            if len(seen) == 1:
                return httpx.Response(200, json={"choices": [{"message": {"content": None, "tool_calls": [{
                    "id": "call-1", "type": "function", "function": {"name": "echo", "arguments": '{"text":"hi"}'}}
                ]}}]})
            return httpx.Response(200, json={"choices": [{"message": {"content": "Done"}}]})

        ticket_id, conversation_id, worker_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        ticket = Ticket(id=ticket_id, conversation_id=conversation_id, objective="Echo hi",
                        deliverable="Summary", authority={"external_capabilities": ["echo"]})
        worker = DirectWorker("http://127.0.0.1:8080", "local", lambda name, args: calls.append((name, args)) or {"ok": True},
                              httpx.Client(transport=httpx.MockTransport(respond)), max_output_tokens=1000)
        report = worker.run(ticket, worker_id, {"type": "function", "function": {
            "name": "echo", "description": "Echo", "parameters": {"type": "object"}}})
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.summary, "Done")
        self.assertEqual(calls, [("echo", {"text": "hi"})])

    def test_worker_runtime_isolation_by_profile_and_tier(self):
        profiles = ConnectdConfig()
        self.assertEqual(select_runtime(profiles.profile("dev_fast"), 2).value, "subprocess")
        self.assertEqual(select_runtime(profiles.profile("balanced"), 2).value, "docker")
        self.assertEqual(select_runtime(profiles.profile("prod_secure"), 1).value, "docker")

    def test_container_service_urls_obey_profile_network(self):
        self.assertEqual(
            WorkerLauncher._container_url("http://127.0.0.1:8080", False, "model-api"),
            "http://host.docker.internal:8080",
        )
        self.assertEqual(
            WorkerLauncher._container_url("http://model-api:8090", True, "model-api"),
            "http://model-api:8090",
        )
        with self.assertRaises(SecurityBoundaryViolation):
            WorkerLauncher._container_url("http://host.docker.internal:8080", True, "model-api")
        with self.assertRaises(SecurityBoundaryViolation):
            WorkerLauncher._container_url("http://example.com", True, "model-api")

    def test_workbench_stays_inside_worktree_and_honors_authority(self):
        root = Path(__file__).parents[1] / "work" / ("workspace-" + uuid.uuid4().hex)
        root.mkdir()
        try:
            workbench = LocalWorkbench(root, LocalAuthority(read_workspace=True,
                                                              write_workspace=True,
                                                              execute_local=False))
            workbench("workbench", {"action": "write", "path": "note.txt", "content": "hello"})
            self.assertEqual(workbench("workbench", {"action": "read", "path": "note.txt"}),
                             {"content": "hello"})
            with self.assertRaises(WorkerError):
                workbench("workbench", {"action": "read", "path": "../outside"})
            with self.assertRaises(WorkerError):
                workbench("workbench", {"action": "run", "argv": ["python", "-V"]})
        finally:
            (root / "note.txt").unlink(missing_ok=True)
            root.rmdir()

    def test_dispatch_claims_runs_and_completes_step(self):
        from fastapi.testclient import TestClient

        config = ConnectdConfig(worker_model={"base_url": "http://127.0.0.1:8080", "model_id": "fake"})
        operator_token = "o" * 40
        client = TestClient(create_app(config, self.store, Ed25519PrivateKey.generate(),
                                       operator_token), base_url="http://127.0.0.1:8790")
        auth = {"Authorization": "Bearer " + operator_token}
        task_id = client.post("/api/v1/tasks", headers=auth, json={
            "title": "Dispatch", "privacy_class": "public", "memory_scope": "repo:test"}).json()["task_id"]
        step_id = client.post(f"/api/v1/tasks/{task_id}/steps", headers=auth,
                              json={"instruction": "Read a file"}).json()["step_id"]
        client.post("/api/v1/compute/nodes", headers=auth, json={
            "node_id": "local", "provider_type": "llama", "privacy_tier": "local_only",
            "airgapped": True, "billing_mode": "free", "endpoint_url": "http://127.0.0.1:8080",
            "model_id": "fake"})

        class FakeLauncher:
            def run(self, payload, worktree, profile, effect_tier, timeout_seconds):
                self.payload = payload
                self.effect_tier = effect_tier
                return WorkerReport(worker_id=payload.worker_id, ticket_id=payload.ticket.id,
                                    conversation_id=payload.ticket.conversation_id,
                                    status="completed", summary="Read complete")

        launcher = FakeLauncher()
        dispatcher = StepDispatcher(config, "http://127.0.0.1:8790", operator_token,
                                    client=client, launcher=launcher)
        report = dispatcher.run_step(task_id, step_id, Path(__file__).parents[1] / "work", "workbench")
        self.assertEqual(report.status, "completed")
        self.assertEqual(launcher.payload.ticket.objective, "Read a file")
        self.assertEqual(launcher.effect_tier, 1)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM task_steps WHERE step_id=?",
                                        (step_id,)).fetchone()[0], "done")
            self.assertEqual(db.execute("SELECT status,is_terminal FROM tasks WHERE task_id=?",
                                        (task_id,)).fetchone()["status"], "completed")

    def test_dispatch_uses_system_one_route_by_default(self):
        from fastapi.testclient import TestClient

        class FakeRouter:
            def __init__(self, *_args, **_kwargs):
                pass

            def route(self, tree, objective):
                self_test.assertEqual(objective, "Inspect a file")
                choices = {"domain": "code", "code_action": "inspect"}
                route = traverse(tree, lambda node, _options: choices[node])
                return RoutingDecision(route, 12.0, "laya", {hop.node_id: .99 for hop in route.hops})

        self_test = self
        config = ConnectdConfig(router={"min_confidence": 0.85},
                                worker_model={"base_url": "http://127.0.0.1:8080", "model_id": "fake"})
        token = "o" * 40
        client = TestClient(create_app(config, self.store, Ed25519PrivateKey.generate(), token,
                                       decision_router=FakeRouter), base_url="http://127.0.0.1:8790")
        operator = {"Authorization": "Bearer " + token}
        task_id = client.post("/api/v1/tasks", headers=operator, json={"title": "Inspect",
            "privacy_class": "public", "memory_scope": "repo:test"}).json()["task_id"]
        step_id = client.post(f"/api/v1/tasks/{task_id}/steps", headers=operator,
                              json={"instruction": "Inspect a file"}).json()["step_id"]
        client.post("/api/v1/compute/nodes", headers=operator, json={"node_id": "local",
            "provider_type": "vllm", "privacy_tier": "local_only", "airgapped": True,
            "billing_mode": "free", "endpoint_url": "http://127.0.0.1:8080", "model_id": "fake"})

        class FakeLauncher:
            def run(self, payload, _worktree, _profile, _effect_tier, _timeout):
                self_test.assertEqual(payload.tool["function"]["name"], "workbench")
                return WorkerReport(worker_id=payload.worker_id, ticket_id=payload.ticket.id,
                    conversation_id=payload.ticket.conversation_id, status="completed", summary="Done")

        StepDispatcher(config, "http://127.0.0.1:8790", token, client=client,
                       launcher=FakeLauncher()).run_step(task_id, step_id,
                                                          Path(__file__).parents[1] / "work")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT resolved_tool_id FROM routing_decisions").fetchone()[0],
                             "workbench")

    def test_paid_model_cannot_bypass_proxy_with_direct_url(self):
        from fastapi.testclient import TestClient

        config = ConnectdConfig(worker_model={"base_url": "http://127.0.0.1:8080",
                                               "model_id": "paid-model", "uses_proxy": False})
        token = "o" * 40
        client = TestClient(create_app(config, self.store, Ed25519PrivateKey.generate(), token),
                            base_url="http://127.0.0.1:8790")
        operator = {"Authorization": "Bearer " + token}
        task_id = client.post("/api/v1/tasks", headers=operator, json={
            "title": "Paid", "privacy_class": "public", "memory_scope": "repo:test"}).json()["task_id"]
        step_id = client.post(f"/api/v1/tasks/{task_id}/steps", headers=operator,
                              json={"instruction": "Analyze"}).json()["step_id"]
        registered = client.post("/api/v1/compute/nodes", headers=operator, json={
            "node_id": "paid-local", "provider_type": "metered", "privacy_tier": "local_only",
            "billing_mode": "paid", "endpoint_url": "http://127.0.0.1:8080",
            "model_id": "paid-model", "tokenizer": PAID_TOKENIZER,
            "pricing": {"input_rate_per_1k_tokens": "0.10",
                "output_rate_per_1k_tokens": "0.20", "max_total_tokens": 1000,
                "max_cost_per_request": "0.20"}})
        self.assertEqual(registered.status_code, 201, registered.text)
        with self.assertRaises(DispatchError):
            StepDispatcher(config, "http://127.0.0.1:8790", token, client=client).run_step(
                task_id, step_id, Path(__file__).parents[1] / "work", "workbench")

        class FakeLauncher:
            def run(self, payload, _worktree, _profile, _effect_tier, _timeout):
                self_test.assertEqual(payload.max_output_tokens, 1000)
                self_test.assertTrue(payload.model_api_auth)
                return WorkerReport(worker_id=payload.worker_id, ticket_id=payload.ticket.id,
                    conversation_id=payload.ticket.conversation_id, status="completed", summary="Done")

        self_test = self
        proxied = ConnectdConfig(worker_model={"base_url": "http://127.0.0.1:8090",
                                               "model_id": "paid-model", "uses_proxy": True})
        report = StepDispatcher(proxied, "http://127.0.0.1:8790", token,
                                client=client, launcher=FakeLauncher()).run_step(
            task_id, step_id, Path(__file__).parents[1] / "work", "workbench")
        self.assertEqual(report.status, "completed")

    def test_proxy_url_cannot_expose_worker_token_to_external_host(self):
        validate_proxy_url("http://127.0.0.1:8090", 8090)
        validate_proxy_url("http://model-api:8090", 8090)
        for url in ("https://external.example:8090", "http://model-engine:8090",
                    "http://127.0.0.1:8091", "http://127.0.0.1:8090/other"):
            with self.assertRaises(DispatchError):
                validate_proxy_url(url, 8090)

    def test_model_proxy_authenticates_worker_and_strips_bearer(self):
        import httpx
        from fastapi.testclient import TestClient

        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,airgapped,
                endpoint_url,model_id) VALUES (?,?,?,?,?,?,?)""",
                ("local-model", "vllm", "local_only", True, True,
                 "http://model-engine:8090", "capable-model"))
        token = AuthService(self.store, "o" * 40).issue_worker("task-1", "worker-1")

        def respond(request):
            self.assertEqual(str(request.url), "http://model-engine:8090/v1/chat/completions")
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        app = create_model_proxy(ConnectdConfig(), self.store, "o" * 40,
                                 client_factory=lambda _tls: httpx.Client(
                                     transport=httpx.MockTransport(respond)))
        client = TestClient(app)
        payload = {"model": "capable-model", "messages": [{"role": "user", "content": "hello"}]}
        self.assertEqual(client.post("/v1/chat/completions", json=payload).status_code, 401)
        result = client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + token},
                             json=payload)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["choices"][0]["message"]["content"], "ok")

    def test_paid_model_proxy_reserves_and_reconciles_budget(self):
        import httpx
        from fastapi.testclient import TestClient

        pricing = {"input_rate_per_1k_tokens": "0.10",
                   "output_rate_per_1k_tokens": "0.20",
                   "max_total_tokens": 1000, "max_cost_per_request": "0.20"}
        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                airgapped,billing_mode,endpoint_url,model_id,pricing_model,tokenizer_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("paid-model", "vllm", "local_only", True, False, "paid",
                 "http://model-engine:8090", "capable-model", json.dumps(pricing),
                 json.dumps(PAID_TOKENIZER)))
        worker_token = AuthService(self.store, "o" * 40).issue_worker("task-1", "worker-1")
        calls = []

        def respond(request):
            calls.append(request)
            return httpx.Response(200, json={"choices": [],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50}})

        app = create_model_proxy(ConnectdConfig(), self.store, "o" * 40,
            client_factory=lambda _tls: httpx.Client(transport=httpx.MockTransport(respond)))
        client = TestClient(app)
        payload = {"model": "capable-model", "max_tokens": 100,
                   "messages": [{"role": "user", "content": "hello"}]}
        headers = {"Authorization": "Bearer " + worker_token}
        self.assertEqual(client.post("/v1/chat/completions", headers=headers,
                                     json=payload).status_code, 403)
        self.assertEqual(calls, [])
        with self.store.connect() as db:
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,
                approved_by,created_at) VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), "task-1", "daily", 100, "operator", utcnow().isoformat()))
        response = client.post("/v1/chat/completions", headers=headers, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        with self.store.connect() as db:
            record = db.execute("SELECT amount_cents,reserved_cents,status,actual_units FROM quota_records").fetchone()
        self.assertEqual((record["amount_cents"], record["status"], record["actual_units"]),
                         (2, "settled", 150))
        self.assertLess(record["reserved_cents"], 20)

    def test_worker_turn_uses_paid_proxy_and_settles_quota(self):
        import httpx
        from fastapi.testclient import TestClient

        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                airgapped,billing_mode,endpoint_url,model_id,pricing_model,tokenizer_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("paid-loop", "vllm", "local_only", True, False, "paid",
                 "http://model-engine:8090", "capable-model", json.dumps({
                     "input_rate_per_1k_tokens": "0.10",
                     "output_rate_per_1k_tokens": "0.20",
                     "max_total_tokens": 1000, "max_cost_per_request": "0.20"}),
                 json.dumps(PAID_TOKENIZER)))
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,
                approved_by,created_at) VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), "task-1", "daily", 100, "operator", utcnow().isoformat()))

        def respond(request):
            self.assertLess(json.loads(request.content)["max_tokens"], 1000)
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, json={"choices": [{"message": {"content": "Done"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50}})

        proxy = create_model_proxy(ConnectdConfig(), self.store, "o" * 40,
            client_factory=lambda _tls: httpx.Client(transport=httpx.MockTransport(respond)))
        proxy_client = TestClient(proxy, base_url="http://proxy")
        worker_token = AuthService(self.store, "o" * 40).issue_worker("task-1", "worker-1")
        worker = DirectWorker("http://proxy", "capable-model", lambda *_: {}, proxy_client,
                              model_auth_token=worker_token, max_output_tokens=1000)
        ticket = Ticket(id=uuid.uuid4(), conversation_id=uuid.uuid4(), objective="Summarize",
                        deliverable="Summary", authority={})
        report = worker.run(ticket, uuid.uuid4(), {"type": "function", "function": {
            "name": "workbench", "description": "Local work", "parameters": {"type": "object"}}})
        self.assertEqual(report.summary, "Done")
        with self.store.connect() as db:
            row = db.execute("SELECT amount_cents,status FROM quota_records").fetchone()
        self.assertEqual((row["amount_cents"], row["status"]), (2, "settled"))

    def test_paid_model_cap_clamps_output_and_blocks_large_prompt(self):
        import httpx
        from fastapi.testclient import TestClient

        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                airgapped,billing_mode,endpoint_url,model_id,pricing_model,tokenizer_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("capped", "vllm", "local_only", True, False, "paid",
                 "http://model-engine:8090", "capable-model", json.dumps({
                     "input_rate_per_1k_tokens": "0.10",
                     "output_rate_per_1k_tokens": "1.00",
                     "max_total_tokens": 1000, "max_cost_per_request": "0.05"}),
                 json.dumps(PAID_TOKENIZER)))
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,
                approved_by,created_at) VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), "task-1", "daily", 100, "operator", utcnow().isoformat()))
        upstream = []

        def respond(request):
            upstream.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [], "usage": {
                "prompt_tokens": 100, "completion_tokens": 10}})

        app = create_model_proxy(ConnectdConfig(), self.store, "o" * 40,
            client_factory=lambda _tls: httpx.Client(transport=httpx.MockTransport(respond)))
        client = TestClient(app)
        token = AuthService(self.store, "o" * 40).issue_worker("task-1", "worker-1")
        headers = {"Authorization": "Bearer " + token}
        payload = {"model": "capable-model", "messages": [{"role": "user", "content": "hello"}],
                   "max_tokens": 900}
        result = client.post("/v1/chat/completions", headers=headers, json=payload)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertLess(upstream[0]["max_tokens"], 900)
        self.assertLessEqual(upstream[0]["max_tokens"], 40)
        oversized = dict(payload, messages=[{"role": "user", "content": "word " * 2000}])
        result = client.post("/v1/chat/completions", headers=headers, json=oversized)
        self.assertEqual(result.status_code, 422)
        self.assertEqual(len(upstream), 1)

    def test_paid_model_quarantines_node_when_usage_exceeds_bound(self):
        import httpx
        from fastapi.testclient import TestClient

        with self.store.connect() as db:
            db.execute("""INSERT INTO compute_nodes(node_id,provider_type,privacy_tier,healthy,
                airgapped,billing_mode,endpoint_url,model_id,pricing_model,tokenizer_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                ("miscounted", "vllm", "local_only", True, False, "paid",
                 "http://model-engine:8090", "capable-model", json.dumps({
                     "input_rate_per_1k_tokens": "0.10",
                     "output_rate_per_1k_tokens": "0.20",
                     "max_total_tokens": 1000, "max_cost_per_request": "0.20"}),
                 json.dumps(PAID_TOKENIZER)))
            db.execute("""INSERT INTO quota_budgets(budget_id,task_id,period,amount_cents,
                approved_by,created_at) VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), "task-1", "daily", 100, "operator", utcnow().isoformat()))

        def respond(_request):
            return httpx.Response(200, json={"choices": [], "usage": {
                "prompt_tokens": 999, "completion_tokens": 1}})

        client = TestClient(create_model_proxy(ConnectdConfig(), self.store, "o" * 40,
            client_factory=lambda _tls: httpx.Client(transport=httpx.MockTransport(respond))))
        token = AuthService(self.store, "o" * 40).issue_worker("task-1", "worker-1")
        response = client.post("/v1/chat/completions",
            headers={"Authorization": "Bearer " + token}, json={"model": "capable-model",
            "messages": [{"role": "user", "content": "hello"}], "max_tokens": 100})
        self.assertEqual(response.status_code, 502)
        with self.store.connect() as db:
            self.assertFalse(db.execute("SELECT healthy FROM compute_nodes WHERE node_id='miscounted'").fetchone()[0])
            self.assertEqual(db.execute("SELECT status FROM quota_records").fetchone()[0], "reserved")

    def test_legacy_aliases_require_task_and_default_private(self):
        from fastapi.testclient import TestClient

        operator_token = "o" * 40
        client = TestClient(create_app(ConnectdConfig(), self.store,
                                      Ed25519PrivateKey.generate(), operator_token,
                                      tool_handlers={"git_status": lambda args: {"ok": True},
                                                     "legacy-bound": lambda args: {"ok": True}}))
        operator = {"Authorization": "Bearer " + operator_token}
        task_id = client.post("/tasks", headers=operator,
                              json={"title": "Legacy task"}).json()["task_id"]
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT privacy_class FROM tasks WHERE task_id=?",
                                        (task_id,)).fetchone()[0], "repo_sensitive")
        token = AuthService(self.store, operator_token).issue_worker(task_id, "worker-1")
        worker = {"Authorization": "Bearer " + token}
        response = client.post("/authorize", headers=worker,
                               json={"tool_id": "git_status", "args": {}})
        self.assertEqual(response.status_code, 400)
        response = client.post("/authorize", headers=worker,
                               json={"tool_id": "git_status", "args": {},
                                     "context": {"task_id": task_id}})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertTrue(response.json()["execution"]["gateway_required"])
        self.assertEqual(client.post("/decisions/legacy-decision/outcome", headers=worker,
                                     json={"outcome": "success"}).status_code, 409)
        with self.store.connect() as db:
            db.execute("""INSERT INTO tool_registry(tool_id,name,domain_path,schema_json,
                effect_tier,active) VALUES (?,?,?,?,?,TRUE)""",
                ("legacy-bound", "legacy_read", "legacy/service", "{}", 0))
        response = client.post("/authorize", headers=worker, json={
            "source_id": "service", "name": "legacy_read", "context": {"task_id": task_id}})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["grant"]["tool_id"], "legacy-bound")

    def test_registry_does_not_activate_unbound_handler(self):
        from fastapi.testclient import TestClient

        operator_token = "o" * 40
        client = TestClient(create_app(ConnectdConfig(), self.store,
                                      Ed25519PrivateKey.generate(), operator_token))
        headers = {"Authorization": "Bearer " + operator_token}
        registered = client.post("/api/v1/tools", headers=headers, json={
            "tool_id": "unbound", "name": "Unbound", "domain_path": "test",
            "schema": {"type": "object"}, "effect_tier": 2})
        self.assertEqual(registered.status_code, 201, registered.text)
        self.assertEqual(registered.json()["status"], "disabled_unbound")
        self.assertEqual(client.post("/api/v1/tools/unbound/activate", headers=headers).status_code, 409)
        tools = client.get("/api/v1/tools", headers=headers).json()
        self.assertEqual(next(row for row in tools if row["tool_id"] == "unbound")["status"],
                         "disabled_unbound")

    def test_local_node_cannot_name_external_inference_host(self):
        from fastapi.testclient import TestClient

        token = "o" * 40
        client = TestClient(create_app(ConnectdConfig(), self.store,
                                      Ed25519PrivateKey.generate(), token))
        response = client.post("/api/v1/compute/nodes",
                               headers={"Authorization": "Bearer " + token},
                               json={"node_id": "false-local", "provider_type": "remote",
                                     "privacy_tier": "local_only", "airgapped": True,
                                     "billing_mode": "free", "model_id": "capable",
                                     "endpoint_url": "http://public.example:8090"})
        self.assertEqual(response.status_code, 422)
        zero_rate = client.post("/api/v1/compute/nodes",
            headers={"Authorization": "Bearer " + token},
            json={"node_id": "zero-price", "provider_type": "metered",
                  "privacy_tier": "local_only", "billing_mode": "paid",
                  "endpoint_url": "http://127.0.0.1:8090", "model_id": "capable",
                  "pricing": {"input_rate_per_1k_tokens": 0,
                              "output_rate_per_1k_tokens": 0,
                              "max_total_tokens": 1000,
                              "max_cost_per_request": "0.10"}})
        self.assertEqual(zero_rate.status_code, 422)


if __name__ == "__main__":
    unittest.main()
