"""Daemon, database migration, and signing-key commands."""

import argparse
import os
from pathlib import Path

from alembic import command
from alembic.config import Config as AlembicConfig
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from connectd.config import load_config
from connectd.store import Store


def upgrade_database(database_url: str) -> None:
    config = AlembicConfig()
    config.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    command.upgrade(config, "head")


def initialize_signing_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
    if os.name != "nt":
        path.chmod(0o600)


def load_signing_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    return key


def operator_token(config, parser: argparse.ArgumentParser) -> str:
    token = os.environ.get(config.daemon.operator_token_env)
    token_file = os.environ.get(f"{config.daemon.operator_token_env}_FILE")
    if token and token_file:
        parser.error("operator token and operator token file cannot both be set")
    if token_file:
        token = Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        parser.error(f"{config.daemon.operator_token_env} or its _FILE variant must be set")
    return token


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="connectd")
    parser.add_argument("--config", default="config/connectd.yaml")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    commands.add_parser("model-proxy")
    key_command = commands.add_parser("init-key")
    key_command.add_argument("--path", type=Path)
    worker = commands.add_parser("worker")
    worker.add_argument("action", choices=["run-step"])
    worker.add_argument("--task-id", required=True)
    worker.add_argument("--step-id", required=True)
    worker.add_argument("--worktree", required=True, type=Path)
    worker.add_argument("--tool", default="auto")
    worker.add_argument("--control-plane-url", default="http://127.0.0.1:8790")
    database = commands.add_parser("db")
    database.add_argument("action", choices=["upgrade", "migrate-legacy"])
    database.add_argument("--agentconnect-db", type=Path)
    database.add_argument("--governance-db", type=Path)
    database.add_argument("--toolconnect-db", type=Path)
    database.add_argument("--brainconnect-db", type=Path)
    database.add_argument("--missing-privacy-class", choices=["public", "low_sensitive",
                                                           "repo_sensitive", "secret_sensitive"])
    database.add_argument("--audit-payload", choices=["full", "hash-only"])
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.command == "init-key":
        key_path = args.path or config.daemon.signing_key_path
        if key_path is None:
            parser.error("daemon.signing_key_path must be configured")
        initialize_signing_key(key_path)
        print(f"created {key_path}")
        return
    if args.command == "db":
        upgrade_database(config.daemon.database_url)
        if args.action == "migrate-legacy":
            from connectd.legacy_etl import LegacySources, migrate_legacy

            required = (args.agentconnect_db, args.governance_db, args.toolconnect_db,
                        args.brainconnect_db, args.missing_privacy_class,
                        args.audit_payload)
            if any(value is None for value in required):
                parser.error("migrate-legacy requires four source DBs and explicit privacy and audit-payload choices")
            counts = migrate_legacy(Store(config.daemon.database_url),
                                    LegacySources(args.agentconnect_db, args.governance_db,
                                                  args.toolconnect_db, args.brainconnect_db),
                                    missing_privacy_class=args.missing_privacy_class,
                                    retain_audit_payload=args.audit_payload == "full")
            print(counts)
        return
    if args.command == "worker":
        from connectd.dispatch import StepDispatcher

        report = StepDispatcher(config, args.control_plane_url, operator_token(config, parser)).run_step(
            args.task_id, args.step_id, args.worktree, args.tool)
        print(report.model_dump_json())
        return
    if args.command == "model-proxy":
        from connectd.model_proxy import create_model_proxy
        import uvicorn

        store = Store(config.daemon.database_url)
        app = create_model_proxy(config, store, operator_token(config, parser))
        uvicorn.run(app, host="0.0.0.0", port=config.model_api.port)
        return
    if config.daemon.signing_key_path is None:
        parser.error("daemon.signing_key_path must be configured")
    token = operator_token(config, parser)
    upgrade_database(config.daemon.database_url)
    from connectd.api import create_app
    import uvicorn

    store = Store(config.daemon.database_url)
    app = create_app(config, store, load_signing_key(config.daemon.signing_key_path), token)
    from threading import Event, Thread
    from connectd.node_monitor import NodeMonitor

    stopped = Event()
    monitor = Thread(target=NodeMonitor(store, managers=config.compute.node_managers).run_until,
                     args=(stopped, config.compute.health_interval_seconds), daemon=True)
    monitor.start()
    try:
        uvicorn.run(app, host=config.daemon.host, port=config.daemon.port)
    finally:
        stopped.set()
        monitor.join(timeout=5)


if __name__ == "__main__":
    main()
