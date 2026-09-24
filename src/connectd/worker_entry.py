"""JSON stdin/stdout entry point for one ephemeral worker run."""

import sys
from pathlib import Path

from connectd.launcher import WorkerInput
from connectd.worker import DirectWorker, HttpCapabilityClient
from connectd.workbench import LocalWorkbench


def main() -> None:
    payload = WorkerInput.model_validate_json(sys.stdin.read())
    capability = (LocalWorkbench(Path.cwd(), payload.ticket.authority.local)
                  if payload.tool["function"]["name"] == "workbench"
                  else HttpCapabilityClient(payload.control_plane_url, payload.worker_token, payload.task_id))
    worker = DirectWorker(payload.model_base_url, payload.model_id, capability,
                          model_auth_token=payload.worker_token if payload.model_api_auth else None,
                          max_output_tokens=payload.max_output_tokens)
    report = worker.run(payload.ticket, payload.worker_id, payload.tool, payload.max_turns)
    sys.stdout.write(report.model_dump_json())


if __name__ == "__main__":
    main()
