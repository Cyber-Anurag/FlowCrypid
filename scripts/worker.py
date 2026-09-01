"""FlowCrypid external analysis worker for single-node or multi-process deployments."""

from __future__ import annotations

import logging
import os
import time

from apps.api.main import claim_next_job, process_analysis_job

logging.basicConfig(level=os.getenv("FLOWCRYPID_LOG_LEVEL", "INFO"), format="%(message)s")
logger = logging.getLogger("flowcrypid.worker")
POLL_SECONDS = float(os.getenv("FLOWCRYPID_WORKER_POLL_SECONDS", "1.0"))


def main() -> None:
    logger.info("FlowCrypid external worker started")
    while True:
        job = claim_next_job()
        if not job:
            time.sleep(POLL_SECONDS)
            continue
        job_id, user_id, stored_path, filename, size_bytes = job
        process_analysis_job(job_id, user_id, stored_path, filename, size_bytes)


if __name__ == "__main__":
    main()
