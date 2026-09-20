"""AWS Lambda entry point.

Configuration comes from the ``GRC_CONFIG`` environment variable (JSON, same schema as the
YAML config file). An invocation may run a subset with
``{"collectors": ["aws.cloudtrail"], "dry_run": true}``; ``dry_run`` collects but writes
nothing.

An event may NOT replace the configuration (``{"config": {...}}``) unless the function is
deployed with ``GRC_ALLOW_EVENT_CONFIG=true``. The configuration decides which accounts are
assumed, which secrets are resolved and where evidence is sent, and the function's role can
read those secrets and assume those roles. Letting any caller who holds ``lambda:InvokeFunction``
supply it would let them point an HTTP sink at their own endpoint with
``auth.token: secretsmanager:<a secret this role can read>`` and walk away with the secret.

If any sink fails the handler raises after attempting all sinks, so Lambda's Errors metric
(and the alarm in the Terraform module) fires rather than a silent gap in evidence.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from grcevidence.runner import Config, ConfigError, build_sinks, deliver, run

log = logging.getLogger()
log.setLevel(logging.INFO)


def handler(event: dict[str, Any] | None, context: Any = None) -> dict[str, Any]:
    event = event or {}
    if event.get("config") and os.environ.get("GRC_ALLOW_EVENT_CONFIG", "").lower() != "true":
        raise ConfigError(
            "this invocation supplied its own config, which is disabled by default; "
            "change GRC_CONFIG on the function (or set GRC_ALLOW_EVENT_CONFIG=true if you "
            "accept that anyone able to invoke it controls where evidence and secrets go)"
        )
    raw = event.get("config") or json.loads(os.environ.get("GRC_CONFIG", "{}"))
    config = Config.from_dict(raw)
    if event.get("collectors"):
        config.include = list(event["collectors"])
    sinks = [] if event.get("dry_run") else build_sinks(config.sinks)
    if not sinks and not event.get("dry_run"):
        raise ConfigError(
            "no sinks configured; refusing to collect evidence that would be discarded"
        )

    result = deliver(run(config), sinks)
    summary = {
        "run_id": result.manifest.run_id,
        "accounts": result.manifest.accounts,
        "counts": result.manifest.counts,
        "sinks": result.sink_results,
        "dry_run": bool(event.get("dry_run")),
    }
    log.info(json.dumps(summary))
    if result.failed_sinks:
        raise RuntimeError(f"evidence delivery failed: {result.failed_sinks}")
    return summary
