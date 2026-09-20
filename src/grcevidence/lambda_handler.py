"""AWS Lambda entry point.

Configuration comes from the ``GRC_CONFIG`` environment variable (JSON, same schema as the
YAML config file). The scheduled event may override it with ``{"config": {...}}`` or run a
subset with ``{"collectors": ["aws.cloudtrail"], "dry_run": true}``. ``dry_run`` collects
but writes nothing.

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
