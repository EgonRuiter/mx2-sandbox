"""MX2 Structured JSON Logging Utility.

Generates machine-readable log lines formatted as JSON objects, outputting
to both stdout and a persistent log file.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

# Global variable to store active log file path
_log_file_path: Optional[str] = None


def setup_logger(log_file: str) -> None:
    """Configures the destination path for log files.

    Args:
        log_file (str): Absolute or relative path to log file.
    """
    global _log_file_path
    _log_file_path = log_file
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)


def log_event(level: str, component: str, message: str, details: Optional[dict[str, Any]] = None) -> None:
    """Logs a structured JSON event to stdout and the configured log file.

    Args:
        level (str): Log level (INFO, WARNING, ERROR, DEBUG).
        component (str): System component identifier (e.g. SMTP-Proxy, Daemon, Gateway).
        message (str): Log message.
        details (dict): Optional key-value diagnostics data.
    """
    global _log_file_path

    log_line = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "level": level.upper().strip(),
        "component": component.strip(),
        "message": message.strip()
    }
    if details:
        log_line["details"] = details

    serialized_line = json.dumps(log_line)

    # Print to stdout
    print(serialized_line, flush=True)

    # Write to log file if configured
    if _log_file_path:
        try:
            with open(_log_file_path, "a") as f:
                f.write(serialized_line + "\n")
        except OSError:
            pass
