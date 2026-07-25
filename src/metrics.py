"""MX2 Production Prometheus Telemetry Engine.

Tracks API requests, HPKE translation events, Proof-of-Work verifications,
and quarantine queue metrics for Prometheus scraping endpoints.
"""

import threading


class MX2MetricsEngine:
    """Thread-safe telemetry metrics counter and exporter for MX2 Daemons."""

    def __init__(self) -> None:
        """Initializes atomic metric counters with thread locks."""
        self._lock = threading.Lock()
        self.api_requests_total = 0
        self.e2ee_translations_total = 0
        self.pow_verified_total = 0
        self.decrypted_messages_total = 0

    def inc_api_requests(self) -> None:
        """Increments total API connections count."""
        with self._lock:
            self.api_requests_total += 1

    def inc_translations(self) -> None:
        """Increments envelope translations count."""
        with self._lock:
            self.e2ee_translations_total += 1

    def inc_pow_verified(self) -> None:
        """Increments verified Proof-of-Work challenges count."""
        with self._lock:
            self.pow_verified_total += 1

    def inc_decrypted(self) -> None:
        """Increments successful HPKE payload decrypts count."""
        with self._lock:
            self.decrypted_messages_total += 1

    def export_prometheus_metrics(self, quarantine_count: int = 0) -> str:
        """Exports Prometheus 0.0.4 formatted text output string."""
        with self._lock:
            lines = [
                "# HELP mx2_api_requests_total Total HTTP API calls resolved.",
                "# TYPE mx2_api_requests_total counter",
                f"mx2_api_requests_total {self.api_requests_total}",
                "",
                "# HELP mx2_e2ee_translations_total Total legacy emails translated to MX2 envelopes.",
                "# TYPE mx2_e2ee_translations_total counter",
                f"mx2_e2ee_translations_total {self.e2ee_translations_total}",
                "",
                "# HELP mx2_pow_verified_total Total Proof-of-Work challenges verified.",
                "# TYPE mx2_pow_verified_total counter",
                f"mx2_pow_verified_total {self.pow_verified_total}",
                "",
                "# HELP mx2_decrypted_messages_total Total HPKE payloads successfully decrypted.",
                "# TYPE mx2_decrypted_messages_total counter",
                f"mx2_decrypted_messages_total {self.decrypted_messages_total}",
                "",
                "# HELP mx2_quarantine_count Current number of emails held in quarantine.",
                "# TYPE mx2_quarantine_count gauge",
                f"mx2_quarantine_count {quarantine_count}",
            ]
            return "\n".join(lines)
