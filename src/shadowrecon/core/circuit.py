"""Host-level circuit breaker to isolate unresponsive or failing endpoints."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("shadowrecon.core.circuit")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # Normal: all requests allowed
    OPEN = "OPEN"            # Tripped: host unresponsive; requests fast-failed
    HALF_OPEN = "HALF_OPEN"  # Testing canary probe after recovery timeout


@dataclass
class HostCircuit:
    host: str
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    last_state_change: float = 0.0
    total_failures: int = 0
    total_successes: int = 0
    trip_reason: str = ""

    def __post_init__(self) -> None:
        if not self.last_state_change:
            self.last_state_change = time.time()


class HostCircuitBreaker:
    """Monitors per-host responsiveness and fast-fails requests to dead hosts.

    Prevents stages from hanging for tens of minutes on unresponsive hosts
    experiencing repeated 504 Gateway Timeouts, TCP resets, or dropped connections.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        enabled: bool = True,
    ) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.01, recovery_timeout)
        self.enabled = enabled
        self._circuits: Dict[str, HostCircuit] = {}

    def extract_host(self, url_or_host: str) -> str:
        """Extract canonical lowercased host from a URL or bare hostname."""
        val = str(url_or_host).strip().lower()
        if "://" in val:
            parsed = urlparse(val)
            return parsed.netloc or parsed.path.split("/")[0]
        # Bare hostname or host:port
        return val.split("/")[0]

    def _get_or_create(self, host: str) -> HostCircuit:
        if host not in self._circuits:
            self._circuits[host] = HostCircuit(host=host)
        return self._circuits[host]

    def allow_request(self, url_or_host: str) -> bool:
        """Check if request to host is permitted by circuit breaker."""
        if not self.enabled:
            return True

        host = self.extract_host(url_or_host)
        if not host:
            return True

        circuit = self._get_or_create(host)
        now = time.time()

        if circuit.state == CircuitState.CLOSED:
            return True

        if circuit.state == CircuitState.OPEN:
            elapsed = now - circuit.last_state_change
            if elapsed >= self.recovery_timeout:
                circuit.state = CircuitState.HALF_OPEN
                circuit.last_state_change = now
                log.info(
                    "Circuit for '%s' transitioned to HALF_OPEN (cool-down of %.1fs expired; testing probe)",
                    host,
                    self.recovery_timeout,
                )
                return True
            # Fast-fail
            return False

        if circuit.state == CircuitState.HALF_OPEN:
            # During half-open, allow single canary probe
            return True

        return True

    def record_success(self, url_or_host: str) -> None:
        """Record a successful response from host, resetting circuit state."""
        if not self.enabled:
            return

        host = self.extract_host(url_or_host)
        if not host:
            return

        circuit = self._get_or_create(host)
        circuit.total_successes += 1
        circuit.consecutive_failures = 0

        if circuit.state != CircuitState.CLOSED:
            log.info("Host '%s' recovered. Resetting circuit to CLOSED.", host)
            circuit.state = CircuitState.CLOSED
            circuit.last_state_change = time.time()
            circuit.trip_reason = ""

    def record_failure(self, url_or_host: str, error_reason: str = "") -> None:
        """Record a failure (timeout, connection reset, 5xx), tripping circuit if threshold reached."""
        if not self.enabled:
            return

        host = self.extract_host(url_or_host)
        if not host:
            return

        circuit = self._get_or_create(host)
        now = time.time()
        circuit.total_failures += 1
        circuit.consecutive_failures += 1
        circuit.last_failure_time = now

        if circuit.state == CircuitState.HALF_OPEN:
            # Canary probe failed, immediately trip back to OPEN
            circuit.state = CircuitState.OPEN
            circuit.last_state_change = now
            circuit.trip_reason = f"Canary probe failed: {error_reason or 'unresponsive'}"
            log.warning("Canary probe for '%s' failed. Re-tripping circuit to OPEN.", host)
            return

        if circuit.state == CircuitState.CLOSED and circuit.consecutive_failures >= self.failure_threshold:
            circuit.state = CircuitState.OPEN
            circuit.last_state_change = now
            circuit.trip_reason = error_reason or f"{self.failure_threshold} consecutive timeouts/failures"
            log.warning(
                "Circuit TRIPPED to OPEN for '%s' (%d consecutive failures: %s). Subsequent requests will fast-fail.",
                host,
                circuit.consecutive_failures,
                circuit.trip_reason,
            )

    def filter_healthy_urls(self, urls: Iterable[str]) -> List[str]:
        """Filter out URLs targeting hosts with OPEN circuits."""
        if not self.enabled:
            return list(urls)
        return [u for u in urls if self.allow_request(u)]

    def filter_healthy_hosts(self, hosts: Iterable[str]) -> List[str]:
        """Filter out hostnames with OPEN circuits."""
        if not self.enabled:
            return list(hosts)
        return [h for h in hosts if self.allow_request(h)]

    def get_open_circuits(self) -> List[str]:
        """List all currently tripped hosts."""
        return [h for h, c in self._circuits.items() if c.state == CircuitState.OPEN]

    def reset(self, url_or_host: Optional[str] = None) -> None:
        """Reset state for a specific host or all tracked circuits."""
        if url_or_host:
            host = self.extract_host(url_or_host)
            if host in self._circuits:
                del self._circuits[host]
        else:
            self._circuits.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate health statistics across all monitored hosts."""
        total = len(self._circuits)
        open_c = len([c for c in self._circuits.values() if c.state == CircuitState.OPEN])
        half_open = len([c for c in self._circuits.values() if c.state == CircuitState.HALF_OPEN])
        closed = len([c for c in self._circuits.values() if c.state == CircuitState.CLOSED])

        return {
            "monitored_hosts": total,
            "healthy_hosts": closed,
            "tripped_hosts": open_c,
            "probing_hosts": half_open,
            "tripped_list": self.get_open_circuits(),
        }
