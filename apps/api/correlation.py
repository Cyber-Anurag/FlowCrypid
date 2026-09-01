"""Deterministic, explainable correlation over normalized FlowCrypid telemetry."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _time(event: dict[str, Any]) -> datetime:
    value = event.get("observed_at")
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else datetime.min


def correlate_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate compatible events in one tenant/source window into explainable chains."""
    ordered = sorted(events, key=_time)
    results: list[dict[str, Any]] = []
    by_source: dict[str, list[dict[str, Any]]] = {}
    for event in ordered:
        by_source.setdefault(str(event.get("source_ip") or event.get("asset_id") or "unknown"), []).append(event)

    for source, source_events in by_source.items():
        flows = [e for e in source_events if e.get("event_type") == "network_flow"]
        dns = [e for e in source_events if e.get("event_type") == "dns"]
        files = [e for e in source_events if e.get("event_type") == "file_access"]
        destinations = {e.get("destination_ip") for e in flows if e.get("destination_ip")}
        outbound = sum(int(e.get("bytes_out") or 0) for e in flows)
        high_sensitive = [e for e in files if e.get("sensitivity") in {"high", "critical"}]
        external_flows = [e for e in flows if e.get("destination_ip") and not str(e.get("destination_ip")).startswith(("10.", "192.168.", "172.16."))]

        def add(chain_id: str, title: str, signals: list[str], evidence: list[str], confidence: float) -> None:
            results.append({"source": source, "chain_id": chain_id, "title": title, "signals": signals, "evidence": evidence, "confidence": confidence, "event_count": len(source_events)})

        if dns and external_flows and min(_time(e) for e in external_flows) >= min(_time(e) for e in dns):
            add("CHAIN-DNS-HTTPS", "DNS discovery followed by external transfer", ["DNS_DISCOVERY", "EXTERNAL_TRANSFER"], [f"{len(dns)} DNS event(s)", f"{len(external_flows)} external flow(s)"], 0.72)
        if high_sensitive and external_flows and min(_time(e) for e in external_flows) >= min(_time(e) for e in high_sensitive):
            add("CHAIN-SENSITIVE-EXFIL", "Sensitive access followed by external transfer", ["SENSITIVE_ACCESS", "EXTERNAL_TRANSFER"], [f"{len(high_sensitive)} high-sensitivity file event(s)", f"{outbound:,} outbound bytes"], 0.78)
        if len(destinations) >= 3 and outbound >= 1_000_000:
            add("CHAIN-DESTINATION-ROTATION", "Multi-destination outbound transfer", ["DESTINATION_ROTATION", "HIGH_OUTBOUND_VOLUME"], [f"{len(destinations)} destinations", f"{outbound:,} outbound bytes"], 0.76)
        if len(source_events) >= 2 and _time(source_events[-1]) - _time(source_events[0]).replace(tzinfo=_time(source_events[0]).tzinfo) > __import__("datetime").timedelta(hours=6):
            add("CHAIN-LONG-IDLE", "Activity separated by a long idle period", ["LONG_IDLE_RESUMPTION"], [f"{len(source_events)} events spanning more than six hours"], 0.55)
    return results
