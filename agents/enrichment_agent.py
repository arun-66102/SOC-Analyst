"""Phase 3 Member 1: VirusTotal + AbuseIPDB threat-intelligence enrichment."""
from __future__ import annotations

import asyncio
import os
import re
import time
from typing import Any

import httpx

from agents.base_agent import BaseAgent
from api.models import AgentResult, EnrichmentOutput, NormalizedEvent

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
VT_INTERVAL_SECONDS = 15.0  # 4 requests/minute public limit
HTTP_TIMEOUT = 15.0
MAX_INDICATORS = 5


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


class EnrichmentAgent(BaseAgent):
    """Enrich IP/domain/hash indicators with VirusTotal and AbuseIPDB."""

    def __init__(self) -> None:
        super().__init__(agent_name="EnrichmentAgent", version="1.0.0")
        self.vt_key = _env("VIRUSTOTAL_API_KEY")
        self.abuse_key = _env("ABUSEIPDB_API_KEY")
        self._vt_lock = asyncio.Lock()
        self._last_vt_request = 0.0

    def _check_dependencies(self) -> dict[str, Any]:
        # Missing TI keys are not a fatal pipeline dependency: the agent can
        # still return a structured result explaining that enrichment is unavailable.
        return {
            "healthy": True,
            "virustotal_configured": bool(self.vt_key),
            "abuseipdb_configured": bool(self.abuse_key),
        }

    def process(self, event: NormalizedEvent) -> AgentResult:
        # BaseAgent is synchronous. This method is used by non-async callers.
        return asyncio.run(self.process_async(event))

    async def process_async(self, event: NormalizedEvent) -> AgentResult:
        indicators = self._extract_indicators(event)
        results: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            for indicator in indicators:
                value = indicator["value"]
                kind = indicator["type"]
                vt = await self._query_virustotal(client, kind, value) if self.vt_key else {
                    "configured": False
                }
                abuse = await self._query_abuseipdb(client, value) if kind == "ip" and self.abuse_key else {
                    "configured": bool(self.abuse_key) if kind == "ip" else False,
                    "skipped": kind != "ip",
                }
                results.append({
                    "type": kind,
                    "value": value,
                    "virustotal": vt,
                    "abuseipdb": abuse,
                })

        malicious = any(
            bool(r.get("virustotal", {}).get("is_malicious"))
            or bool(r.get("abuseipdb", {}).get("is_malicious"))
            for r in results
        )
        labels = sorted({
            label
            for r in results
            for label in r.get("virustotal", {}).get("threat_labels", [])
        })
        vt_scores = [
            r["virustotal"].get("score") for r in results
            if r.get("virustotal", {}).get("score")
        ]
        abuse_scores = [
            r["abuseipdb"].get("abuse_confidence_score") for r in results
            if isinstance(r.get("abuseipdb", {}).get("abuse_confidence_score"), int)
        ]
        confidence = self._confidence(results, malicious)

        output = EnrichmentOutput(
            ip_address=next((r["value"] for r in results if r["type"] == "ip"), None),
            is_malicious=malicious,
            threat_labels=labels,
            virustotal_score=vt_scores[0] if vt_scores else None,
            abuseipdb_score=max(abuse_scores) if abuse_scores else None,
            confidence=confidence,
            sources=self._sources(results),
            indicators=results,
        )
        return AgentResult(
            event_id=event.event_id,
            status="success",
            confidence=confidence,
            reasoning=(
                f"Checked {len(results)} indicator(s). "
                + ("At least one indicator was flagged malicious." if malicious
                   else "No queried indicator was confirmed malicious by available sources.")
            ),
            output=output.model_dump(),
        )

    def _extract_indicators(self, event: NormalizedEvent) -> list[dict[str, str]]:
        found: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(kind: str, value: Any) -> None:
            if value is None:
                return
            value = str(value).strip()
            if not value or len(value) > 512:
                return
            key = (kind, value.lower())
            if key not in seen:
                seen.add(key)
                found.append({"type": kind, "value": value})

        add("ip", event.src_ip)
        add("ip", event.dst_ip)

        # Look through raw payload for common indicator field names.
        key_patterns = {
            "domain": re.compile(r"^(domain|hostname|host|fqdn)$", re.I),
            "hash": re.compile(r"^(md5|sha1|sha256|file_hash|hash)$", re.I),
            "ip": re.compile(r"^(ip|src_ip|dst_ip|source_ip|destination_ip)$", re.I),
        }
        payload = event.raw_payload or {}
        for key, value in payload.items():
            kind = next((k for k, p in key_patterns.items() if p.match(str(key))), None)
            if kind:
                if isinstance(value, (list, tuple)):
                    for item in value:
                        add(kind, item)
                else:
                    add(kind, value)
            if len(found) >= MAX_INDICATORS:
                break
        return found[:MAX_INDICATORS]

    async def _rate_limit_vt(self) -> None:
        async with self._vt_lock:
            wait = VT_INTERVAL_SECONDS - (time.monotonic() - self._last_vt_request)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_vt_request = time.monotonic()

    async def _query_virustotal(self, client: httpx.AsyncClient, kind: str, value: str) -> dict[str, Any]:
        endpoint_kind = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}.get(kind)
        if not endpoint_kind:
            return {"error": "unsupported_indicator_type"}
        await self._rate_limit_vt()
        try:
            response = await client.get(
                f"{VT_BASE}/{endpoint_kind}/{value}",
                headers={"x-apikey": self.vt_key, "Accept": "application/json"},
            )
            if response.status_code == 404:
                return {"found": False, "status_code": 404}
            response.raise_for_status()
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {}) or {}
            malicious_count = int(stats.get("malicious", 0) or 0)
            suspicious_count = int(stats.get("suspicious", 0) or 0)
            total = sum(int(v or 0) for v in stats.values())
            return {
                "found": True,
                "is_malicious": malicious_count > 0,
                "score": f"{malicious_count}/{total}" if total else None,
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "threat_labels": list(attrs.get("tags") or [])[:10],
            }
        except httpx.HTTPStatusError as exc:
            return {"error": f"VirusTotal HTTP {exc.response.status_code}"}
        except Exception as exc:
            return {"error": f"VirusTotal request failed: {exc}"}

    async def _query_abuseipdb(self, client: httpx.AsyncClient, ip: str) -> dict[str, Any]:
        try:
            response = await client.get(
                f"{ABUSE_BASE}/check",
                headers={"Key": self.abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0) or 0)
            return {
                "found": True,
                "is_malicious": score >= 50,
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
            }
        except httpx.HTTPStatusError as exc:
            return {"error": f"AbuseIPDB HTTP {exc.response.status_code}"}
        except Exception as exc:
            return {"error": f"AbuseIPDB request failed: {exc}"}

    @staticmethod
    def _confidence(results: list[dict[str, Any]], malicious: bool) -> float:
        if not results:
            return 0.0
        configured = 0
        confirmed = 0
        for result in results:
            vt = result.get("virustotal", {})
            abuse = result.get("abuseipdb", {})
            if vt.get("configured") is not False and not vt.get("error"):
                configured += 1
                if vt.get("is_malicious"):
                    confirmed += 1
            if isinstance(abuse.get("abuse_confidence_score"), int):
                configured += 1
                if abuse.get("is_malicious"):
                    confirmed += 1
        if configured == 0:
            return 0.0
        return round(min(1.0, 0.5 + 0.5 * (confirmed / configured)) if malicious else 0.5, 2)

    @staticmethod
    def _sources(results: list[dict[str, Any]]) -> list[str]:
        sources: set[str] = set()
        for r in results:
            if r.get("virustotal") and not r["virustotal"].get("error") and r["virustotal"].get("configured", True) is not False:
                sources.add("VirusTotal")
            if r.get("abuseipdb") and isinstance(r["abuseipdb"].get("abuse_confidence_score"), int):
                sources.add("AbuseIPDB")
        return sorted(sources)
