"""NVD CVE lookup client."""

from __future__ import annotations

import logging
import os
import time
from typing import Iterable

import requests

from scanner.utils import severity_meets_threshold


class CVELookup:
    """Look up potential CVEs through the NVD CVE 2.0 API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 15.0,
        rate_delay: float | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self.rate_delay = rate_delay if rate_delay is not None else (0.7 if self.api_key else 6.1)
        self.logger = logger or logging.getLogger(__name__)
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def lookup_for_services(
        self,
        services: Iterable[dict],
        max_results: int = 5,
        min_severity: str = "LOW",
    ) -> list[dict]:
        """Return flattened CVE records for all service fingerprints."""
        vulnerabilities: list[dict] = []
        query_cache: dict[str, list[dict]] = {}

        for service in services:
            query = self._query_from_service(service)
            if not query:
                continue

            if query not in query_cache:
                query_cache[query] = self.search(
                    query=query,
                    max_results=max_results,
                    min_severity=min_severity,
                )
                if self.rate_delay:
                    time.sleep(self.rate_delay)

            for cve in query_cache[query]:
                service_cve = dict(cve)
                service_cve["port"] = service.get("port")
                service_cve["service"] = service.get("service", "unknown")
                service_cve["query"] = query
                vulnerabilities.append(service_cve)

        return vulnerabilities

    def search(
        self,
        query: str,
        max_results: int = 5,
        min_severity: str = "LOW",
    ) -> list[dict]:
        """Search NVD for a keyword and return normalized CVE records."""
        params = {
            "keywordSearch": query,
            "resultsPerPage": max(1, min(max_results, 20)),
        }

        try:
            response = self.session.get(self.BASE_URL, params=params, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            self.logger.warning("NVD lookup failed for '%s': %s", query, exc)
            return []

        data = response.json()
        results: list[dict] = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            normalized = self._normalize_cve(cve_data)
            if severity_meets_threshold(normalized["severity"], min_severity):
                results.append(normalized)
        return results

    def _normalize_cve(self, cve_data: dict) -> dict:
        """Convert one NVD CVE entry into the scanner report shape."""
        cve_id = cve_data.get("id", "UNKNOWN")
        description = self._english_description(cve_data.get("descriptions", []))
        score, severity = self._cvss_score_and_severity(cve_data.get("metrics", {}))

        return {
            "id": cve_id,
            "severity": severity,
            "description": description,
            "cvss_score": score,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

    @staticmethod
    def _english_description(descriptions: list[dict]) -> str:
        """Pick the English CVE description when one is available."""
        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    @staticmethod
    def _cvss_score_and_severity(metrics: dict) -> tuple[float | str, str]:
        """Extract CVSS score and severity across NVD metric versions."""
        metric_keys = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
        for key in metric_keys:
            entries = metrics.get(key) or []
            if not entries:
                continue
            metric = entries[0]
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore", "N/A")
            severity = (
                cvss_data.get("baseSeverity")
                or metric.get("baseSeverity")
                or CVELookup._severity_from_score(score)
            )
            return score, str(severity).upper()
        return "N/A", "UNKNOWN"

    @staticmethod
    def _severity_from_score(score: float | str) -> str:
        """Map a CVSS score to a severity label."""
        try:
            value = float(score)
        except (TypeError, ValueError):
            return "UNKNOWN"
        if value >= 9.0:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MEDIUM"
        if value > 0:
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _query_from_service(service: dict) -> str:
        """Build a compact NVD keyword query from service detection fields."""
        product = (service.get("product") or "").strip()
        version = (service.get("version") or "").strip()
        service_name = (service.get("service") or "").strip()
        banner = (service.get("banner") or "").strip()

        if product and version:
            return f"{product} {version}"
        if product:
            return product
        if service_name and service_name.lower() not in {"unknown", "tcpwrapped"}:
            if banner:
                return f"{service_name} {banner[:80]}"
            return service_name
        return ""
