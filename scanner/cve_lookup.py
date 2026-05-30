"""NVD CVE lookup client."""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Iterable

import requests

from scanner.utils import sanitize_text, severity_meets_threshold


class CVELookup:
    """Look up potential CVEs through the NVD CVE 2.0 API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_QUERY_LENGTH = 180
    MAX_SERVICE_QUERIES = 50
    MAX_RESPONSE_BYTES = 5_000_000
    CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

    def __init__(
        self,
        api_key: str | None = None,
        timeout: float = 15.0,
        rate_delay: float | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.api_key = self._clean_api_key(api_key or os.getenv("NVD_API_KEY"))
        self.timeout = min(max(timeout, 3.0), 30.0)
        self.rate_delay = rate_delay if rate_delay is not None else (0.7 if self.api_key else 6.1)
        self.rate_delay = min(max(self.rate_delay, 0.0), 30.0)
        self.logger = logger or logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "User-Agent": "python-network-vulnerability-scanner/1.0",
            }
        )
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
        query_count = 0

        for service in services:
            query = self._query_from_service(service)
            if not query:
                continue

            if query not in query_cache:
                query_count += 1
                if query_count > self.MAX_SERVICE_QUERIES:
                    self.logger.warning("CVE lookup stopped after %s unique service queries.", self.MAX_SERVICE_QUERIES)
                    break
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
            "keywordSearch": sanitize_text(query, self.MAX_QUERY_LENGTH),
            "resultsPerPage": max(1, min(max_results, 20)),
        }

        try:
            response = self._get_with_single_retry(params)
        except requests.RequestException as exc:
            self.logger.warning("NVD lookup failed for '%s': %s", sanitize_text(query, 120), sanitize_text(exc, 200))
            return []

        if len(response.content) > self.MAX_RESPONSE_BYTES:
            self.logger.warning("NVD response for '%s' exceeded the maximum allowed size.", sanitize_text(query, 120))
            return []

        try:
            data = response.json()
        except ValueError as exc:
            self.logger.warning("NVD returned invalid JSON for '%s': %s", sanitize_text(query, 120), sanitize_text(exc, 120))
            return []

        results: list[dict] = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            normalized = self._normalize_cve(cve_data)
            if severity_meets_threshold(normalized["severity"], min_severity):
                results.append(normalized)
        return results

    def _normalize_cve(self, cve_data: dict) -> dict:
        """Convert one NVD CVE entry into the scanner report shape."""
        cve_id = sanitize_text(cve_data.get("id", "UNKNOWN"), 32)
        description = self._english_description(cve_data.get("descriptions", []))
        score, severity = self._cvss_score_and_severity(cve_data.get("metrics", {}))
        safe_id = cve_id if self.CVE_ID_PATTERN.match(cve_id) else "UNKNOWN"

        return {
            "id": sanitize_text(safe_id, 32),
            "severity": sanitize_text(severity, 16),
            "description": sanitize_text(description, 1000),
            "cvss_score": score,
            "published": sanitize_text(cve_data.get("published", ""), 40),
            "last_modified": sanitize_text(cve_data.get("lastModified", ""), 40),
            "url": f"https://nvd.nist.gov/vuln/detail/{safe_id}" if safe_id != "UNKNOWN" else "https://nvd.nist.gov/vuln",
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
        product = sanitize_text(service.get("product") or "", 80).strip()
        version = sanitize_text(service.get("version") or "", 60).strip()
        service_name = sanitize_text(service.get("service") or "", 60).strip()
        banner = sanitize_text(service.get("banner") or "", 80).strip()

        if product and version:
            return sanitize_text(f"{product} {version}", CVELookup.MAX_QUERY_LENGTH)
        if product:
            return sanitize_text(product, CVELookup.MAX_QUERY_LENGTH)
        if service_name and service_name.lower() not in {"unknown", "tcpwrapped"}:
            if banner:
                return sanitize_text(f"{service_name} {banner}", CVELookup.MAX_QUERY_LENGTH)
            return sanitize_text(service_name, CVELookup.MAX_QUERY_LENGTH)
        return ""

    def _get_with_single_retry(self, params: dict) -> requests.Response:
        """Call NVD and retry once on rate limiting when Retry-After is reasonable."""
        response = self.session.get(self.BASE_URL, params=params, timeout=(5.0, self.timeout))
        if response.status_code == 429:
            retry_after = self._retry_after_seconds(response.headers.get("Retry-After"))
            if retry_after is not None:
                time.sleep(retry_after)
                response = self.session.get(self.BASE_URL, params=params, timeout=(5.0, self.timeout))
        response.raise_for_status()
        return response

    @staticmethod
    def _retry_after_seconds(value: str | None) -> float | None:
        """Parse a bounded Retry-After header value."""
        if not value or not value.isdigit():
            return None
        seconds = int(value)
        if seconds < 0 or seconds > 30:
            return None
        return float(seconds)

    @staticmethod
    def _clean_api_key(value: str | None) -> str | None:
        """Validate API key shape enough to avoid logging or sending junk secrets."""
        if not value:
            return None
        candidate = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", candidate):
            return None
        return candidate
