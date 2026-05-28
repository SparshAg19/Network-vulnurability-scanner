"""HTML report generation."""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    """Render scanner findings into HTML reports."""

    def __init__(
        self,
        template_dir: str | Path,
        logger: logging.Logger | None = None,
    ) -> None:
        self.template_dir = Path(template_dir)
        self.logger = logger or logging.getLogger(__name__)
        self.environment = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def generate_html_report(self, report_data: dict, output_path: str | Path) -> Path:
        """Render and save the HTML report."""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        template = self.environment.get_template("report_template.html")
        html = template.render(**report_data)
        output.write_text(html, encoding="utf-8")
        self.logger.info("HTML report written to %s", output)
        return output
