"""HTML report generation."""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from scanner.utils import write_text_atomic


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
            undefined=StrictUndefined,
        )

    def generate_html_report(self, report_data: dict, output_path: str | Path) -> Path:
        """Render and save the HTML report."""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        template = self.environment.get_template("report_template.html")
        html = template.render(**report_data)
        write_text_atomic(output, html)
        self.logger.info("HTML report written to %s", output)
        return output
