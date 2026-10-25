"""Reporting and export package for ShadowRecon: HTML, PDF, Markdown, SARIF, JSON, CSV, and Webhooks."""
from shadowrecon.reporting.export import export_csv, export_json
from shadowrecon.reporting.html import generate_report_from_store
from shadowrecon.reporting.markdown import export_markdown, generate_markdown_report
from shadowrecon.reporting.pdf import export_pdf, generate_pdf_html
from shadowrecon.reporting.sarif import export_sarif, generate_sarif_dict
from shadowrecon.reporting.webhook import (
    attach_finding_notifier,
    build_completion_payload,
    build_finding_payload,
    detect_webhook_type,
    send_webhook,
)

__all__ = [
    "attach_finding_notifier",
    "build_completion_payload",
    "build_finding_payload",
    "detect_webhook_type",
    "export_csv",
    "export_json",
    "export_markdown",
    "export_pdf",
    "export_sarif",
    "generate_markdown_report",
    "generate_pdf_html",
    "generate_report_from_store",
    "generate_sarif_dict",
    "send_webhook",
]
