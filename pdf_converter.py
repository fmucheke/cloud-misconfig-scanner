"""
pdf_converter.py

Converts a Markdown report (as produced by report_generator.py) into a
formatted PDF.

Uses markdown2 (Markdown -> HTML) + xhtml2pdf (HTML -> PDF) rather than
weasyprint. Both are pure-Python packages installable via pip with no
separate system-level dependencies — weasyprint requires GTK, which has a
notoriously difficult install path on Windows unrelated to this project's
actual scope, so it was avoided here.

Usage:
    python pdf_converter.py <path-to-report.md>

    If no path is given, converts the most recently generated report in
    the reports/ folder.
"""

import glob
import os
import sys
import markdown2
from xhtml2pdf import pisa

REPORTS_DIR = "reports"

# The default fonts xhtml2pdf/reportlab use (Helvetica) lack glyphs for
# some Unicode characters an LLM is likely to produce — arrows especially.
# Rather than fail silently with garbled output (an arrow can render as
# stray characters like "fi"), these are swapped for safe ASCII
# equivalents before conversion.
UNICODE_REPLACEMENTS = {
    "\u2192": "->",   # → right arrow — confirmed broken, renders as garbled "fi"-like text
    "\u2190": "<-",   # ← left arrow — same risk as above, not yet seen but same font limitation
    "\u2022": "-",    # • bullet — same category of unsupported glyph
}
# Note: em dash (—), curly quotes (' ' " "), and middot (·) were checked
# against actual rendered output and confirmed to display correctly in
# this font — deliberately NOT included here to avoid changing something
# that already works.


def sanitize_for_pdf(text):
    for char, replacement in UNICODE_REPLACEMENTS.items():
        text = text.replace(char, replacement)
    return text

# Minimal CSS so the PDF reads like a real report rather than unstyled
# HTML — xhtml2pdf supports a limited CSS subset, so this stays simple
# and safe rather than reaching for anything fancy that might not render.
REPORT_CSS = """
<style>
    body { font-family: Helvetica, Arial, sans-serif; font-size: 11pt; line-height: 1.5; color: #1a1a1a; }
    h1 { font-size: 20pt; border-bottom: 2px solid #333; padding-bottom: 8px; }
    h2 { font-size: 15pt; margin-top: 24px; color: #222; }
    h3 { font-size: 12pt; margin-top: 18px; }
    hr { border: none; border-top: 1px solid #ccc; margin: 16px 0; }
    strong { color: #000; }
    code { font-family: Courier, monospace; background-color: #f0f0f0; padding: 1px 4px; }
</style>
"""


def find_latest_report():
    reports = sorted(glob.glob(os.path.join(REPORTS_DIR, "report-*.md")))
    if not reports:
        return None
    return reports[-1]


def convert_markdown_file_to_pdf(markdown_path):
    with open(markdown_path, "r", encoding="utf-8") as f:
        markdown_text = f.read()

    markdown_text = sanitize_for_pdf(markdown_text)

    html_body = markdown2.markdown(markdown_text, extras=["tables"])
    full_html = f"<html><head>{REPORT_CSS}</head><body>{html_body}</body></html>"

    pdf_path = os.path.splitext(markdown_path)[0] + ".pdf"

    with open(pdf_path, "wb") as pdf_file:
        result = pisa.CreatePDF(full_html, dest=pdf_file)

    if result.err:
        print(f"PDF conversion completed with {result.err} error(s) — check output for issues.")
    else:
        print(f"PDF written to {pdf_path}")

    return pdf_path


if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    else:
        input_path = find_latest_report()
        if input_path is None:
            print(f"No report found in {REPORTS_DIR}/ — run report_generator.py first, "
                  f"or pass a path directly: python pdf_converter.py path/to/report.md")
            sys.exit(1)
        print(f"No path given — using most recent report: {input_path}")

    convert_markdown_file_to_pdf(input_path)