from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent / "templates"
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

TEMPLATE_FILE = TEMPLATES_DIR / "scan_report.html.j2"
if not TEMPLATE_FILE.exists():
    TEMPLATE_FILE.write_text("""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>VulnScan Report - {{ target }}</title></head>
<body>
<h1>VulnScan Report — {{ target }}</h1>
<p><strong>Timestamp:</strong> {{ timestamp }}</p>
<h2>Open Ports</h2>
<ul>
{% for p in open_ports %}
  <li><strong>{{ p }}</strong> — banner: {{ banners[p|string] or "None" }}
  {% if issues.get(p|string) %}
    <ul>
      {% for issue in issues[p|string] %}
        <li>{{ issue.cve }} ({{ issue.severity }}) — {{ issue.notes }}</li>
      {% endfor %}
    </ul>
  {% endif %}
  </li>
{% endfor %}
</ul>
</body>
</html>""", encoding="utf-8")

def save_html_report(report: dict, issues: dict, outpath: str):
    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=select_autoescape())
    tpl = env.get_template("scan_report.html.j2")
    out_html = tpl.render(
        target=report.get("target"),
        timestamp=report.get("timestamp"),
        open_ports=report.get("open_ports", []),
        banners=report.get("banners", {}),
        issues=issues
    )
    p = Path(outpath)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(out_html, encoding="utf-8")
    print(f"[reporter] HTML report saved: {p}")
