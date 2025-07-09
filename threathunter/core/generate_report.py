# generate_report.py
# Generates HTML and PDF summary reports from alerts

import json
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML
import os

def generate_html_report(alerts, output_html):
    env = Environment(
        loader=FileSystemLoader(searchpath=os.path.dirname(__file__)),
        autoescape=select_autoescape(['html', 'xml'])
    )
    template = env.get_template('report_template.html')
    html_content = template.render(alerts=alerts)
    with open(output_html, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_html

def generate_pdf_report(html_path, output_pdf):
    HTML(html_path).write_pdf(output_pdf)
    return output_pdf

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate ThreatHunter alert report (HTML/PDF)")
    parser.add_argument('--alerts', type=str, default='threathunter/reports/alerts.json', help='Path to alerts.json')
    parser.add_argument('--html', type=str, default='threathunter/reports/summary.html', help='Output HTML report')
    parser.add_argument('--pdf', type=str, default='threathunter/reports/summary.pdf', help='Output PDF report')
    args = parser.parse_args()

    with open(args.alerts, 'r', encoding='utf-8') as f:
        alerts = json.load(f)
    # Ensure template exists
    template_path = os.path.join(os.path.dirname(__file__), 'report_template.html')
    if not os.path.exists(template_path):
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write("""
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>ThreatHunter Alert Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background: #f4f4f4; }
        .high { color: #c0392b; font-weight: bold; }
        .medium { color: #e67e22; }
        .low { color: #27ae60; }
    </style>
</head>
<body>
    <h1>ThreatHunter Alert Report</h1>
    <p>Total Alerts: {{ alerts|length }}</p>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Rule</th>
            <th>User</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Details</th>
        </tr>
        {% for alert in alerts %}
        <tr>
            <td>{{ alert.timestamp }}</td>
            <td>{{ alert.rule }}</td>
            <td>{{ alert.user }}</td>
            <td>{{ alert.src_ip }}</td>
            <td class="{{ alert.severity|lower }}">{{ alert.severity }}</td>
            <td>
                {% if alert.event %}
                    {{ alert.event.raw_message }}
                {% elif alert.events %}
                    <ul>
                    {% for e in alert.events %}
                        <li>{{ e.raw_message }}</li>
                    {% endfor %}
                    </ul>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
""")
    html_path = generate_html_report(alerts, args.html)
    print(f"[+] HTML report generated: {html_path}")
    pdf_path = generate_pdf_report(html_path, args.pdf)
    print(f"[+] PDF report generated: {pdf_path}") 