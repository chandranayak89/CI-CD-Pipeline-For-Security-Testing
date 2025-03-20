#!/usr/bin/env python3
"""
Generate HTML report from dependency scanning results.
This script processes Safety, pip-audit, and license reports to create a comprehensive
HTML report for dependency vulnerabilities.
"""

import json
import os
import sys
import datetime
from pathlib import Path

# Configuration
REPORT_DIR = Path("reports/dependency-scan")
OUTPUT_FILE = REPORT_DIR / "index.html"

# Ensure report directory exists
REPORT_DIR.mkdir(exist_ok=True, parents=True)

def load_json_file(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {file_path}: {e}")
        return None

def get_severity_class(severity):
    """Get CSS class for a severity level."""
    severity = severity.lower()
    if severity in ['critical', 'high']:
        return 'critical'
    elif severity in ['medium']:
        return 'warning'
    elif severity in ['low']:
        return 'info'
    else:
        return 'notice'

def generate_safety_section():
    """Generate HTML section for Safety report."""
    safety_data = load_json_file(REPORT_DIR / "safety-report.json")
    
    if not safety_data:
        return "<p>No Safety data available.</p>"
    
    html = "<h2>Safety Scan Results</h2>\n"
    
    if not safety_data:
        html += "<p>No vulnerabilities detected by Safety.</p>"
        return html
    
    html += f"<p>Found {len(safety_data)} vulnerable packages</p>\n"
    
    html += """
    <table class="table">
        <thead>
            <tr>
                <th>Package</th>
                <th>Installed Version</th>
                <th>Vulnerable Spec</th>
                <th>Severity</th>
                <th>CVE</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for vuln in safety_data:
        package_name = vuln.get("package_name", "Unknown")
        installed_version = vuln.get("installed_version", "Unknown")
        vulnerable_spec = vuln.get("vulnerable_spec", "Unknown")
        severity = vuln.get("severity", "Unknown")
        advisory = vuln.get("advisory", "No advisory information")
        cve = vuln.get("cve", "N/A")
        
        severity_class = get_severity_class(severity)
        
        html += f"""
        <tr class="{severity_class}">
            <td>{package_name}</td>
            <td>{installed_version}</td>
            <td>{vulnerable_spec}</td>
            <td>{severity}</td>
            <td>{cve}</td>
            <td>{advisory}</td>
        </tr>
        """
    
    html += """
        </tbody>
    </table>
    """
    
    return html

def generate_pip_audit_section():
    """Generate HTML section for pip-audit report."""
    audit_data = load_json_file(REPORT_DIR / "pip-audit-report.json")
    
    if not audit_data:
        return "<p>No pip-audit data available.</p>"
    
    html = "<h2>Pip Audit Results</h2>\n"
    
    if not audit_data.get("vulnerabilities"):
        html += "<p>No vulnerabilities detected by pip-audit.</p>"
        return html
    
    vulns = audit_data.get("vulnerabilities", [])
    html += f"<p>Found {len(vulns)} vulnerable packages</p>\n"
    
    html += """
    <table class="table">
        <thead>
            <tr>
                <th>Package</th>
                <th>Installed Version</th>
                <th>Fixed In</th>
                <th>Vulnerability ID</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for vuln in vulns:
        package = vuln.get("name", "Unknown")
        version = vuln.get("version", "Unknown")
        fixed_in = vuln.get("fix_versions", [])
        fixed_str = ", ".join(fixed_in) if fixed_in else "Not specified"
        
        for v in vuln.get("vulnerabilities", []):
            vuln_id = v.get("id", "Unknown")
            description = v.get("description", "No description available")
            severity = v.get("severity", "medium")
            
            severity_class = get_severity_class(severity)
            
            html += f"""
            <tr class="{severity_class}">
                <td>{package}</td>
                <td>{version}</td>
                <td>{fixed_str}</td>
                <td>{vuln_id}</td>
                <td>{description}</td>
            </tr>
            """
    
    html += """
        </tbody>
    </table>
    """
    
    return html

def generate_license_section():
    """Generate HTML section for license report."""
    license_data = load_json_file(REPORT_DIR / "dependency-licenses.json")
    
    if not license_data:
        return "<p>No license data available.</p>"
    
    html = "<h2>Dependency License Analysis</h2>\n"
    
    license_count = {}
    for pkg in license_data:
        license_name = pkg.get("License", "Unknown")
        if license_name in license_count:
            license_count[license_name] += 1
        else:
            license_count[license_name] = 1
    
    # Create a summary chart
    html += "<div class='license-summary'>\n"
    html += "<h3>License Distribution</h3>\n"
    html += "<ul>\n"
    
    for license_name, count in license_count.items():
        html += f"<li>{license_name}: {count} packages</li>\n"
    
    html += "</ul>\n</div>\n"
    
    # Create detailed table
    html += """
    <h3>Detailed License Information</h3>
    <table class="table">
        <thead>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>License</th>
                <th>License URL</th>
            </tr>
        </thead>
        <tbody>
    """
    
    for pkg in license_data:
        name = pkg.get("Name", "Unknown")
        version = pkg.get("Version", "Unknown")
        license_name = pkg.get("License", "Unknown")
        license_url = pkg.get("URL", "#")
        
        html += f"""
        <tr>
            <td>{name}</td>
            <td>{version}</td>
            <td>{license_name}</td>
            <td><a href="{license_url}" target="_blank">View</a></td>
        </tr>
        """
    
    html += """
        </tbody>
    </table>
    """
    
    return html

def generate_html_report():
    """Generate the complete HTML report."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Vulnerability Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .container {{
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
            padding: 20px;
            margin-bottom: 20px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }}
        .timestamp {{
            font-size: 14px;
            color: #7f8c8d;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        .critical {{
            background-color: #ffebee;
        }}
        .warning {{
            background-color: #fff8e1;
        }}
        .info {{
            background-color: #e1f5fe;
        }}
        .notice {{
            background-color: #f1f1f1;
        }}
        .license-summary {{
            margin-bottom: 20px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 5px;
        }}
        .summary-box {{
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }}
        .summary-title {{
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .severity-indicator {{
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 5px;
        }}
        .severity-critical {{ background-color: #f44336; }}
        .severity-high {{ background-color: #ff9800; }}
        .severity-medium {{ background-color: #ffeb3b; }}
        .severity-low {{ background-color: #4caf50; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Dependency Vulnerability Report</h1>
            <div class="timestamp">Generated: {timestamp}</div>
        </div>
        
        <div class="summary-box">
            <div class="summary-title">Severity Legend:</div>
            <div><span class="severity-indicator severity-critical"></span> Critical - Must be fixed immediately</div>
            <div><span class="severity-indicator severity-high"></span> High - Should be fixed as soon as possible</div>
            <div><span class="severity-indicator severity-medium"></span> Medium - Should be addressed in the near future</div>
            <div><span class="severity-indicator severity-low"></span> Low - Should be fixed when convenient</div>
        </div>
        
        {generate_safety_section()}
        
        {generate_pip_audit_section()}
        
        {generate_license_section()}
    </div>
</body>
</html>
"""
    
    return html

def main():
    """Main function."""
    try:
        report_html = generate_html_report()
        
        with open(OUTPUT_FILE, 'w') as f:
            f.write(report_html)
        
        print(f"HTML report generated successfully at {OUTPUT_FILE}")
        return 0
    except Exception as e:
        print(f"Error generating report: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 