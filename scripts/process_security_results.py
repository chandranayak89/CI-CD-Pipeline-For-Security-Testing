#!/usr/bin/env python3
"""
Security results processor for the Security Testing Pipeline.
This script processes and aggregates security scan results into a dashboard.
"""

import os
import json
import argparse
import sys
from datetime import datetime

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Process security scan results into a dashboard")
    parser.add_argument('--input', required=True, help='Input directory containing security scan results')
    parser.add_argument('--output', required=True, help='Output HTML file for the dashboard')
    return parser.parse_args()

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {filepath}: {str(e)}")
        return None

def process_bandit_results(results):
    """Process Bandit scan results."""
    if not results:
        return {
            "total_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "issues": []
        }
    
    high_issues = 0
    medium_issues = 0
    low_issues = 0
    issues = []
    
    # Process results based on Bandit's JSON format
    for result in results.get("results", []):
        severity = result.get("issue_severity", "").lower()
        if severity == "high":
            high_issues += 1
        elif severity == "medium":
            medium_issues += 1
        elif severity == "low":
            low_issues += 1
        
        issues.append({
            "file": result.get("filename", "Unknown"),
            "line": result.get("line_number", 0),
            "issue": result.get("issue_text", "Unknown issue"),
            "severity": severity,
            "confidence": result.get("issue_confidence", ""),
            "cwe": result.get("cwe", {}).get("id", "Unknown")
        })
    
    return {
        "total_issues": len(issues),
        "high_issues": high_issues,
        "medium_issues": medium_issues,
        "low_issues": low_issues,
        "issues": issues
    }

def process_safety_results(results):
    """Process Safety dependency scan results."""
    if not results:
        return {
            "total_vulnerabilities": 0,
            "vulnerabilities": []
        }
    
    vulnerabilities = []
    
    # Process results based on Safety's JSON format
    for vuln in results.get("vulnerabilities", []):
        vulnerabilities.append({
            "package": vuln.get("package_name", "Unknown"),
            "installed_version": vuln.get("installed_version", "Unknown"),
            "vulnerable_spec": vuln.get("vulnerable_spec", "Unknown"),
            "description": vuln.get("description", "No description"),
            "id": vuln.get("vulnerability_id", "Unknown"),
            "cvss_score": vuln.get("cvss_score", 0)
        })
    
    return {
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }

def process_semgrep_results(results):
    """Process Semgrep scan results."""
    if not results:
        return {
            "total_findings": 0,
            "findings": []
        }
    
    findings = []
    
    # Process results based on Semgrep's JSON format
    for result in results.get("results", []):
        findings.append({
            "rule_id": result.get("rule_id", "Unknown"),
            "file": result.get("path", "Unknown"),
            "line": result.get("start", {}).get("line", 0),
            "message": result.get("extra", {}).get("message", "Unknown issue"),
            "severity": result.get("extra", {}).get("severity", "unknown"),
            "metadata": result.get("extra", {}).get("metadata", {})
        })
    
    return {
        "total_findings": len(findings),
        "findings": findings
    }

def generate_html_dashboard(bandit_data, safety_data, semgrep_data, output_file):
    """Generate HTML dashboard from the processed security data."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Results Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f7f9fc;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            flex-wrap: wrap;
        }}
        .summary-card {{
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card.red {{
            background-color: #ffebee;
            border-left: 4px solid #e53935;
        }}
        .summary-card.orange {{
            background-color: #fff8e1;
            border-left: 4px solid #ffb300;
        }}
        .summary-card.green {{
            background-color: #e8f5e9;
            border-left: 4px solid #43a047;
        }}
        .summary-card h3 {{
            margin-top: 0;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #e1e5ee;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f7f9fc;
        }}
        .severity-high {{
            color: #e53935;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #ffb300;
            font-weight: bold;
        }}
        .severity-low {{
            color: #43a047;
        }}
        .tab {{
            overflow: hidden;
            border: 1px solid #e1e5ee;
            background-color: #f8f9fa;
            border-radius: 5px 5px 0 0;
        }}
        .tab button {{
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }}
        .tab button:hover {{
            background-color: #ddd;
        }}
        .tab button.active {{
            background-color: white;
            border-bottom: 2px solid #3498db;
        }}
        .tabcontent {{
            display: none;
            padding: 20px;
            border: 1px solid #e1e5ee;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }}
        .timestamp {{
            text-align: right;
            color: #7f8c8d;
            margin-bottom: 20px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 5px;
        }}
        .badge.high {{
            background-color: #ffebee;
            color: #e53935;
        }}
        .badge.medium {{
            background-color: #fff8e1;
            color: #ffb300;
        }}
        .badge.low {{
            background-color: #e8f5e9;
            color: #43a047;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Results Dashboard</h1>
        <p class="timestamp">Generated: {timestamp}</p>
        
        <div class="summary">
            <div class="summary-card red">
                <h3>High Severity Issues</h3>
                <div class="number">{bandit_data['high_issues']}</div>
                <p>Found by Bandit</p>
            </div>
            <div class="summary-card orange">
                <h3>Medium Severity Issues</h3>
                <div class="number">{bandit_data['medium_issues']}</div>
                <p>Found by Bandit</p>
            </div>
            <div class="summary-card green">
                <h3>Low Severity Issues</h3>
                <div class="number">{bandit_data['low_issues']}</div>
                <p>Found by Bandit</p>
            </div>
            <div class="summary-card orange">
                <h3>Dependency Vulnerabilities</h3>
                <div class="number">{safety_data['total_vulnerabilities']}</div>
                <p>Found by Safety</p>
            </div>
            <div class="summary-card orange">
                <h3>Semgrep Findings</h3>
                <div class="number">{semgrep_data['total_findings']}</div>
                <p>Custom code patterns</p>
            </div>
        </div>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'Bandit')">Bandit (SAST)</button>
            <button class="tablinks" onclick="openTab(event, 'Safety')">Safety (Dependencies)</button>
            <button class="tablinks" onclick="openTab(event, 'Semgrep')">Semgrep (Custom Rules)</button>
        </div>
        
        <div id="Bandit" class="tabcontent" style="display: block;">
            <h2>Bandit SAST Results <span class="badge high">{bandit_data['total_issues']}</span></h2>
            
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Line</th>
                        <th>Issue</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>CWE</th>
                    </tr>
                </thead>
                <tbody>"""
    
    if bandit_data['total_issues'] == 0:
        html += """
                    <tr>
                        <td colspan="6" style="text-align: center;">No issues found</td>
                    </tr>"""
    else:
        for issue in bandit_data['issues']:
            severity_class = f"severity-{issue['severity']}"
            html += f"""
                    <tr>
                        <td>{issue['file']}</td>
                        <td>{issue['line']}</td>
                        <td>{issue['issue']}</td>
                        <td class="{severity_class}">{issue['severity'].upper()}</td>
                        <td>{issue['confidence']}</td>
                        <td>{issue['cwe']}</td>
                    </tr>"""
    
    html += """
                </tbody>
            </table>
        </div>
        
        <div id="Safety" class="tabcontent">
            <h2>Safety Dependency Scan Results <span class="badge high">{safety_data['total_vulnerabilities']}</span></h2>
            
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Installed Version</th>
                        <th>Vulnerable Specification</th>
                        <th>Vulnerability ID</th>
                        <th>CVSS Score</th>
                    </tr>
                </thead>
                <tbody>"""
    
    if safety_data['total_vulnerabilities'] == 0:
        html += """
                    <tr>
                        <td colspan="5" style="text-align: center;">No vulnerabilities found</td>
                    </tr>"""
    else:
        for vuln in safety_data['vulnerabilities']:
            html += f"""
                    <tr>
                        <td>{vuln['package']}</td>
                        <td>{vuln['installed_version']}</td>
                        <td>{vuln['vulnerable_spec']}</td>
                        <td>{vuln['id']}</td>
                        <td>{vuln['cvss_score']}</td>
                    </tr>
                    <tr>
                        <td colspan="5" style="padding-left: 20px; font-style: italic; background-color: #f8f9fa;">
                            {vuln['description']}
                        </td>
                    </tr>"""
    
    html += """
                </tbody>
            </table>
        </div>
        
        <div id="Semgrep" class="tabcontent">
            <h2>Semgrep Custom Rules Results <span class="badge high">{semgrep_data['total_findings']}</span></h2>
            
            <table>
                <thead>
                    <tr>
                        <th>Rule ID</th>
                        <th>File</th>
                        <th>Line</th>
                        <th>Message</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>"""
    
    if semgrep_data['total_findings'] == 0:
        html += """
                    <tr>
                        <td colspan="5" style="text-align: center;">No findings detected</td>
                    </tr>"""
    else:
        for finding in semgrep_data['findings']:
            severity_class = f"severity-{finding['severity'].lower()}"
            html += f"""
                    <tr>
                        <td>{finding['rule_id']}</td>
                        <td>{finding['file']}</td>
                        <td>{finding['line']}</td>
                        <td>{finding['message']}</td>
                        <td class="{severity_class}">{finding['severity'].upper()}</td>
                    </tr>"""
    
    html += """
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
    </script>
</body>
</html>"""
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    
    # Write HTML to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"Dashboard generated and saved to {output_file}")

def main():
    """Main function to process security results."""
    args = parse_arguments()
    
    # Ensure input directory exists
    if not os.path.isdir(args.input):
        print(f"Error: Input directory {args.input} does not exist")
        sys.exit(1)
    
    # Load result files
    bandit_file = os.path.join(args.input, "bandit-results.json")
    safety_file = os.path.join(args.input, "safety-results.json")
    semgrep_file = os.path.join(args.input, "semgrep-results.json")
    
    bandit_results = load_json_file(bandit_file)
    safety_results = load_json_file(safety_file)
    semgrep_results = load_json_file(semgrep_file)
    
    # Process results
    bandit_data = process_bandit_results(bandit_results)
    safety_data = process_safety_results(safety_results)
    semgrep_data = process_semgrep_results(semgrep_results)
    
    # Create output directory
    os.makedirs("security-dashboard", exist_ok=True)
    
    # Generate dashboard
    output_path = os.path.join("security-dashboard", "index.html")
    generate_html_dashboard(bandit_data, safety_data, semgrep_data, output_path)
    
    # Create a summary file for quick reference
    summary = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "bandit_issues": {
            "total": bandit_data["total_issues"],
            "high": bandit_data["high_issues"],
            "medium": bandit_data["medium_issues"],
            "low": bandit_data["low_issues"]
        },
        "dependency_vulnerabilities": safety_data["total_vulnerabilities"],
        "semgrep_findings": semgrep_data["total_findings"]
    }
    
    with open(os.path.join("security-dashboard", "summary.json"), 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("Processing completed successfully")

if __name__ == "__main__":
    main() 