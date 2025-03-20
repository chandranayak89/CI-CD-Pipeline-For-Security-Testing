#!/usr/bin/env python3
"""
Script to generate a human-readable HTML report from ZAP scan results.
"""

import argparse
import json
import os
import sys
from datetime import datetime

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate a DAST HTML report from ZAP scan results')
    parser.add_argument('--baseline', required=True, help='Path to the ZAP baseline scan JSON file')
    parser.add_argument('--fullscan', required=True, help='Path to the ZAP full scan JSON file')
    parser.add_argument('--output', required=True, help='Path to the output HTML file')
    return parser.parse_args()

def load_scan_results(file_path):
    """Load scan results from a JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading scan results from {file_path}: {e}")
        return None

def get_severity_class(risk):
    """Get CSS class for severity level."""
    if risk.lower() == 'high':
        return 'high-risk'
    elif risk.lower() == 'medium':
        return 'medium-risk'
    elif risk.lower() == 'low':
        return 'low-risk'
    else:
        return 'info-risk'

def generate_html_report(baseline_results, fullscan_results, output_path):
    """Generate an HTML report from the scan results."""
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    # Combine alerts from both scans (baseline and full)
    all_alerts = []
    
    # Process baseline scan results
    if baseline_results and 'site' in baseline_results:
        for site in baseline_results['site']:
            if 'alerts' in site:
                for alert in site['alerts']:
                    alert['source'] = 'Baseline Scan'
                    all_alerts.append(alert)
    
    # Process full scan results
    if fullscan_results and 'site' in fullscan_results:
        for site in fullscan_results['site']:
            if 'alerts' in site:
                for alert in site['alerts']:
                    alert['source'] = 'Full Scan'
                    # Check if alert already exists from baseline scan
                    if not any(a.get('name') == alert.get('name') for a in all_alerts):
                        all_alerts.append(alert)
    
    # Sort alerts by risk (High, Medium, Low, Informational)
    risk_order = {'High': 0, 'Medium': 1, 'Low': 2, 'Informational': 3}
    all_alerts.sort(key=lambda x: risk_order.get(x.get('risk', 'Informational'), 4))
    
    # Group alerts by risk
    alerts_by_risk = {
        'High': [],
        'Medium': [],
        'Low': [],
        'Informational': []
    }
    
    for alert in all_alerts:
        risk = alert.get('risk', 'Informational')
        alerts_by_risk[risk].append(alert)
    
    # Count alerts by risk
    risk_counts = {risk: len(alerts) for risk, alerts in alerts_by_risk.items()}
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DAST Security Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary-box {{
            text-align: center;
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }}
        .high-risk {{
            background-color: #ffdddd;
            border-left: 5px solid #dc3545;
        }}
        .medium-risk {{
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
        }}
        .low-risk {{
            background-color: #d1ecf1;
            border-left: 5px solid #17a2b8;
        }}
        .info-risk {{
            background-color: #e2e3e5;
            border-left: 5px solid #6c757d;
        }}
        .alert-item {{
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
        }}
        .alert-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .alert-name {{
            font-weight: bold;
            font-size: 18px;
        }}
        .alert-risk {{
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }}
        .alert-details {{
            margin-top: 10px;
        }}
        .alert-section {{
            margin-bottom: 5px;
        }}
        .alert-section-title {{
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            text-align: center;
        }}
        .timestamp {{
            text-align: right;
            color: #6c757d;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DAST Security Scan Report</h1>
            <p>CI/CD Pipeline for Security Testing</p>
        </div>
        
        <div class="summary">
            <div class="summary-box high-risk">
                <h3>High Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{risk_counts['High']}</p>
            </div>
            <div class="summary-box medium-risk">
                <h3>Medium Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{risk_counts['Medium']}</p>
            </div>
            <div class="summary-box low-risk">
                <h3>Low Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{risk_counts['Low']}</p>
            </div>
            <div class="summary-box info-risk">
                <h3>Informational</h3>
                <p style="font-size: 24px; font-weight: bold;">{risk_counts['Informational']}</p>
            </div>
        </div>
        
        <h2>Security Findings</h2>
"""
    
    # Add alerts by risk level
    for risk in ['High', 'Medium', 'Low', 'Informational']:
        if alerts_by_risk[risk]:
            html += f"""
        <h3>{risk} Risk Issues ({len(alerts_by_risk[risk])})</h3>
"""
            for alert in alerts_by_risk[risk]:
                severity_class = get_severity_class(risk)
                html += f"""
        <div class="alert-item {severity_class}">
            <div class="alert-header">
                <div class="alert-name">{alert.get('name', 'Unknown Alert')}</div>
                <div class="alert-risk" style="background-color: {'#dc3545' if risk == 'High' else '#ffc107' if risk == 'Medium' else '#17a2b8' if risk == 'Low' else '#6c757d'}">
                    {risk}
                </div>
            </div>
            <div class="alert-details">
                <div class="alert-section">
                    <span class="alert-section-title">Description:</span> 
                    <p>{alert.get('description', 'No description available')}</p>
                </div>
                <div class="alert-section">
                    <span class="alert-section-title">Solution:</span>
                    <p>{alert.get('solution', 'No solution available')}</p>
                </div>
                <div class="alert-section">
                    <span class="alert-section-title">CWE:</span> 
                    {alert.get('cweid', 'N/A')}
                </div>
                <div class="alert-section">
                    <span class="alert-section-title">WASC:</span> 
                    {alert.get('wascid', 'N/A')}
                </div>
                <div class="alert-section">
                    <span class="alert-section-title">Source:</span> 
                    {alert.get('source', 'Unknown')}
                </div>
            </div>
        </div>
"""
    
    # Add timestamp and close tags
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    html += f"""
        <div class="timestamp">
            <p>Report generated on: {timestamp}</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"Report successfully generated at {output_path}")

def main():
    """Main function."""
    args = parse_arguments()
    
    # Load scan results
    baseline_results = load_scan_results(args.baseline)
    fullscan_results = load_scan_results(args.fullscan)
    
    if not baseline_results and not fullscan_results:
        print("Error: No valid scan results found. Exiting.")
        sys.exit(1)
    
    # Generate HTML report
    generate_html_report(baseline_results, fullscan_results, args.output)

if __name__ == "__main__":
    main() 