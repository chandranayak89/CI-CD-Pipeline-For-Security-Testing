#!/usr/bin/env python3
"""
Update vulnerable dependencies to secure versions.
This script analyzes security reports and suggests updates to fix vulnerabilities.
It can also automatically update the requirements.txt file.
"""

import argparse
import json
import os
import sys
import re
import subprocess
from pathlib import Path

# Define paths
REPORT_DIR = Path("reports/dependency-scan")
REQUIREMENTS_FILE = Path("requirements.txt")
BACKUP_FILE = Path("requirements.txt.bak")
SAFETY_REPORT = REPORT_DIR / "safety-report.json"
PIP_AUDIT_REPORT = REPORT_DIR / "pip-audit-report.json"

def load_json_file(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error loading {file_path}: {e}")
        return None

def parse_requirements():
    """Parse requirements.txt file into a dictionary."""
    requirements = {}
    try:
        with open(REQUIREMENTS_FILE, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                # Handle different requirement formats
                if '>=' in line or '==' in line or '<=' in line:
                    parts = re.split(r'(>=|==|<=)', line, 1)
                    if len(parts) >= 3:
                        package = parts[0].strip()
                        operator = parts[1].strip()
                        version = parts[2].strip()
                        requirements[package] = {'line': line, 'version': version, 'operator': operator}
                else:
                    requirements[line] = {'line': line, 'version': None, 'operator': None}
        
        return requirements, lines
    except FileNotFoundError:
        print(f"Requirements file not found: {REQUIREMENTS_FILE}")
        return {}, []

def get_vulnerable_packages():
    """Get list of vulnerable packages from reports."""
    vulnerabilities = {}
    
    # Process Safety report
    safety_data = load_json_file(SAFETY_REPORT)
    if safety_data:
        for vuln in safety_data:
            package_name = vuln.get("package_name", "").lower()
            if package_name:
                if package_name not in vulnerabilities:
                    vulnerabilities[package_name] = []
                
                vulnerabilities[package_name].append({
                    'source': 'safety',
                    'installed_version': vuln.get("installed_version"),
                    'vulnerable_spec': vuln.get("vulnerable_spec"),
                    'severity': vuln.get("severity", "unknown"),
                    'advisory': vuln.get("advisory"),
                    'recommendation': "Upgrade to latest version"
                })
    
    # Process pip-audit report
    audit_data = load_json_file(PIP_AUDIT_REPORT)
    if audit_data and 'vulnerabilities' in audit_data:
        for vuln in audit_data['vulnerabilities']:
            package_name = vuln.get("name", "").lower()
            if package_name:
                if package_name not in vulnerabilities:
                    vulnerabilities[package_name] = []
                
                fix_versions = vuln.get("fix_versions", [])
                recommendation = f"Upgrade to {', '.join(fix_versions)}" if fix_versions else "Upgrade to latest version"
                
                vulnerabilities[package_name].append({
                    'source': 'pip-audit',
                    'installed_version': vuln.get("version"),
                    'fix_versions': fix_versions,
                    'severity': vuln.get("vulnerabilities", [{}])[0].get("severity", "unknown") if vuln.get("vulnerabilities") else "unknown",
                    'description': vuln.get("vulnerabilities", [{}])[0].get("description", "") if vuln.get("vulnerabilities") else "",
                    'recommendation': recommendation
                })
    
    return vulnerabilities

def get_latest_version(package):
    """Get the latest version of a package from PyPI."""
    try:
        result = subprocess.run(
            ['pip', 'index', 'versions', package], 
            capture_output=True, 
            text=True, 
            check=True
        )
        output = result.stdout
        
        # Parse the output to find the latest version
        match = re.search(r'Available versions: (.*)', output)
        if match:
            versions = match.group(1).split(', ')
            if versions:
                return versions[0].strip()
        
        return None
    except subprocess.CalledProcessError:
        print(f"Error checking latest version for {package}")
        return None

def generate_update_recommendations(vulnerabilities, requirements):
    """Generate recommendations for updating vulnerable packages."""
    recommendations = []
    
    for package, vulns in vulnerabilities.items():
        if package in requirements:
            current_version = requirements[package]['version']
            current_operator = requirements[package]['operator']
            
            # Get the most severe vulnerability
            most_severe = max(vulns, key=lambda x: {
                'critical': 4, 
                'high': 3, 
                'medium': 2, 
                'low': 1, 
                'unknown': 0
            }.get(x.get('severity', '').lower(), 0))
            
            # Determine fix version
            fix_version = None
            if 'fix_versions' in most_severe and most_severe['fix_versions']:
                fix_version = most_severe['fix_versions'][0]
            else:
                fix_version = get_latest_version(package)
            
            if fix_version:
                old_req = requirements[package]['line']
                if current_operator and current_version:
                    new_req = f"{package}>={fix_version}"
                else:
                    new_req = f"{package}>={fix_version}"
                
                recommendations.append({
                    'package': package,
                    'current_version': current_version,
                    'fix_version': fix_version,
                    'severity': most_severe.get('severity', 'unknown'),
                    'old_requirement': old_req,
                    'new_requirement': new_req,
                    'description': most_severe.get('advisory', most_severe.get('description', 'No description available'))
                })
    
    return recommendations

def update_requirements(recommendations, requirements_lines):
    """Update requirements.txt file with secure versions."""
    # First create a backup
    with open(BACKUP_FILE, 'w') as f:
        f.writelines(requirements_lines)
    
    # Create a dictionary for quick lookup
    rec_dict = {r['package']: r for r in recommendations}
    
    # Update the requirements file
    updated_lines = []
    for line in requirements_lines:
        original_line = line
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('-'):
            # Check if this line matches any of our vulnerable packages
            for package, rec in rec_dict.items():
                if line.lower().startswith(package.lower()) and ('==' in line or '>=' in line or '<=' in line or line == package):
                    line = rec['new_requirement']
                    break
        
        # Preserve original formatting (newlines, etc.)
        if line != original_line.strip():
            updated_lines.append(line + '\n')
        else:
            updated_lines.append(original_line)
    
    # Write updated requirements
    with open(REQUIREMENTS_FILE, 'w') as f:
        f.writelines(updated_lines)
    
    return len(recommendations)

def print_recommendations(recommendations):
    """Print update recommendations in a readable format."""
    if not recommendations:
        print("\nNo updates needed! All dependencies are secure.")
        return
    
    print("\n============== VULNERABILITY UPDATE RECOMMENDATIONS ==============")
    print(f"Found {len(recommendations)} vulnerable packages that need updates")
    print("==================================================================\n")
    
    for i, rec in enumerate(recommendations, 1):
        severity = rec['severity'].upper()
        print(f"{i}. Package: {rec['package']} ({severity} severity)")
        print(f"   Current: {rec['old_requirement']}")
        print(f"   Recommended: {rec['new_requirement']}")
        print(f"   Reason: {rec['description']}")
        print()
    
    print("To update automatically, run with --apply flag")

def setup_argparse():
    """Set up argument parser."""
    parser = argparse.ArgumentParser(description='Update vulnerable dependencies')
    parser.add_argument('--apply', action='store_true',
                        help='Apply the recommended updates to requirements.txt')
    parser.add_argument('--report', action='store_true',
                        help='Generate a detailed report of vulnerability findings')
    return parser

def main():
    """Main function."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Create reports directory if it doesn't exist
    REPORT_DIR.mkdir(exist_ok=True, parents=True)
    
    # Parse requirements and get vulnerable packages
    requirements, requirements_lines = parse_requirements()
    if not requirements:
        print("No requirements found or unable to parse requirements file.")
        return 1
    
    vulnerabilities = get_vulnerable_packages()
    if not vulnerabilities:
        print("No vulnerability data found. Run dependency scan first.")
        return 1
    
    # Generate update recommendations
    recommendations = generate_update_recommendations(vulnerabilities, requirements)
    
    # Print recommendations
    print_recommendations(recommendations)
    
    # Apply updates if requested
    if args.apply and recommendations:
        num_updated = update_requirements(recommendations, requirements_lines)
        print(f"\nUpdated {num_updated} packages in {REQUIREMENTS_FILE}")
        print(f"Backup saved to {BACKUP_FILE}")
    
    # Generate detailed report if requested
    if args.report:
        report_file = REPORT_DIR / "dependency_update_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                'vulnerable_packages': len(vulnerabilities),
                'updated_packages': len(recommendations),
                'recommendations': recommendations
            }, f, indent=2)
        print(f"\nDetailed report saved to {report_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 