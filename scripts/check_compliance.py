#!/usr/bin/env python3
"""
Compliance Checker

This script checks the project against the defined security policies and compliance rules.
It verifies that all security controls are in place and reports any violations.
"""

import argparse
import glob
import json
import logging
import os
import re
import sys
import subprocess
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("compliance_check.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("compliance-checker")


class ComplianceChecker:
    """Class to check compliance with security policies"""
    
    def __init__(self, policy_file: str, output_dir: str, strict: bool = False):
        """
        Initialize the compliance checker
        
        Args:
            policy_file: Path to the security policy YAML file
            output_dir: Directory to save reports
            strict: If True, any policy violation will cause the script to exit with error
        """
        self.policy_file = policy_file
        self.output_dir = output_dir
        self.strict = strict
        self.policies = {}
        self.violations = []
        self.passed_checks = []
        self.total_checks = 0
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Read policies
        self._load_policies()
    
    def _load_policies(self) -> None:
        """Load security policies from YAML file"""
        try:
            with open(self.policy_file, 'r') as f:
                self.policies = yaml.safe_load(f)
            logger.info(f"Loaded security policies from {self.policy_file}")
        except Exception as e:
            logger.error(f"Failed to load security policies: {str(e)}")
            sys.exit(1)
    
    def add_violation(self, policy: str, description: str, severity: str = "high") -> None:
        """
        Add a policy violation
        
        Args:
            policy: The policy that was violated
            description: Description of the violation
            severity: Severity of the violation (critical, high, medium, low)
        """
        self.violations.append({
            "policy": policy,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        })
        logger.warning(f"Policy violation: {policy} - {description}")
    
    def add_passed_check(self, policy: str, description: str) -> None:
        """
        Add a passed policy check
        
        Args:
            policy: The policy that was checked
            description: Description of the check
        """
        self.passed_checks.append({
            "policy": policy,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })
        logger.info(f"Policy check passed: {policy} - {description}")
    
    def check_sast_policies(self) -> None:
        """Check Static Application Security Testing policies"""
        logger.info("Checking SAST policies...")
        sast_policies = self.policies.get('sast_policies', {})
        
        # Check if required SAST tools are installed
        required_tools = set()
        for check in sast_policies.get('required_checks', []):
            required_tools.add(check.get('tool'))
        
        for tool in required_tools:
            self.total_checks += 1
            try:
                subprocess.check_output(f"which {tool}", shell=True)
                self.add_passed_check(
                    "sast_policies.required_tools", 
                    f"Required SAST tool '{tool}' is installed"
                )
            except subprocess.CalledProcessError:
                self.add_violation(
                    "sast_policies.required_tools",
                    f"Required SAST tool '{tool}' is not installed",
                    "high"
                )
        
        # Check if SAST reports exist
        self.total_checks += 1
        sast_reports = glob.glob("reports/sast/*.json") + glob.glob("reports/sast/*.xml")
        if sast_reports:
            self.add_passed_check(
                "sast_policies.reports",
                f"Found {len(sast_reports)} SAST reports"
            )
        else:
            self.add_violation(
                "sast_policies.reports",
                "No SAST reports found in reports/sast/",
                "medium"
            )
    
    def check_dast_policies(self) -> None:
        """Check Dynamic Application Security Testing policies"""
        logger.info("Checking DAST policies...")
        dast_policies = self.policies.get('dast_policies', {})
        
        # Check if required DAST tools are installed
        required_scans = dast_policies.get('required_scans', [])
        self.total_checks += 1
        
        try:
            subprocess.check_output("which zap-cli", shell=True)
            self.add_passed_check(
                "dast_policies.required_tools",
                "ZAP CLI is installed for DAST scanning"
            )
        except subprocess.CalledProcessError:
            self.add_violation(
                "dast_policies.required_tools",
                "ZAP CLI is not installed for DAST scanning",
                "high"
            )
        
        # Check if DAST reports exist
        self.total_checks += 1
        dast_reports = glob.glob("reports/dast/*.json") + glob.glob("reports/dast/*.xml")
        if dast_reports:
            self.add_passed_check(
                "dast_policies.reports",
                f"Found {len(dast_reports)} DAST reports"
            )
        else:
            self.add_violation(
                "dast_policies.reports",
                "No DAST reports found in reports/dast/",
                "medium"
            )
    
    def check_container_policies(self) -> None:
        """Check container security policies"""
        logger.info("Checking container security policies...")
        container_policies = self.policies.get('container_policies', {})
        
        # Check if Docker is installed
        self.total_checks += 1
        try:
            subprocess.check_output("which docker", shell=True)
            self.add_passed_check(
                "container_policies.docker",
                "Docker is installed for container management"
            )
        except subprocess.CalledProcessError:
            self.add_violation(
                "container_policies.docker",
                "Docker is not installed",
                "medium"
            )
        
        # Check if container scanning is in place
        self.total_checks += 1
        container_reports = glob.glob("reports/container/*.json") + glob.glob("reports/container/*.xml")
        if container_reports:
            self.add_passed_check(
                "container_policies.image_scanning",
                f"Found {len(container_reports)} container scan reports"
            )
        else:
            self.add_violation(
                "container_policies.image_scanning",
                "No container scan reports found in reports/container/",
                "medium"
            )
        
        # Check if Falco is configured
        self.total_checks += 1
        if os.path.exists("falco/falco_rules.yaml"):
            # Validate if required Falco rules are present
            required_rules = container_policies.get('runtime_security', {}).get('required_falco_rules', [])
            with open("falco/falco_rules.yaml", 'r') as f:
                falco_content = f.read()
                missing_rules = []
                for rule in required_rules:
                    if rule not in falco_content:
                        missing_rules.append(rule)
            
            if missing_rules:
                self.add_violation(
                    "container_policies.runtime_security.required_falco_rules",
                    f"Missing required Falco rules: {', '.join(missing_rules)}",
                    "high"
                )
            else:
                self.add_passed_check(
                    "container_policies.runtime_security.required_falco_rules",
                    "All required Falco rules are configured"
                )
        else:
            self.add_violation(
                "container_policies.runtime_security",
                "Falco rules not configured (falco/falco_rules.yaml not found)",
                "high"
            )
    
    def check_dependency_policies(self) -> None:
        """Check dependency management policies"""
        logger.info("Checking dependency management policies...")
        dependency_policies = self.policies.get('dependency_policies', {})
        
        # Check if dependency scanning tools are installed
        self.total_checks += 1
        try:
            subprocess.check_output("which safety", shell=True)
            self.add_passed_check(
                "dependency_policies.scanning.tools",
                "Safety is installed for dependency scanning"
            )
        except subprocess.CalledProcessError:
            self.add_violation(
                "dependency_policies.scanning.tools",
                "Safety is not installed for dependency scanning",
                "medium"
            )
        
        # Check if dependency scan reports exist
        self.total_checks += 1
        dependency_reports = glob.glob("reports/dependencies/*.json") + glob.glob("reports/dependencies/*.html")
        if dependency_reports:
            self.add_passed_check(
                "dependency_policies.scanning.reports",
                f"Found {len(dependency_reports)} dependency scan reports"
            )
        else:
            self.add_violation(
                "dependency_policies.scanning.reports",
                "No dependency scan reports found in reports/dependencies/",
                "medium"
            )
        
        # Check if automatic updates are configured
        self.total_checks += 1
        if os.path.exists("scripts/update_dependencies.py") or os.path.exists("scripts/dependency_maintenance.sh"):
            self.add_passed_check(
                "dependency_policies.auto_update",
                "Automatic dependency update scripts are configured"
            )
        else:
            auto_update_required = dependency_policies.get('auto_update', False)
            if auto_update_required:
                self.add_violation(
                    "dependency_policies.auto_update",
                    "Automatic dependency updates are required but not configured",
                    "medium"
                )
            else:
                self.add_passed_check(
                    "dependency_policies.auto_update",
                    "Automatic dependency updates are not required"
                )
    
    def check_secrets_policies(self) -> None:
        """Check secrets management policies"""
        logger.info("Checking secrets management policies...")
        secrets_policies = self.policies.get('secrets_policies', {})
        
        # Check if secrets detection tools are installed
        required_tools = secrets_policies.get('detection_tools', [])
        for tool in required_tools:
            self.total_checks += 1
            try:
                subprocess.check_output(f"which {tool}", shell=True)
                self.add_passed_check(
                    "secrets_policies.detection_tools",
                    f"Required secrets detection tool '{tool}' is installed"
                )
            except subprocess.CalledProcessError:
                self.add_violation(
                    "secrets_policies.detection_tools",
                    f"Required secrets detection tool '{tool}' is not installed",
                    "high"
                )
        
        # Check if TruffleHog config exists
        self.total_checks += 1
        if os.path.exists("policies/trufflehog-config.yaml"):
            self.add_passed_check(
                "secrets_policies.trufflehog",
                "TruffleHog configuration exists"
            )
            
            # Check if all required secret patterns are included
            required_patterns = secrets_policies.get('secret_patterns', [])
            with open("policies/trufflehog-config.yaml", 'r') as f:
                trufflehog_config = yaml.safe_load(f)
                custom_regexes = trufflehog_config.get('custom_regexes', [])
                pattern_names = [regex.get('name') for regex in custom_regexes]
                
                missing_patterns = []
                for pattern in required_patterns:
                    if pattern.get('name') not in pattern_names:
                        missing_patterns.append(pattern.get('name'))
                
                if missing_patterns:
                    self.add_violation(
                        "secrets_policies.secret_patterns",
                        f"Missing required secret patterns in TruffleHog config: {', '.join(missing_patterns)}",
                        "medium"
                    )
                else:
                    self.add_passed_check(
                        "secrets_policies.secret_patterns",
                        "All required secret patterns are included in TruffleHog config"
                    )
        else:
            self.add_violation(
                "secrets_policies.trufflehog",
                "TruffleHog configuration does not exist (policies/trufflehog-config.yaml not found)",
                "high"
            )
    
    def check_compliance_frameworks(self) -> None:
        """Check compliance with required frameworks"""
        logger.info("Checking compliance frameworks...")
        frameworks = self.policies.get('compliance_standards', {}).get('frameworks', [])
        
        for framework in frameworks:
            name = framework.get('name')
            version = framework.get('version')
            self.total_checks += 1
            
            # Look for evidence of compliance with this framework
            compliance_files = glob.glob(f"reports/compliance/*{name.lower().replace(' ', '-')}*.pdf") + \
                              glob.glob(f"reports/compliance/*{name.lower().replace(' ', '-')}*.html")
            
            if compliance_files:
                self.add_passed_check(
                    f"compliance_standards.frameworks.{name}",
                    f"Evidence of compliance with {name} {version} found"
                )
            else:
                # This is a warning, not a violation, since absence of reports doesn't mean non-compliance
                self.add_violation(
                    f"compliance_standards.frameworks.{name}",
                    f"No evidence of compliance with {name} {version} found",
                    "low"
                )
    
    def check_pipeline_enforcement(self) -> None:
        """Check if pipeline enforcement is configured"""
        logger.info("Checking pipeline enforcement...")
        pipeline_enforcement = self.policies.get('pipeline_enforcement', {})
        
        # Check if GitHub Actions workflows exist for each stage
        stages = pipeline_enforcement.get('stages', [])
        for stage in stages:
            stage_name = stage.get('name')
            self.total_checks += 1
            
            # Look for workflow files that might handle this stage
            workflow_files = glob.glob(".github/workflows/*.yml")
            stage_configured = False
            
            for workflow_file in workflow_files:
                with open(workflow_file, 'r') as f:
                    content = f.read()
                    if stage_name.lower() in content.lower():
                        stage_configured = True
                        break
            
            if stage_configured:
                self.add_passed_check(
                    f"pipeline_enforcement.stages.{stage_name}",
                    f"Pipeline stage '{stage_name}' appears to be configured in workflows"
                )
            else:
                self.add_violation(
                    f"pipeline_enforcement.stages.{stage_name}",
                    f"No evidence that pipeline stage '{stage_name}' is configured in workflows",
                    "medium"
                )
    
    def run_all_checks(self) -> None:
        """Run all compliance checks"""
        self.check_sast_policies()
        self.check_dast_policies()
        self.check_container_policies()
        self.check_dependency_policies()
        self.check_secrets_policies()
        self.check_compliance_frameworks()
        self.check_pipeline_enforcement()
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a compliance report
        
        Returns:
            Dict containing the compliance report
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "policy_file": self.policy_file,
            "policy_version": self.policies.get('version', 'unknown'),
            "last_updated": self.policies.get('last_updated', 'unknown'),
            "total_checks": self.total_checks,
            "passed_checks": len(self.passed_checks),
            "violations": {
                "total": len(self.violations),
                "by_severity": {
                    "critical": sum(1 for v in self.violations if v["severity"] == "critical"),
                    "high": sum(1 for v in self.violations if v["severity"] == "high"),
                    "medium": sum(1 for v in self.violations if v["severity"] == "medium"),
                    "low": sum(1 for v in self.violations if v["severity"] == "low")
                }
            },
            "detailed_violations": self.violations,
            "detailed_passed_checks": self.passed_checks,
            "compliance_status": "non-compliant" if len(self.violations) > 0 else "compliant"
        }
        return report
    
    def save_report(self, format_type: str = "json") -> str:
        """
        Save compliance report to a file
        
        Args:
            format_type: Type of report to generate (json or html)
            
        Returns:
            Path to the saved report
        """
        report = self.generate_report()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == "json":
            report_path = os.path.join(self.output_dir, f"compliance_report_{timestamp}.json")
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Saved JSON compliance report to {report_path}")
            return report_path
        
        elif format_type == "html":
            report_path = os.path.join(self.output_dir, f"compliance_report_{timestamp}.html")
            with open(report_path, 'w') as f:
                f.write(self._generate_html_report(report))
            logger.info(f"Saved HTML compliance report to {report_path}")
            return report_path
        
        else:
            logger.error(f"Unsupported report format: {format_type}")
            return ""
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """
        Generate HTML report from the compliance data
        
        Args:
            report: Compliance report data
            
        Returns:
            HTML content as string
        """
        violations_by_severity = {
            "critical": [v for v in report["detailed_violations"] if v["severity"] == "critical"],
            "high": [v for v in report["detailed_violations"] if v["severity"] == "high"],
            "medium": [v for v in report["detailed_violations"] if v["severity"] == "medium"],
            "low": [v for v in report["detailed_violations"] if v["severity"] == "low"]
        }
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Policy Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ display: flex; margin-bottom: 20px; }}
        .summary-box {{ flex: 1; margin: 10px; padding: 15px; border-radius: 5px; color: white; }}
        .compliant {{ background-color: #28a745; }}
        .non-compliant {{ background-color: #dc3545; }}
        .info {{ background-color: #17a2b8; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ text-align: left; padding: 12px; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .critical {{ background-color: #ffdddd; }}
        .high {{ background-color: #ffe0cc; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #e6ffcc; }}
        .passed {{ background-color: #ccffcc; }}
    </style>
</head>
<body>
    <h1>Security Policy Compliance Report</h1>
    <p><strong>Generated:</strong> {report["timestamp"]}</p>
    <p><strong>Policy File:</strong> {report["policy_file"]}</p>
    <p><strong>Policy Version:</strong> {report["policy_version"]}</p>
    <p><strong>Last Updated:</strong> {report["last_updated"]}</p>
    
    <div class="summary">
        <div class="summary-box {'compliant' if report['compliance_status'] == 'compliant' else 'non-compliant'}">
            <h2>Status: {report['compliance_status'].upper()}</h2>
            <p>{report['violations']['total']} violations found</p>
        </div>
        <div class="summary-box info">
            <h2>Checks: {report['passed_checks']}/{report['total_checks']}</h2>
            <p>{report['passed_checks']} passed, {report['total_checks'] - report['passed_checks']} failed</p>
        </div>
    </div>
    
    <h2>Violations by Severity</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        <tr class="critical">
            <td>Critical</td>
            <td>{report['violations']['by_severity']['critical']}</td>
        </tr>
        <tr class="high">
            <td>High</td>
            <td>{report['violations']['by_severity']['high']}</td>
        </tr>
        <tr class="medium">
            <td>Medium</td>
            <td>{report['violations']['by_severity']['medium']}</td>
        </tr>
        <tr class="low">
            <td>Low</td>
            <td>{report['violations']['by_severity']['low']}</td>
        </tr>
    </table>
    """
        
        # Add violations tables by severity
        for severity, items in violations_by_severity.items():
            if items:
                html += f"""
    <h2>{severity.capitalize()} Severity Violations</h2>
    <table>
        <tr>
            <th>Policy</th>
            <th>Description</th>
        </tr>
    """
                for violation in items:
                    html += f"""
        <tr class="{severity}">
            <td>{violation['policy']}</td>
            <td>{violation['description']}</td>
        </tr>
    """
                html += "</table>"
        
        # Add passed checks
        if report["detailed_passed_checks"]:
            html += """
    <h2>Passed Checks</h2>
    <table>
        <tr>
            <th>Policy</th>
            <th>Description</th>
        </tr>
    """
            for check in report["detailed_passed_checks"]:
                html += f"""
        <tr class="passed">
            <td>{check['policy']}</td>
            <td>{check['description']}</td>
        </tr>
    """
            html += "</table>"
        
        html += """
</body>
</html>
"""
        return html
    
    def check_thresholds_violated(self) -> bool:
        """
        Check if any threshold violations were detected
        
        Returns:
            True if thresholds violated, False otherwise
        """
        critical_count = sum(1 for v in self.violations if v["severity"] == "critical")
        high_count = sum(1 for v in self.violations if v["severity"] == "high")
        
        # Thresholds from policy (if defined)
        sast_thresholds = self.policies.get('sast_policies', {}).get('severity_thresholds', {})
        critical_threshold = sast_thresholds.get('critical', 0)
        high_threshold = sast_thresholds.get('high', 0)
        
        return critical_count > critical_threshold or high_count > high_threshold
    
    def summarize_results(self) -> None:
        """Print a summary of compliance check results"""
        report = self.generate_report()
        
        logger.info(f"Compliance Status: {report['compliance_status'].upper()}")
        logger.info(f"Total Checks: {report['total_checks']}")
        logger.info(f"Passed Checks: {report['passed_checks']}")
        logger.info(f"Total Violations: {report['violations']['total']}")
        logger.info(f"Violations by Severity:")
        logger.info(f"  Critical: {report['violations']['by_severity']['critical']}")
        logger.info(f"  High: {report['violations']['by_severity']['high']}")
        logger.info(f"  Medium: {report['violations']['by_severity']['medium']}")
        logger.info(f"  Low: {report['violations']['by_severity']['low']}")
        
        # Determine exit status based on policy
        if self.strict and report['violations']['total'] > 0:
            logger.error("Compliance check failed in strict mode (any violation)")
            return 1
        elif self.check_thresholds_violated():
            logger.error("Compliance check failed (threshold violation)")
            return 1
        else:
            logger.info("Compliance check completed - thresholds not violated")
            return 0


def parse_args() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Check compliance with security policies")
    parser.add_argument(
        "--policy-file",
        default="policies/security-policies.yaml",
        help="Path to security policy YAML file"
    )
    parser.add_argument(
        "--output-dir",
        default="reports/compliance",
        help="Directory to save compliance reports"
    )
    parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Format of the compliance report"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="If set, any policy violation will cause script to exit with error"
    )
    return parser.parse_args()


def main() -> int:
    """Main function"""
    args = parse_args()
    
    # Create compliance checker
    checker = ComplianceChecker(
        policy_file=args.policy_file,
        output_dir=args.output_dir,
        strict=args.strict
    )
    
    # Run all checks
    checker.run_all_checks()
    
    # Generate reports
    if args.format in ["json", "both"]:
        checker.save_report(format_type="json")
    if args.format in ["html", "both"]:
        checker.save_report(format_type="html")
    
    # Summarize results
    exit_code = checker.summarize_results()
    return exit_code


if __name__ == "__main__":
    sys.exit(main()) 