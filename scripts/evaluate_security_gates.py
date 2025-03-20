#!/usr/bin/env python3
"""
Security Gates Evaluator

This script evaluates security scan results against defined gates to determine
if a deployment should proceed. It acts as an automated quality gate that
prevents insecure code from being deployed to target environments.
"""

import argparse
import json
import os
import sys
import yaml
from datetime import datetime
from typing import Dict, List, Any, Tuple, Optional
import logging
import requests  # For Slack notifications


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("security-gates")


class SecurityGateException(Exception):
    """Exception raised when a security gate fails."""
    pass


def load_gate_config(config_path: str) -> Dict[str, Any]:
    """
    Load the security gates configuration file
    
    Args:
        config_path: Path to the configuration YAML file
        
    Returns:
        Dictionary containing gate configurations
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to load gate configuration: {str(e)}")
        raise


def load_scan_results(results_dir: str) -> Dict[str, Any]:
    """
    Load security scan results from JSON files in the specified directory
    
    Args:
        results_dir: Directory containing scan result JSON files
        
    Returns:
        Dictionary of scan results by category
    """
    results = {}
    
    # Define expected result files
    expected_files = {
        'sast': ['bandit-results.json', 'semgrep-results.json'],
        'dast': ['zap-baseline-results.json', 'zap-full-scan-results.json'],
        'container': ['trivy-results.json'],
        'dependencies': ['safety-results.json', 'pip-audit-results.json'],
        'policy': ['compliance-results.json'],
        'secrets': ['trufflehog-results.json'],
        'runtime_security': ['falco-validation-results.json']
    }
    
    # Load each result file if it exists
    for category, files in expected_files.items():
        results[category] = {}
        
        for file_name in files:
            file_path = os.path.join(results_dir, file_name)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        results[category][file_name] = json.load(f)
                        logger.info(f"Loaded {file_path}")
                except Exception as e:
                    logger.warning(f"Could not load {file_path}: {str(e)}")
    
    return results


def count_findings_by_severity(results: Dict[str, Any], category: str) -> Dict[str, int]:
    """
    Count findings by severity level for a given category
    
    Args:
        results: Dictionary of scan results
        category: Category to count findings for
        
    Returns:
        Dictionary of counts by severity
    """
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    if category not in results:
        return counts
    
    # Different tools have different output formats, so we need to handle each one
    for tool_file, tool_results in results[category].items():
        if 'bandit' in tool_file:
            # Bandit format
            if 'results' in tool_results:
                for finding in tool_results['results']:
                    severity = finding.get('issue_severity', '').lower()
                    if severity in counts:
                        counts[severity] += 1
        
        elif 'semgrep' in tool_file:
            # Semgrep format
            if 'results' in tool_results:
                for finding in tool_results['results']:
                    severity = finding.get('extra', {}).get('severity', '').lower()
                    if severity in counts:
                        counts[severity] += 1
        
        elif 'zap' in tool_file:
            # ZAP format
            if 'site' in tool_results and isinstance(tool_results['site'], list):
                for site in tool_results['site']:
                    if 'alerts' in site and isinstance(site['alerts'], list):
                        for alert in site['alerts']:
                            risk = alert.get('riskdesc', '').lower()
                            if 'high' in risk:
                                counts['high'] += 1
                            elif 'medium' in risk:
                                counts['medium'] += 1
                            elif 'low' in risk:
                                counts['low'] += 1
                            elif 'info' in risk:
                                counts['info'] += 1
        
        elif 'trivy' in tool_file:
            # Trivy format
            if 'Results' in tool_results:
                for result in tool_results['Results']:
                    if 'Vulnerabilities' in result:
                        for vuln in result['Vulnerabilities']:
                            severity = vuln.get('Severity', '').lower()
                            if severity in counts:
                                counts[severity] += 1
        
        elif 'safety' in tool_file or 'pip-audit' in tool_file:
            # Safety format
            if isinstance(tool_results, list):
                for vuln in tool_results:
                    if isinstance(vuln, list) and len(vuln) >= 5:
                        severity = vuln[4].lower() if len(vuln) > 4 else 'unknown'
                        if severity == 'critical':
                            counts['critical'] += 1
                        elif severity == 'high':
                            counts['high'] += 1
                        elif severity == 'medium':
                            counts['medium'] += 1
                        elif severity == 'low':
                            counts['low'] += 1
        
        elif 'trufflehog' in tool_file:
            # TruffleHog format
            if isinstance(tool_results, list):
                for finding in tool_results:
                    severity = finding.get('severity', '').lower()
                    if severity in counts:
                        counts[severity] += 1
    
    return counts


def check_required_tools(results: Dict[str, Any], required_tools: List[str], category: str) -> Tuple[bool, List[str]]:
    """
    Check if all required tools have results
    
    Args:
        results: Dictionary of scan results
        required_tools: List of required tool names
        category: Category to check tools for
        
    Returns:
        Tuple of (all_present, missing_tools)
    """
    if category not in results:
        return False, required_tools
    
    present_tools = []
    for tool_file in results[category].keys():
        for required_tool in required_tools:
            if required_tool in tool_file and required_tool not in present_tools:
                present_tools.append(required_tool)
    
    missing_tools = [tool for tool in required_tools if tool not in present_tools]
    return len(missing_tools) == 0, missing_tools


def evaluate_gate(
    results: Dict[str, Any], 
    gate_config: Dict[str, Any], 
    category: str
) -> Tuple[bool, List[str]]:
    """
    Evaluate a specific security gate against scan results
    
    Args:
        results: Dictionary of scan results
        gate_config: Configuration for the gate
        category: Category of the gate
        
    Returns:
        Tuple of (passed, failure_reasons)
    """
    failure_reasons = []
    
    # Check if gate is required
    if not gate_config.get('required', False):
        logger.info(f"Gate {category} is not required, skipping")
        return True, []
    
    # Check if required tools are present
    required_tools = gate_config.get('required_tools', [])
    if required_tools:
        tools_present, missing_tools = check_required_tools(results, required_tools, category)
        if not tools_present:
            failure_reasons.append(
                f"Required tools missing for {category}: {', '.join(missing_tools)}"
            )
            # If tools are missing, we can't evaluate this gate properly
            return False, failure_reasons
    
    # If it's a policy gate, check compliance score
    if category == 'policy' and 'compliance_score' in gate_config:
        min_score = gate_config['compliance_score']
        actual_score = 0
        
        if 'compliance-results.json' in results.get('policy', {}):
            compliance_results = results['policy']['compliance-results.json']
            if 'compliance_score' in compliance_results:
                actual_score = compliance_results['compliance_score']
        
        if actual_score < min_score:
            failure_reasons.append(
                f"Compliance score ({actual_score}%) below required threshold ({min_score}%)"
            )
    
    # For runtime security, check if rules are validated
    elif category == 'runtime_security' and gate_config.get('rules_validated', False):
        if 'falco-validation-results.json' in results.get('runtime_security', {}):
            validation_results = results['runtime_security']['falco-validation-results.json']
            if not validation_results.get('all_rules_validated', False):
                failure_reasons.append("Runtime security rules not properly validated")
    
    # For other gates, check finding counts
    else:
        counts = count_findings_by_severity(results, category)
        
        # Check counts against thresholds
        for severity in ['critical', 'high', 'medium', 'low']:
            max_key = f'max_{severity}'
            if max_key in gate_config:
                max_allowed = gate_config[max_key]
                actual_count = counts[severity]
                
                if actual_count > max_allowed:
                    failure_reasons.append(
                        f"{severity.capitalize()} findings ({actual_count}) exceed maximum allowed ({max_allowed})"
                    )
    
    return len(failure_reasons) == 0, failure_reasons


def evaluate_environment_gates(
    results: Dict[str, Any], 
    gate_config: Dict[str, Any], 
    environment: str
) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Evaluate all gates for a specific environment
    
    Args:
        results: Dictionary of scan results
        gate_config: Security gates configuration
        environment: Environment to evaluate gates for
        
    Returns:
        Tuple of (all_passed, failures_by_gate)
    """
    failures_by_gate = {}
    all_passed = True
    
    env_config = gate_config['environments'].get(environment)
    if not env_config:
        logger.error(f"Environment '{environment}' not found in gate configuration")
        sys.exit(1)
    
    if not env_config.get('enabled', True):
        logger.info(f"Gates for environment '{environment}' are disabled")
        return True, {}
    
    # Evaluate each gate
    for gate_category, gate_config in env_config.get('gates', {}).items():
        passed, failure_reasons = evaluate_gate(results, gate_config, gate_category)
        
        if not passed:
            failures_by_gate[gate_category] = failure_reasons
            all_passed = False
            logger.warning(f"Gate '{gate_category}' failed for environment '{environment}'")
            for reason in failure_reasons:
                logger.warning(f"  - {reason}")
        else:
            logger.info(f"Gate '{gate_category}' passed for environment '{environment}'")
    
    return all_passed, failures_by_gate


def evaluate_special_gates(
    results: Dict[str, Any], 
    gate_config: Dict[str, Any], 
    special_gates: List[str]
) -> Tuple[bool, Dict[str, List[str]]]:
    """
    Evaluate special gates requested for the deployment
    
    Args:
        results: Dictionary of scan results
        gate_config: Security gates configuration
        special_gates: List of special gate names to evaluate
        
    Returns:
        Tuple of (all_passed, failures_by_gate)
    """
    failures_by_gate = {}
    all_passed = True
    
    for special_gate in special_gates:
        if special_gate not in gate_config.get('special_gates', {}):
            logger.warning(f"Special gate '{special_gate}' not found in configuration")
            continue
        
        special_config = gate_config['special_gates'][special_gate]
        if not special_config.get('enabled', False):
            logger.info(f"Special gate '{special_gate}' is disabled")
            continue
        
        logger.info(f"Evaluating special gate: {special_gate}")
        
        # Evaluate each sub-gate in the special gate
        for gate_category, gate_config in special_config.get('gates', {}).items():
            passed, failure_reasons = evaluate_gate(results, gate_config, gate_category)
            
            if not passed:
                gate_key = f"{special_gate}:{gate_category}"
                failures_by_gate[gate_key] = failure_reasons
                all_passed = False
                logger.warning(f"Special gate '{gate_key}' failed")
                for reason in failure_reasons:
                    logger.warning(f"  - {reason}")
            else:
                logger.info(f"Special gate '{special_gate}:{gate_category}' passed")
    
    return all_passed, failures_by_gate


def generate_report(
    environment: str,
    all_passed: bool,
    failures_by_gate: Dict[str, List[str]],
    gate_config: Dict[str, Any],
    results_dir: str
) -> None:
    """
    Generate a report of the security gate evaluation
    
    Args:
        environment: Target environment
        all_passed: Whether all gates passed
        failures_by_gate: Dictionary of failures by gate
        gate_config: Security gates configuration
        results_dir: Directory to save the report to
    """
    report = {
        "timestamp": datetime.now().isoformat(),
        "environment": environment,
        "passed": all_passed,
        "failures": failures_by_gate
    }
    
    # Add to the report file
    report_file = os.path.join(results_dir, 'gate-evaluation-report.json')
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Gate evaluation report saved to {report_file}")
    
    # Generate HTML report if configured
    if gate_config.get('reports', {}).get('generate_html', False):
        html_report_file = os.path.join(results_dir, 'gate-evaluation-report.html')
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Gate Evaluation - {environment}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .passed {{ color: green; }}
                .failed {{ color: red; }}
                .gate {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 10px; }}
                .gate-header {{ font-weight: bold; margin-bottom: 10px; }}
                .failure-reason {{ color: red; margin-left: 20px; }}
                .timestamp {{ color: #666; font-size: 0.8em; }}
            </style>
        </head>
        <body>
            <h1>Security Gate Evaluation - {environment}</h1>
            <div class="timestamp">Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
            <h2 class="{'passed' if all_passed else 'failed'}">
                Overall Status: {'PASSED' if all_passed else 'FAILED'}
            </h2>
        """
        
        if all_passed:
            html_content += """
            <div class="gate">
                <div class="gate-header passed">All security gates passed successfully!</div>
                <p>The deployment is ready to proceed to the target environment.</p>
            </div>
            """
        else:
            html_content += """
            <div class="gate">
                <div class="gate-header failed">Some security gates failed!</div>
                <p>The deployment cannot proceed until these issues are addressed:</p>
            """
            
            for gate, reasons in failures_by_gate.items():
                html_content += f"""
                <div class="gate">
                    <div class="gate-header failed">Gate: {gate}</div>
                """
                
                for reason in reasons:
                    html_content += f"""
                    <div class="failure-reason">- {reason}</div>
                    """
                
                html_content += """
                </div>
                """
            
            html_content += """
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        with open(html_report_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML gate evaluation report saved to {html_report_file}")


def send_notification(
    environment: str,
    all_passed: bool,
    failures_by_gate: Dict[str, List[str]],
    gate_config: Dict[str, Any]
) -> None:
    """
    Send notification about gate evaluation results
    
    Args:
        environment: Target environment
        all_passed: Whether all gates passed
        failures_by_gate: Dictionary of failures by gate
        gate_config: Security gates configuration
    """
    notifications_config = gate_config.get('notifications', {})
    
    # Determine which notification to send
    if all_passed and notifications_config.get('gate_success', {}).get('slack', False):
        send_slack_notification(
            f"✅ Security gates PASSED for {environment} deployment",
            "All security requirements have been met. Deployment can proceed.",
            "good",
            gate_config
        )
    elif not all_passed and notifications_config.get('gate_failure', {}).get('slack', False):
        failure_text = "\n".join([
            f"❌ *{gate}*: {', '.join(reasons)}"
            for gate, reasons in failures_by_gate.items()
        ])
        
        send_slack_notification(
            f"❌ Security gates FAILED for {environment} deployment",
            f"Deployment cannot proceed until these issues are fixed:\n{failure_text}",
            "danger",
            gate_config
        )


def send_slack_notification(title: str, message: str, color: str, gate_config: Dict[str, Any]) -> None:
    """
    Send Slack notification
    
    Args:
        title: Notification title
        message: Notification message
        color: Color for the Slack attachment (good, warning, danger)
        gate_config: Security gates configuration
    """
    # This is a placeholder for actual Slack integration
    # In a real implementation, you would use a webhook URL from configuration
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL')
    if not webhook_url:
        logger.warning("Slack webhook URL not configured, skipping notification")
        return
    
    try:
        payload = {
            "attachments": [
                {
                    "fallback": title,
                    "color": color,
                    "title": title,
                    "text": message,
                    "footer": "Security Gates Evaluation",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            logger.info("Slack notification sent successfully")
        else:
            logger.warning(f"Failed to send Slack notification: {response.status_code} {response.text}")
    except Exception as e:
        logger.warning(f"Error sending Slack notification: {str(e)}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Evaluate security gates for deployment')
    parser.add_argument('--config', default='policies/deployment-gates.yaml', help='Path to gate configuration file')
    parser.add_argument('--results-dir', default='reports', help='Directory containing scan results')
    parser.add_argument('--environment', required=True, help='Target environment (dev, staging, production)')
    parser.add_argument('--special-gates', nargs='*', default=[], help='Special gates to apply')
    parser.add_argument('--slack-webhook', help='Slack webhook URL for notifications')
    args = parser.parse_args()
    
    # If Slack webhook provided, set as environment variable
    if args.slack_webhook:
        os.environ['SLACK_WEBHOOK_URL'] = args.slack_webhook
    
    try:
        # Load gate configuration
        logger.info(f"Loading gate configuration from {args.config}")
        gate_config = load_gate_config(args.config)
        
        # Load scan results
        logger.info(f"Loading scan results from {args.results_dir}")
        results = load_scan_results(args.results_dir)
        
        # Evaluate environment gates
        logger.info(f"Evaluating gates for environment: {args.environment}")
        all_passed, failures_by_gate = evaluate_environment_gates(
            results, gate_config, args.environment
        )
        
        # Evaluate special gates if requested
        if args.special_gates:
            logger.info(f"Evaluating special gates: {', '.join(args.special_gates)}")
            special_passed, special_failures = evaluate_special_gates(
                results, gate_config, args.special_gates
            )
            all_passed = all_passed and special_passed
            failures_by_gate.update(special_failures)
        
        # Generate report
        generate_report(
            args.environment,
            all_passed,
            failures_by_gate,
            gate_config,
            args.results_dir
        )
        
        # Send notification
        send_notification(
            args.environment,
            all_passed,
            failures_by_gate,
            gate_config
        )
        
        # Exit with appropriate code
        if all_passed:
            logger.info(f"All security gates passed for environment: {args.environment}")
            sys.exit(0)
        else:
            logger.error(f"Some security gates failed for environment: {args.environment}")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error evaluating security gates: {str(e)}")
        sys.exit(2)


if __name__ == "__main__":
    main() 