#!/usr/bin/env python3
"""
Pre-commit Security Policy Check

This script is used by pre-commit hooks to validate changes against security policies
before they are committed. It performs lightweight checks to ensure that security
policies are not violated in the changes being committed.
"""

import argparse
import os
import re
import sys
import subprocess
import yaml
from typing import List, Dict, Any, Set, Tuple


def load_security_policies(policy_file: str = 'policies/security-policies.yaml') -> Dict[str, Any]:
    """
    Load security policies from YAML file
    
    Args:
        policy_file: Path to policy file
        
    Returns:
        Dictionary of security policies
    """
    try:
        with open(policy_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Failed to load security policies: {str(e)}")
        sys.exit(1)


def get_staged_files() -> List[str]:
    """
    Get list of staged files for the commit
    
    Returns:
        List of staged file paths
    """
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip().split('\n') if result.stdout.strip() else []
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to get staged files: {str(e)}")
        return []


def check_for_secrets(files: List[str]) -> List[str]:
    """
    Check files for potential secrets using regex patterns
    
    Args:
        files: List of file paths to check
        
    Returns:
        List of violations found
    """
    violations = []
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded password'),
        (r'api[_\-]?key\s*=\s*["\'][a-zA-Z0-9]{16,}["\']', 'API key'),
        (r'secret\s*=\s*["\'][a-zA-Z0-9]{16,}["\']', 'Secret'),
        (r'aws_access_key_id\s*=\s*["\']AKIA[0-9A-Z]{16}["\']', 'AWS access key'),
        (r'-----BEGIN\s+PRIVATE\s+KEY-----', 'Private key'),
        (r'-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----', 'RSA private key'),
        (r'eyJhbGciOiJ[\w-]*\.[\w-]*\.[\w-]*', 'JWT token')
    ]
    
    for file_path in files:
        # Skip binary files, large files
        if not os.path.isfile(file_path) or os.path.getsize(file_path) > 1000000:
            continue
            
        # Skip certain file types
        if any(file_path.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.zip', '.tar', '.gz']):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern, pattern_name in secret_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        violations.append(f"{file_path}:{line_num} - Potential {pattern_name} found")
        except Exception as e:
            print(f"WARNING: Couldn't scan {file_path}: {str(e)}")
    
    return violations


def check_python_security(python_files: List[str]) -> List[str]:
    """
    Check Python files for security issues
    
    Args:
        python_files: List of Python file paths
        
    Returns:
        List of violations found
    """
    violations = []
    
    if not python_files:
        return violations
        
    # Common dangerous Python functions/imports to check for
    dangerous_patterns = [
        (r'eval\s*\(', 'Use of eval() function'),
        (r'exec\s*\(', 'Use of exec() function'),
        (r'os\.system\s*\(', 'Use of os.system()'),
        (r'subprocess\.call\s*\(\s*shell\s*=\s*True', 'Subprocess with shell=True'),
        (r'subprocess\.Popen\s*\(\s*shell\s*=\s*True', 'Subprocess with shell=True'),
        (r'__reduce__', 'Pickle serialization vulnerability'),
        (r'\.run\s*\(\s*shell\s*=\s*True', 'Running commands with shell=True'),
        (r'yaml\.load\s*\((?!.*Loader)', 'Unsafe YAML loading'),
        (r'request\.get\s*\([^)]*verify\s*=\s*False', 'SSL verification disabled')
    ]
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                for pattern, pattern_name in dangerous_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        violations.append(f"{file_path}:{line_num} - {pattern_name}")
        except Exception as e:
            print(f"WARNING: Couldn't scan {file_path}: {str(e)}")
    
    return violations


def check_dockerfile_security(dockerfile_paths: List[str]) -> List[str]:
    """
    Check Dockerfile for security issues
    
    Args:
        dockerfile_paths: List of Dockerfile paths
        
    Returns:
        List of violations found
    """
    violations = []
    
    if not dockerfile_paths:
        return violations
    
    # Patterns for Dockerfile security issues
    dockerfile_patterns = [
        (r'FROM\s+.*:latest', 'Using latest tag for base image'),
        (r'USER\s+root', 'Running as root user'),
        (r'apt-get\s+update(?!.*&&\s*apt-get)', 'apt-get update without apt-get install'),
        (r'ADD\s+', 'ADD command used (COPY preferred)'),
        (r'RUN\s+pip\s+install\s+--no-cache-dir\s+--upgrade\s+pip', 'Upgrading pip can cause issues'),
        (r'RUN\s+chmod\s+777', 'Using chmod 777')
    ]
    
    for file_path in dockerfile_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Check for patterns
                for pattern, pattern_name in dockerfile_patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        violations.append(f"{file_path}:{line_num} - {pattern_name}")
                
                # Check if healthcheck exists
                if 'HEALTHCHECK' not in content:
                    violations.append(f"{file_path} - No HEALTHCHECK instruction found")
        except Exception as e:
            print(f"WARNING: Couldn't scan {file_path}: {str(e)}")
    
    return violations


def check_policy_compliance(files: List[str], policies: Dict[str, Any]) -> List[str]:
    """
    Check if files comply with security policies
    
    Args:
        files: List of file paths
        policies: Security policies
        
    Returns:
        List of violations found
    """
    violations = []
    
    # Group files by type
    python_files = [f for f in files if f.endswith('.py')]
    dockerfile_files = [f for f in files if os.path.basename(f) == 'Dockerfile' or f.endswith('.dockerfile')]
    
    # Check for secrets in all files
    secret_violations = check_for_secrets(files)
    violations.extend(secret_violations)
    
    # Check Python files
    python_violations = check_python_security(python_files)
    violations.extend(python_violations)
    
    # Check Dockerfile
    dockerfile_violations = check_dockerfile_security(dockerfile_files)
    violations.extend(dockerfile_violations)
    
    return violations


def format_violation_output(violations: List[str]) -> str:
    """
    Format violations for output
    
    Args:
        violations: List of violation strings
        
    Returns:
        Formatted output string
    """
    if not violations:
        return "No security policy violations found!"
    
    output = "\nSecurity policy violations found:\n"
    output += "="*50 + "\n"
    
    for i, violation in enumerate(violations, 1):
        output += f"{i}. {violation}\n"
    
    output += "\n" + "="*50 + "\n"
    output += "These violations must be fixed before committing.\n"
    output += "Run 'git commit --no-verify' to bypass this check (NOT RECOMMENDED).\n"
    
    return output


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Pre-commit security policy check')
    parser.add_argument('files', nargs='*', help='Files to check')
    args = parser.parse_args()
    
    # Get files to check - either from arguments or git
    files_to_check = args.files if args.files else get_staged_files()
    
    if not files_to_check:
        print("No files to check. Exiting.")
        return 0
    
    # Load security policies
    policy_file = 'policies/security-policies.yaml'
    if not os.path.exists(policy_file):
        print(f"WARNING: Policy file {policy_file} not found. Using minimal checks.")
        policies = {}
    else:
        policies = load_security_policies(policy_file)
    
    # Check for policy violations
    violations = check_policy_compliance(files_to_check, policies)
    
    # Output results
    output = format_violation_output(violations)
    print(output)
    
    # Return exit code
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main()) 