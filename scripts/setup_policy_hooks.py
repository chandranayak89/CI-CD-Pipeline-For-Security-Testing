#!/usr/bin/env python3
"""
Setup Policy Hooks

This script sets up pre-commit hooks for security policy enforcement.
It installs the pre-commit tool and configures it to run security checks
before each commit, helping to enforce security policies at the developer level.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path
from typing import Tuple, List


def check_prerequisites() -> Tuple[bool, List[str]]:
    """
    Check if prerequisites are installed
    
    Returns:
        Tuple of (all_installed, missing_tools)
    """
    required_tools = ['git', 'pip', 'python3']
    missing_tools = []
    
    for tool in required_tools:
        # On Windows, we need to check differently
        if platform.system() == 'Windows':
            try:
                if tool == 'python3':
                    # Check for python instead of python3 on Windows
                    subprocess.run(['python', '--version'], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 check=True)
                else:
                    subprocess.run(['where', tool], 
                                 stdout=subprocess.PIPE, 
                                 stderr=subprocess.PIPE,
                                 check=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
        else:
            try:
                subprocess.run(['which', tool], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE,
                             check=True)
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
    
    return len(missing_tools) == 0, missing_tools


def install_pre_commit() -> bool:
    """
    Install pre-commit if not already installed
    
    Returns:
        True if installation was successful, False otherwise
    """
    try:
        # First check if pre-commit is already installed
        subprocess.run(['pre-commit', '--version'], 
                     stdout=subprocess.PIPE, 
                     stderr=subprocess.PIPE,
                     check=True)
        print("✓ pre-commit is already installed")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Installing pre-commit...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'pre-commit'], 
                         check=True)
            print("✓ pre-commit successfully installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install pre-commit: {e}")
            return False


def install_security_tools() -> bool:
    """
    Install required security tools for the hooks
    
    Returns:
        True if all installations were successful, False otherwise
    """
    tools = [
        'safety',        # For checking dependencies
        'bandit',        # For SAST
        'gitleaks',      # For secrets detection
        'semgrep',       # For code pattern analysis
        'pyyaml'         # For YAML parsing
    ]
    
    all_installed = True
    for tool in tools:
        try:
            print(f"Installing {tool}...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', tool], 
                         check=True)
            print(f"✓ {tool} successfully installed")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {tool}: {e}")
            all_installed = False
    
    return all_installed


def setup_pre_commit_hooks() -> bool:
    """
    Set up pre-commit hooks using the config file
    
    Returns:
        True if hooks were successfully set up, False otherwise
    """
    try:
        # Check if .pre-commit-config.yaml exists
        config_file = Path('.pre-commit-config.yaml')
        if not config_file.exists():
            print("❌ .pre-commit-config.yaml not found in the current directory")
            return False
        
        # Install the hooks
        print("Setting up pre-commit hooks...")
        subprocess.run(['pre-commit', 'install'], check=True)
        print("✓ Pre-commit hooks successfully installed")
        
        # Validate the setup
        print("Validating hooks configuration...")
        subprocess.run(['pre-commit', 'autoupdate'], check=True)
        print("✓ Pre-commit hooks configuration is valid")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to set up pre-commit hooks: {e}")
        return False


def run_initial_checks() -> bool:
    """
    Run initial checks to make sure hooks are working
    
    Returns:
        True if checks passed, False otherwise
    """
    try:
        print("\nRunning initial hooks check (this may take a while)...")
        result = subprocess.run(['pre-commit', 'run', '--all-files'], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE,
                             text=True)
        
        # Print the output for visibility
        print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        if result.returncode == 0:
            print("✓ All checks passed! Your project is now set up with security policy hooks.")
            return True
        else:
            print("⚠ Some checks failed. This is normal if you're setting up hooks on an existing project.")
            print("  Review the output above and fix any issues before committing.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to run initial checks: {e}")
        return False


def main():
    """Main function"""
    print("="*70)
    print("Security Policy Hooks Setup")
    print("="*70)
    print("This script will set up pre-commit hooks to enforce security policies.")
    print()
    
    # Check we're in the right directory
    if not os.path.isdir('.git'):
        print("❌ This doesn't appear to be a git repository.")
        print("   Please run this script from the root of your git repository.")
        return 1
    
    # Check prerequisites
    all_installed, missing_tools = check_prerequisites()
    if not all_installed:
        print(f"❌ Missing required tools: {', '.join(missing_tools)}")
        print("   Please install these tools before continuing.")
        return 1
    
    # Install pre-commit
    if not install_pre_commit():
        print("❌ Failed to install pre-commit. Aborting setup.")
        return 1
    
    # Install security tools
    print("\nInstalling security tools for the hooks...")
    if not install_security_tools():
        print("⚠ Some security tools failed to install.")
        proceed = input("Do you want to continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            print("Setup aborted.")
            return 1
    
    # Set up hooks
    if not setup_pre_commit_hooks():
        print("❌ Failed to set up pre-commit hooks. Aborting setup.")
        return 1
    
    # Run initial checks
    run_initial_checks()
    
    print("\n"+"="*70)
    print("Setup Complete!")
    print("="*70)
    print("Security policy hooks are now installed and will run before each commit.")
    print("To bypass hooks temporarily (NOT RECOMMENDED): git commit --no-verify")
    print("To run hooks manually: pre-commit run --all-files")
    print("\nEnjoy your enhanced security posture! 🔒")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 