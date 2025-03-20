#!/usr/bin/env python3
"""
Generate a dependency lock file to ensure consistent dependency versions.
This script creates a pip-based lock file (requirements.lock) that pins all
dependencies (including transitive dependencies) to specific versions.
"""

import subprocess
import sys
import os
import json
import argparse
from pathlib import Path
import datetime

def setup_argparse():
    """Set up argument parser."""
    parser = argparse.ArgumentParser(description='Generate dependency lock file')
    parser.add_argument('--requirements', default='requirements.txt',
                        help='Path to requirements.txt file')
    parser.add_argument('--output', default='requirements.lock',
                        help='Path to output lock file')
    parser.add_argument('--json', action='store_true',
                        help='Also generate a JSON format lock file')
    parser.add_argument('--check', action='store_true',
                        help='Check if lock file is up to date with requirements')
    return parser

def get_installed_dependencies():
    """Get all installed dependencies and their versions."""
    try:
        result = subprocess.run(
            ['pip', 'freeze'], 
            capture_output=True, 
            text=True, 
            check=True
        )
        dependencies = {}
        
        for line in result.stdout.splitlines():
            if '==' in line:
                name, version = line.split('==')
                dependencies[name.lower()] = {
                    'version': version,
                    'line': line
                }
        
        return dependencies
    except subprocess.CalledProcessError as e:
        print(f"Error getting installed dependencies: {e}")
        return {}

def get_dependencies_from_requirements(requirements_file):
    """Parse requirements file to get direct dependencies."""
    direct_dependencies = set()
    try:
        with open(requirements_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    # Handle different requirement formats
                    for sep in ['==', '>=', '<=', '~=', '>', '<', '!=']:
                        if sep in line:
                            name = line.split(sep)[0].strip().lower()
                            direct_dependencies.add(name)
                            break
                    else:
                        # No version specifier, just the package name
                        direct_dependencies.add(line.lower())
        
        return direct_dependencies
    except FileNotFoundError:
        print(f"Requirements file not found: {requirements_file}")
        return set()

def get_dependency_tree():
    """Get dependency tree to identify direct and transitive dependencies."""
    try:
        result = subprocess.run(
            ['pip', 'list', '--format=json'], 
            capture_output=True, 
            text=True, 
            check=True
        )
        packages = json.loads(result.stdout)
        
        dependencies = {}
        for package in packages:
            name = package['name'].lower()
            version = package['version']
            
            # Try to get package dependencies
            try:
                dep_result = subprocess.run(
                    ['pip', 'show', package['name']], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                
                # Parse dependencies from pip show output
                requires = []
                for line in dep_result.stdout.splitlines():
                    if line.startswith('Requires:'):
                        requires_str = line[len('Requires:'):].strip()
                        if requires_str:
                            requires = [r.strip().lower() for r in requires_str.split(',')]
                        break
                
                dependencies[name] = {
                    'version': version,
                    'dependencies': requires
                }
            except subprocess.CalledProcessError:
                dependencies[name] = {
                    'version': version,
                    'dependencies': []
                }
        
        return dependencies
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"Error getting dependency tree: {e}")
        return {}

def generate_lockfile(requirements_file, output_file, json_output=False):
    """Generate a lock file based on installed dependencies."""
    # First install all requirements
    try:
        print(f"Installing dependencies from {requirements_file}...")
        subprocess.run(
            ['pip', 'install', '-r', requirements_file],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False
    
    # Get direct dependencies from requirements file
    direct_deps = get_dependencies_from_requirements(requirements_file)
    
    # Get all installed dependencies
    all_deps = get_installed_dependencies()
    
    # Get dependency tree
    dep_tree = get_dependency_tree()
    
    # Generate timestamp
    timestamp = datetime.datetime.now().isoformat()
    
    # Write lock file
    try:
        with open(output_file, 'w') as f:
            f.write(f"# Generated by dependency locker on {timestamp}\n")
            f.write("# DO NOT EDIT THIS FILE DIRECTLY\n\n")
            
            # Write direct dependencies first
            f.write("# Direct dependencies\n")
            for name in sorted(direct_deps):
                if name in all_deps:
                    f.write(f"{all_deps[name]['line']}\n")
            
            # Write transitive dependencies
            f.write("\n# Transitive dependencies\n")
            for name, info in sorted(all_deps.items()):
                if name not in direct_deps:
                    f.write(f"{info['line']}\n")
        
        print(f"Lock file generated at {output_file}")
        
        # Generate JSON format if requested
        if json_output:
            json_file = os.path.splitext(output_file)[0] + '.json'
            
            json_data = {
                'metadata': {
                    'generated_at': timestamp,
                    'requirements_file': requirements_file
                },
                'dependencies': {}
            }
            
            # Add all dependencies to JSON data
            for name, info in sorted(all_deps.items()):
                is_direct = name in direct_deps
                
                json_data['dependencies'][name] = {
                    'version': info['version'],
                    'is_direct': is_direct,
                    'dependencies': dep_tree.get(name, {}).get('dependencies', [])
                }
            
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            print(f"JSON lock file generated at {json_file}")
        
        return True
    except Exception as e:
        print(f"Error generating lock file: {e}")
        return False

def check_lockfile(requirements_file, lock_file):
    """Check if lock file is up to date with requirements."""
    if not os.path.exists(lock_file):
        print(f"Lock file {lock_file} does not exist")
        return False
    
    # Get direct dependencies from requirements file
    direct_deps = get_dependencies_from_requirements(requirements_file)
    
    # Get dependencies from lock file
    lock_deps = set()
    try:
        with open(lock_file, 'r') as f:
            in_direct_section = False
            for line in f:
                line = line.strip()
                if line.startswith("# Direct dependencies"):
                    in_direct_section = True
                    continue
                elif line.startswith("# Transitive dependencies"):
                    in_direct_section = False
                    continue
                
                if in_direct_section and line and not line.startswith('#'):
                    if '==' in line:
                        name = line.split('==')[0].strip().lower()
                        lock_deps.add(name)
    except FileNotFoundError:
        print(f"Lock file not found: {lock_file}")
        return False
    
    # Check if all direct dependencies are in lock file
    missing_deps = direct_deps - lock_deps
    if missing_deps:
        print(f"Lock file is missing these dependencies: {', '.join(missing_deps)}")
        return False
    
    # Check if lock file has extra direct dependencies
    extra_deps = lock_deps - direct_deps
    if extra_deps:
        print(f"Lock file has extra dependencies: {', '.join(extra_deps)}")
        return False
    
    print("Lock file is up to date with requirements")
    return True

def main():
    """Main function."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    if args.check:
        if check_lockfile(args.requirements, args.output):
            return 0
        else:
            return 1
    else:
        if generate_lockfile(args.requirements, args.output, args.json):
            return 0
        else:
            return 1

if __name__ == "__main__":
    sys.exit(main()) 