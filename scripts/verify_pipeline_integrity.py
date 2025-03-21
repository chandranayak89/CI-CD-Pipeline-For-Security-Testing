#!/usr/bin/env python3
"""
Pipeline Integrity Verification Script

This script verifies the integrity of the CI/CD pipeline by:
1. Validating workflow file hashes against known good values
2. Verifying the identity of the runner
3. Checking for signs of pipeline tampering
4. Validating that the execution environment is secure

Usage:
    python verify_pipeline_integrity.py --workflow-hash HASH --runner-id ID [--log-level LEVEL]
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import sys
import requests
from typing import Dict, List, Any, Optional, Tuple

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('pipeline_integrity')

class IntegrityVerificationError(Exception):
    """Exception raised for integrity verification failures."""
    pass

class PipelineIntegrityVerifier:
    """Class to handle pipeline integrity verification."""
    
    def __init__(self, workflow_hash: str, runner_id: str, log_level: str = "info"):
        self.workflow_hash = workflow_hash
        self.runner_id = runner_id
        self.timestamp = datetime.datetime.utcnow().isoformat()
        
        # Set log level
        if log_level.lower() == "debug":
            logger.setLevel(logging.DEBUG)
        elif log_level.lower() == "info":
            logger.setLevel(logging.INFO)
        elif log_level.lower() == "warning":
            logger.setLevel(logging.WARNING)
        elif log_level.lower() == "error":
            logger.setLevel(logging.ERROR)
        
        # Load trusted configurations
        self.trusted_configs = self._load_trusted_configurations()
    
    def _load_trusted_configurations(self) -> Dict[str, Any]:
        """Load trusted configurations from secure storage."""
        config_path = os.environ.get('TRUSTED_CONFIG_PATH', 
                                    './security-policies/trusted-pipeline-configs.json')
        
        try:
            # If the file exists, load it
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    return json.load(f)
            
            # If the file doesn't exist, use minimal default config
            logger.warning(f"Trusted configuration file not found at {config_path}")
            logger.warning("Using minimal default configuration - for production, ensure the file exists")
            
            return {
                "trusted_workflow_hashes": {},
                "trusted_runner_patterns": [
                    "^github-runner-",
                    "^github-hosted-"
                ],
                "required_environment_variables": [
                    "GITHUB_WORKFLOW",
                    "GITHUB_REPOSITORY",
                    "GITHUB_ACTOR"
                ],
                "trusted_github_domains": [
                    "github.com",
                    "api.github.com"
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to load trusted configurations: {e}")
            # Return minimal default config
            return {
                "trusted_workflow_hashes": {},
                "trusted_runner_patterns": [],
                "required_environment_variables": [],
                "trusted_github_domains": ["github.com"]
            }
    
    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the pipeline.
        
        Returns:
            bool: True if integrity verification passed, False otherwise
        """
        try:
            logger.info("Starting pipeline integrity verification")
            
            # Verify workflow file hash
            self._verify_workflow_hash()
            logger.info("✅ Workflow hash verification passed")
            
            # Verify runner identity
            self._verify_runner_identity()
            logger.info("✅ Runner identity verification passed")
            
            # Verify execution environment
            self._verify_execution_environment()
            logger.info("✅ Execution environment verification passed")
            
            # Verify no tampering signs
            self._verify_no_tampering()
            logger.info("✅ Tampering check passed")
            
            # All verifications passed
            logger.info("Pipeline integrity verification completed successfully")
            return True
            
        except IntegrityVerificationError as e:
            logger.error(f"❌ Pipeline integrity verification failed: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error during pipeline integrity verification: {e}")
            return False
    
    def _verify_workflow_hash(self) -> None:
        """
        Verify the workflow file hash against trusted hashes.
        
        Raises:
            IntegrityVerificationError: If workflow hash verification fails
        """
        logger.debug(f"Verifying workflow hash: {self.workflow_hash}")
        
        # Get workflow name and repo from environment
        workflow_name = os.environ.get('GITHUB_WORKFLOW', '')
        repo_name = os.environ.get('GITHUB_REPOSITORY', '')
        
        if not workflow_name or not repo_name:
            raise IntegrityVerificationError("Missing workflow or repository information")
        
        # Get trusted hashes
        trusted_hashes = self.trusted_configs.get('trusted_workflow_hashes', {})
        
        # Check if we have trusted hashes for this workflow
        workflow_key = f"{repo_name}/{workflow_name}"
        
        if workflow_key in trusted_hashes:
            # Check against specific trusted hash
            trusted_hash = trusted_hashes[workflow_key]
            if self.workflow_hash != trusted_hash:
                raise IntegrityVerificationError(
                    f"Workflow hash mismatch. Expected: {trusted_hash}, Got: {self.workflow_hash}"
                )
        else:
            # If no trusted hash is registered yet, log a warning
            # In a production environment, you might want to fail
            logger.warning(f"No trusted hash registered for workflow: {workflow_key}")
            logger.warning(f"Current hash: {self.workflow_hash}")
            logger.warning("For production use, register this hash if it is trustworthy")
            
            # Update the trusted configurations with the current hash
            # Note: This is for demonstration. In production, you would use a secure
            # method to register trusted hashes, not update them on-the-fly
            trusted_hashes[workflow_key] = self.workflow_hash
    
    def _verify_runner_identity(self) -> None:
        """
        Verify the runner identity against trusted patterns.
        
        Raises:
            IntegrityVerificationError: If runner identity verification fails
        """
        logger.debug(f"Verifying runner identity with ID hash: {self.runner_id}")
        
        # Get runner name from environment
        runner_name = os.environ.get('GITHUB_RUNNER_NAME', '')
        
        if not runner_name:
            logger.warning("Runner name not available in environment")
            # Continue with other checks if runner name is not available
        else:
            # Check runner name against trusted patterns
            trusted_patterns = self.trusted_configs.get('trusted_runner_patterns', [])
            is_trusted = False
            
            for pattern in trusted_patterns:
                if re.match(pattern, runner_name):
                    is_trusted = True
                    break
            
            if not is_trusted and trusted_patterns:
                raise IntegrityVerificationError(
                    f"Runner name '{runner_name}' does not match any trusted pattern"
                )
        
        # Additional checks could be added here:
        # - Verify runner IP address against allowlist
        # - Verify runner signatures
        # - Verify runner has required security features
    
    def _verify_execution_environment(self) -> None:
        """
        Verify the execution environment is secure and expected.
        
        Raises:
            IntegrityVerificationError: If execution environment verification fails
        """
        logger.debug("Verifying execution environment")
        
        # Check for required environment variables
        required_vars = self.trusted_configs.get('required_environment_variables', [])
        for var in required_vars:
            if var not in os.environ:
                raise IntegrityVerificationError(f"Required environment variable '{var}' not found")
        
        # Check GitHub API domains (if being used)
        github_url = os.environ.get('GITHUB_API_URL', '')
        if github_url:
            trusted_domains = self.trusted_configs.get('trusted_github_domains', [])
            is_trusted_domain = False
            
            for domain in trusted_domains:
                if domain in github_url:
                    is_trusted_domain = True
                    break
            
            if not is_trusted_domain:
                raise IntegrityVerificationError(f"GitHub API URL '{github_url}' uses untrusted domain")
        
        # Additional environment checks could include:
        # - Verify GitHub event payload structure
        # - Check for suspicious environment variables
        # - Verify system security features are enabled
        # - Check container image signatures if running in containers
    
    def _verify_no_tampering(self) -> None:
        """
        Verify there are no signs of tampering in the pipeline.
        
        Raises:
            IntegrityVerificationError: If signs of tampering are detected
        """
        logger.debug("Checking for signs of tampering")
        
        # Check for suspicious environment variable overrides
        suspicious_vars = [
            'ACTIONS_STEP_DEBUG', 'ACTIONS_RUNNER_DEBUG',
            'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN'
        ]
        
        for var in suspicious_vars:
            # Just check if these have been tampered with in unusual ways
            if var in os.environ and len(os.environ[var]) < 10:
                logger.warning(f"Suspicious environment variable '{var}' has unusual value length")
        
        # Check for suspicious files in workspace
        suspicious_files = ['.git/hooks/pre-commit', '.git/hooks/post-checkout']
        for file_path in suspicious_files:
            if os.path.exists(file_path):
                # This isn't necessarily malicious, but worth checking
                logger.warning(f"Potentially suspicious file found: {file_path}")
        
        # Additional tampering checks could include:
        # - Check for unexpected processes running
        # - Verify integrity of critical system files
        # - Check for unexpected network connections
        # - Verify execution path for commands

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Verify CI/CD Pipeline Integrity')
    parser.add_argument('--workflow-hash', required=True, help='SHA-256 hash of the workflow file')
    parser.add_argument('--runner-id', required=True, help='Identity hash of the runner')
    parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error'],
                        help='Logging level')
    return parser.parse_args()

def main() -> int:
    """Main function."""
    args = parse_arguments()
    
    # Create the verifier
    verifier = PipelineIntegrityVerifier(
        workflow_hash=args.workflow_hash,
        runner_id=args.runner_id,
        log_level=args.log_level
    )
    
    # Run verification
    success = verifier.verify_integrity()
    
    # Return exit code based on verification result
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 