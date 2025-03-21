#!/usr/bin/env python3
"""
Supply Chain Verification Script

This script verifies the integrity of the software supply chain by:
1. Validating the integrity of dependencies
2. Verifying artifact signatures
3. Checking container image provenance
4. Validating SBOMs for completeness
5. Ensuring compliance with supply chain policies

Integration with secrets_manager.py for secure handling of verification keys.
"""

import argparse
import datetime
import glob
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import uuid
import yaml
from typing import Dict, List, Tuple, Optional, Any, Set

# Try to import our secrets manager
try:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scripts.secretes_manager import SecretsManager, Secret, SecretType, SecretSeverity
except ImportError:
    print("Warning: Could not import SecretsManager. Limited functionality available.")
    SecretsManager = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("supply-chain-verifier")

class VerificationError(Exception):
    """Exception raised for verification failures."""
    pass

class SupplyChainVerifier:
    """
    Main class for verifying the software supply chain integrity.
    """
    
    def __init__(self, policy_file: str, secrets_manager: Optional[Any] = None):
        """
        Initialize the verifier with policy and optional secrets manager.
        
        Args:
            policy_file: Path to the policy configuration YAML file
            secrets_manager: Optional SecretsManager instance
        """
        self.policy_file = policy_file
        self.secrets_manager = secrets_manager
        self.policy = self._load_policy()
        self.verification_results = {
            "passed": True,
            "timestamp": datetime.datetime.now().isoformat(),
            "verification_id": str(uuid.uuid4()),
            "results": {},
            "summary": {
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "critical_failures": 0
            }
        }
    
    def _load_policy(self) -> Dict:
        """Load and validate the policy configuration."""
        try:
            with open(self.policy_file, 'r') as f:
                policy = yaml.safe_load(f)
            
            # Validate policy schema - minimal validation here
            required_sections = ['general', 'dependency_management', 'artifact_signing']
            for section in required_sections:
                if section not in policy:
                    raise ValueError(f"Missing required policy section: {section}")
            
            return policy
        except Exception as e:
            logger.error(f"Failed to load policy file: {str(e)}")
            raise
    
    def _record_result(self, check_name: str, passed: bool, details: Dict = None) -> None:
        """
        Record the result of a verification check.
        
        Args:
            check_name: Name of the verification check
            passed: Whether the check passed or failed
            details: Additional details about the check
        """
        if details is None:
            details = {}
        
        result = {
            "passed": passed,
            "timestamp": datetime.datetime.now().isoformat(),
            "details": details
        }
        
        self.verification_results["results"][check_name] = result
        self.verification_results["summary"]["total_checks"] += 1
        
        if passed:
            self.verification_results["summary"]["passed_checks"] += 1
        else:
            self.verification_results["summary"]["failed_checks"] += 1
            self.verification_results["passed"] = False
            
            # Check if this is a critical failure
            if details.get("severity") == "critical":
                self.verification_results["summary"]["critical_failures"] += 1
    
    def verify_dependency_integrity(self, lockfile_path: str) -> bool:
        """
        Verify the integrity of dependencies in a lockfile.
        
        Args:
            lockfile_path: Path to the lockfile (e.g., Pipfile.lock, package-lock.json)
            
        Returns:
            bool: True if dependency verification passed, False otherwise
        """
        logger.info(f"Verifying dependencies in {lockfile_path}")
        
        try:
            # Determine lockfile type
            if lockfile_path.endswith(".lock"):
                if os.path.basename(lockfile_path) == "Pipfile.lock":
                    lockfile_type = "pipfile"
                elif os.path.basename(lockfile_path) == "poetry.lock":
                    lockfile_type = "poetry"
                else:
                    lockfile_type = "unknown"
            elif lockfile_path.endswith("package-lock.json"):
                lockfile_type = "npm"
            else:
                lockfile_type = "unknown"
            
            # Load the lockfile
            with open(lockfile_path, 'r') as f:
                lockfile_data = json.load(f)
            
            violations = []
            allowed_sources = set()
            for source in self.policy["dependency_management"]["allowed_sources"]:
                allowed_sources.add(source["url"])
            
            # Check each dependency for hash verification and source
            if lockfile_type == "pipfile":
                hashes_missing = []
                sources_disallowed = []
                
                for _, package_data in lockfile_data.get("default", {}).items():
                    if "hashes" not in package_data and self.policy["dependency_management"]["lockfile_requirements"].get("require_hashes", False):
                        hashes_missing.append(package_data.get("name", "unknown"))
                    
                    source = package_data.get("index")
                    if source and source not in allowed_sources:
                        sources_disallowed.append((package_data.get("name", "unknown"), source))
                
                if hashes_missing:
                    violations.append(f"Missing hashes for {len(hashes_missing)} packages")
                
                if sources_disallowed:
                    violations.append(f"Disallowed sources for {len(sources_disallowed)} packages")
            
            # Add checks for other lockfile types here
            
            # Record the result
            passed = len(violations) == 0
            details = {
                "lockfile_type": lockfile_type,
                "violations": violations,
                "total_dependencies": len(lockfile_data.get("default", {})),
                "severity": "critical" if not passed else "info"
            }
            
            self._record_result(
                check_name="dependency_integrity", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify dependency integrity: {str(e)}")
            self._record_result(
                check_name="dependency_integrity",
                passed=False,
                details={"error": str(e), "severity": "critical"}
            )
            return False
    
    def verify_sbom(self, sbom_file: str) -> bool:
        """
        Verify a Software Bill of Materials (SBOM) for completeness and accuracy.
        
        Args:
            sbom_file: Path to the SBOM file (e.g., cyclonedx or SPDX format)
            
        Returns:
            bool: True if SBOM verification passed, False otherwise
        """
        logger.info(f"Verifying SBOM in {sbom_file}")
        
        try:
            # Determine SBOM format
            with open(sbom_file, 'r') as f:
                sbom_data = json.load(f)
            
            # Check for CycloneDX format
            if "bomFormat" in sbom_data and sbom_data["bomFormat"] == "CycloneDX":
                sbom_format = "cyclonedx"
            # Check for SPDX format
            elif "spdxVersion" in sbom_data:
                sbom_format = "spdx"
            else:
                sbom_format = "unknown"
            
            violations = []
            
            # Verify minimum components
            min_components = self.policy["dependency_management"]["sbom_requirements"].get("minimum_components", 1)
            if sbom_format == "cyclonedx":
                components = sbom_data.get("components", [])
                if len(components) < min_components:
                    violations.append(f"SBOM has fewer components than required ({len(components)} < {min_components})")
            
            # Verify required metadata
            if sbom_format == "cyclonedx":
                required_metadata = ["timestamp", "authors"]
                metadata = sbom_data.get("metadata", {})
                for field in required_metadata:
                    if field not in metadata:
                        violations.append(f"Missing required metadata field: {field}")
            
            # Record the result
            passed = len(violations) == 0
            details = {
                "sbom_format": sbom_format,
                "violations": violations,
                "component_count": len(sbom_data.get("components", [])) if sbom_format == "cyclonedx" else "unknown",
                "severity": "high" if not passed else "info"
            }
            
            self._record_result(
                check_name="sbom_verification", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify SBOM: {str(e)}")
            self._record_result(
                check_name="sbom_verification",
                passed=False,
                details={"error": str(e), "severity": "high"}
            )
            return False
    
    def verify_artifact_signatures(self, artifacts_dir: str, signatures_dir: str = None) -> bool:
        """
        Verify cryptographic signatures of build artifacts.
        
        Args:
            artifacts_dir: Directory containing the build artifacts
            signatures_dir: Directory containing signature files (defaults to artifacts_dir)
            
        Returns:
            bool: True if signature verification passed, False otherwise
        """
        logger.info(f"Verifying artifact signatures in {artifacts_dir}")
        
        if signatures_dir is None:
            signatures_dir = artifacts_dir
        
        try:
            # Find all artifacts and their signatures
            artifacts = glob.glob(os.path.join(artifacts_dir, "*"))
            artifacts = [a for a in artifacts if not a.endswith('.sig')]
            
            verification_failures = []
            verification_successes = []
            
            # Get verification key from secrets manager
            verification_key = None
            key_path = None
            
            if self.secrets_manager:
                try:
                    with tempfile.NamedTemporaryFile(delete=False) as key_file:
                        key_path = key_file.name
                        verification_key_data = self.secrets_manager.get_secret("ARTIFACT_VERIFICATION_KEY").value
                        key_file.write(verification_key_data.encode('utf-8'))
                except Exception as e:
                    logger.warning(f"Failed to get verification key from secrets manager: {str(e)}")
                    key_path = "verification-key.pem"  # Fallback to looking for key file
            else:
                key_path = "verification-key.pem"
            
            # Verify each artifact
            for artifact in artifacts:
                artifact_name = os.path.basename(artifact)
                signature_file = os.path.join(signatures_dir, f"{artifact_name}.sig")
                
                if not os.path.exists(signature_file):
                    verification_failures.append({
                        "artifact": artifact_name,
                        "reason": "Signature file not found"
                    })
                    continue
                
                # Verify with cosign if available
                try:
                    result = subprocess.run(
                        ["cosign", "verify-blob", "--key", key_path, "--signature", signature_file, artifact],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode == 0:
                        verification_successes.append(artifact_name)
                    else:
                        verification_failures.append({
                            "artifact": artifact_name,
                            "reason": f"Signature verification failed: {result.stderr}"
                        })
                except Exception as e:
                    logger.warning(f"Failed to use cosign for verification: {str(e)}")
                    
                    # Fallback to manual verification if cosign is not available
                    # This is a simple placeholder for demonstration purposes
                    verification_failures.append({
                        "artifact": artifact_name,
                        "reason": "Cosign not available, manual verification not implemented"
                    })
            
            # Clean up temporary key file if created
            if verification_key and os.path.exists(key_path):
                os.unlink(key_path)
            
            # Record the result
            passed = len(verification_failures) == 0 and len(verification_successes) > 0
            details = {
                "verified_artifacts": verification_successes,
                "verification_failures": verification_failures,
                "total_artifacts": len(artifacts),
                "severity": "critical" if not passed else "info"
            }
            
            self._record_result(
                check_name="artifact_signature_verification", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify artifact signatures: {str(e)}")
            self._record_result(
                check_name="artifact_signature_verification",
                passed=False,
                details={"error": str(e), "severity": "critical"}
            )
            return False
    
    def verify_container_provenance(self, image_name: str, sbom_file: str = None) -> bool:
        """
        Verify the provenance of a container image.
        
        Args:
            image_name: Name of the container image to verify
            sbom_file: Optional path to SBOM file
            
        Returns:
            bool: True if container provenance verification passed, False otherwise
        """
        logger.info(f"Verifying container provenance for {image_name}")
        
        try:
            violations = []
            
            # Verify image exists
            result = subprocess.run(
                ["docker", "image", "inspect", image_name],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                violations.append(f"Container image {image_name} not found")
                
                self._record_result(
                    check_name="container_provenance",
                    passed=False,
                    details={
                        "violations": violations,
                        "severity": "critical"
                    }
                )
                return False
            
            image_info = json.loads(result.stdout)
            
            # Check base image
            if len(image_info) > 0 and "Config" in image_info[0]:
                config = image_info[0]["Config"]
                
                # Check for disallowed base images
                base_image = None
                if "Labels" in config and "org.opencontainers.image.base.name" in config["Labels"]:
                    base_image = config["Labels"]["org.opencontainers.image.base.name"]
                
                if base_image:
                    disallowed_base_images = self.policy["container_security"]["base_image_policy"].get("disallowed_base_images", [])
                    for disallowed in disallowed_base_images:
                        if re.match(disallowed, base_image):
                            violations.append(f"Base image {base_image} matches disallowed pattern {disallowed}")
            
            # Check image signatures if cosign is available
            try:
                # Get verification key from secrets manager
                verification_key = None
                key_path = None
                
                if self.secrets_manager:
                    try:
                        with tempfile.NamedTemporaryFile(delete=False) as key_file:
                            key_path = key_file.name
                            verification_key_data = self.secrets_manager.get_secret("CONTAINER_VERIFICATION_KEY").value
                            key_file.write(verification_key_data.encode('utf-8'))
                    except Exception as e:
                        logger.warning(f"Failed to get container verification key: {str(e)}")
                        key_path = "container-verification-key.pem"  # Fallback
                else:
                    key_path = "container-verification-key.pem"
                
                # Verify container signature
                result = subprocess.run(
                    ["cosign", "verify", "--key", key_path, image_name],
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode != 0:
                    violations.append(f"Container signature verification failed: {result.stderr}")
                
                # Verify SBOM attestation if available
                if sbom_file:
                    result = subprocess.run(
                        ["cosign", "verify-attestation", "--key", key_path, "--type", "sbom", image_name],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode != 0:
                        violations.append(f"SBOM attestation verification failed: {result.stderr}")
                
                # Clean up temporary key file if created
                if verification_key and os.path.exists(key_path):
                    os.unlink(key_path)
                    
            except Exception as e:
                logger.warning(f"Failed to verify container signatures: {str(e)}")
                violations.append(f"Container signature verification failed: {str(e)}")
            
            # Record the result
            passed = len(violations) == 0
            details = {
                "image": image_name,
                "violations": violations,
                "severity": "critical" if not passed else "info"
            }
            
            self._record_result(
                check_name="container_provenance", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify container provenance: {str(e)}")
            self._record_result(
                check_name="container_provenance",
                passed=False,
                details={"error": str(e), "severity": "critical"}
            )
            return False
    
    def verify_build_environment(self, build_info_file: str) -> bool:
        """
        Verify the security of the build environment.
        
        Args:
            build_info_file: Path to build environment information file
            
        Returns:
            bool: True if build environment verification passed, False otherwise
        """
        logger.info(f"Verifying build environment from {build_info_file}")
        
        try:
            # Load build environment info
            with open(build_info_file, 'r') as f:
                build_info = json.load(f)
            
            violations = []
            
            # Check for ephemeral builders
            if self.policy["cicd_security"]["build_environment"].get("require_ephemeral_builders", False):
                if not build_info.get("ephemeral_builder", False):
                    violations.append("Build was not performed on an ephemeral builder")
            
            # Check for network isolation
            if self.policy["cicd_security"]["build_environment"].get("prohibit_network_during_build", False):
                if build_info.get("network_access", False):
                    violations.append("Build had network access when prohibited")
            
            # Check for reproducible builds
            if self.policy["cicd_security"]["build_environment"].get("require_reproducible_builds", False):
                if not build_info.get("reproducible_build", False):
                    violations.append("Build is not reproducible")
            
            # Record the result
            passed = len(violations) == 0
            details = {
                "violations": violations,
                "build_id": build_info.get("build_id", "unknown"),
                "severity": "high" if not passed else "info"
            }
            
            self._record_result(
                check_name="build_environment", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify build environment: {str(e)}")
            self._record_result(
                check_name="build_environment",
                passed=False,
                details={"error": str(e), "severity": "high"}
            )
            return False
    
    def verify_code_signing(self, repo_path: str) -> bool:
        """
        Verify that commits in the repository are properly signed.
        
        Args:
            repo_path: Path to the git repository
            
        Returns:
            bool: True if code signing verification passed, False otherwise
        """
        logger.info(f"Verifying code signing in {repo_path}")
        
        try:
            # Check if the policy requires signed commits
            if not self.policy["code_security"]["branch_protection"].get("require_signed_commits", False):
                # If not required, report as passed but with a note
                self._record_result(
                    check_name="code_signing", 
                    passed=True,
                    details={
                        "message": "Signed commits not required by policy",
                        "severity": "info"
                    }
                )
                return True
            
            # Get recent commits
            result = subprocess.run(
                ["git", "-C", repo_path, "log", "--format=%H %G?", "-n", "10"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse commit signature status
            commits = []
            unsigned_commits = []
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(' ')
                    if len(parts) >= 2:
                        commit_hash = parts[0]
                        signature_status = parts[1]
                        
                        commits.append({
                            "hash": commit_hash,
                            "signed": signature_status in ('G', 'U', 'X', 'Y')
                        })
                        
                        if signature_status not in ('G', 'U', 'X', 'Y'):
                            unsigned_commits.append(commit_hash)
            
            # Record the result
            passed = len(unsigned_commits) == 0
            details = {
                "total_commits_checked": len(commits),
                "unsigned_commits": unsigned_commits,
                "severity": "high" if not passed else "info"
            }
            
            self._record_result(
                check_name="code_signing", 
                passed=passed,
                details=details
            )
            
            return passed
        
        except Exception as e:
            logger.error(f"Failed to verify code signing: {str(e)}")
            self._record_result(
                check_name="code_signing",
                passed=False,
                details={"error": str(e), "severity": "high"}
            )
            return False
    
    def run_all_verifications(self, args: Dict) -> Dict:
        """
        Run all applicable verifications based on provided arguments.
        
        Args:
            args: Dictionary of arguments for verification
            
        Returns:
            Dict: Verification results
        """
        # Track overall verification status
        verification_passed = True
        
        # Run dependency verification if requested
        if args.get("lockfile_path"):
            passed = self.verify_dependency_integrity(args["lockfile_path"])
            verification_passed = verification_passed and passed
        
        # Run SBOM verification if requested
        if args.get("sbom_file"):
            passed = self.verify_sbom(args["sbom_file"])
            verification_passed = verification_passed and passed
        
        # Run artifact verification if requested
        if args.get("artifacts_dir"):
            passed = self.verify_artifact_signatures(
                args["artifacts_dir"], 
                args.get("signatures_dir")
            )
            verification_passed = verification_passed and passed
        
        # Run container verification if requested
        if args.get("container_image"):
            passed = self.verify_container_provenance(
                args["container_image"],
                args.get("container_sbom")
            )
            verification_passed = verification_passed and passed
        
        # Run build environment verification if requested
        if args.get("build_info_file"):
            passed = self.verify_build_environment(args["build_info_file"])
            verification_passed = verification_passed and passed
        
        # Run code signing verification if requested
        if args.get("repo_path"):
            passed = self.verify_code_signing(args["repo_path"])
            verification_passed = verification_passed and passed
        
        # Set the overall status
        self.verification_results["passed"] = verification_passed
        
        # Add timing information
        self.verification_results["end_timestamp"] = datetime.datetime.now().isoformat()
        
        return self.verification_results
    
    def save_results(self, output_file: str) -> None:
        """
        Save verification results to a file.
        
        Args:
            output_file: Path to write results to
        """
        with open(output_file, 'w') as f:
            json.dump(self.verification_results, f, indent=2)
        
        logger.info(f"Verification results saved to {output_file}")
        
        # Report summary to console
        summary = self.verification_results["summary"]
        print("\nSupply Chain Verification Summary:")
        print(f"Total checks: {summary['total_checks']}")
        print(f"Passed checks: {summary['passed_checks']}")
        print(f"Failed checks: {summary['failed_checks']}")
        print(f"Critical failures: {summary['critical_failures']}")
        print(f"Overall status: {'✅ PASSED' if self.verification_results['passed'] else '❌ FAILED'}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Verify software supply chain integrity')
    
    parser.add_argument('--policy', required=True, help='Path to supply chain policy file')
    parser.add_argument('--output', required=True, help='Path to write verification results')
    
    # Dependency verification
    parser.add_argument('--lockfile', help='Path to dependency lockfile')
    
    # SBOM verification
    parser.add_argument('--sbom', help='Path to SBOM file')
    
    # Artifact verification
    parser.add_argument('--artifacts-dir', help='Directory containing build artifacts')
    parser.add_argument('--signatures-dir', help='Directory containing signature files')
    
    # Container verification
    parser.add_argument('--container-image', help='Name of container image to verify')
    parser.add_argument('--container-sbom', help='Path to container SBOM file')
    
    # Build environment verification
    parser.add_argument('--build-info', help='Path to build environment information file')
    
    # Code signing verification
    parser.add_argument('--repo-path', help='Path to git repository')
    
    # Verification level
    parser.add_argument('--level', choices=['minimal', 'standard', 'strict'],
                        default='standard', help='Verification level')
    
    # Secrets retrieval options
    parser.add_argument('--secrets-config', help='Path to secrets manager configuration')
    
    args = parser.parse_args()
    return args

def main():
    """Main function."""
    args = parse_args()
    
    # Initialize secrets manager if available
    secrets_manager = None
    if SecretsManager:
        try:
            secrets_manager = SecretsManager(args.secrets_config)
            logger.info("Initialized secrets manager")
        except Exception as e:
            logger.warning(f"Failed to initialize secrets manager: {str(e)}")
    
    # Initialize the verifier
    verifier = SupplyChainVerifier(args.policy, secrets_manager)
    
    # Prepare arguments for verification
    verification_args = {
        "lockfile_path": args.lockfile,
        "sbom_file": args.sbom,
        "artifacts_dir": args.artifacts_dir,
        "signatures_dir": args.signatures_dir,
        "container_image": args.container_image,
        "container_sbom": args.container_sbom,
        "build_info_file": args.build_info,
        "repo_path": args.repo_path
    }
    
    # Run all applicable verifications
    results = verifier.run_all_verifications(verification_args)
    
    # Save results
    verifier.save_results(args.output)
    
    # Exit with appropriate status code
    if not results["passed"]:
        sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    main() 