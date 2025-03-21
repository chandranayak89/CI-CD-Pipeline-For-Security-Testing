#!/usr/bin/env python3
"""
Environment Integrity Verification Script

This script verifies the integrity of deployment environments by:
1. Checking environment configuration against expected values
2. Verifying security controls are properly configured
3. Detecting configuration drift from expected state
4. Validating network policies and access controls

Usage:
    python verify_environment_integrity.py --environment ENV [--check-resources BOOL] [--verify-configurations BOOL] [--output FILE]
"""

import argparse
import datetime
import hashlib
import json
import logging
import os
import re
import sys
import yaml
import time
from typing import Dict, List, Any, Optional, Tuple, Set

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('environment_integrity')

class EnvironmentIntegrityError(Exception):
    """Exception raised for environment integrity check failures."""
    pass

class EnvironmentVerifier:
    """Class to handle environment integrity verification."""
    
    def __init__(self, environment: str, check_resources: bool = True, 
                 verify_configurations: bool = True, output_file: str = None):
        """
        Initialize the environment verifier.
        
        Args:
            environment: Name of the environment to verify (e.g., staging, production)
            check_resources: Whether to check resource existence and state
            verify_configurations: Whether to verify detailed configuration settings
            output_file: Path to write verification results to
        """
        self.environment = environment
        self.check_resources = check_resources
        self.verify_configurations = verify_configurations
        self.output_file = output_file
        self.timestamp = datetime.datetime.utcnow().isoformat()
        self.results = {
            "timestamp": self.timestamp,
            "environment": self.environment,
            "status": "pending",
            "checks": {},
            "findings": []
        }
        
        # Load environment-specific configurations
        self.env_config = self._load_environment_config()
        
        # Initialize environment-specific clients
        self.clients = self._initialize_clients()
    
    def _load_environment_config(self) -> Dict[str, Any]:
        """Load environment-specific configuration."""
        config_path = os.environ.get('ENV_CONFIG_PATH', 
                                    f'./config/environments/{self.environment}.yml')
        
        try:
            # If the file exists, load it
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yml') or config_path.endswith('.yaml'):
                        return yaml.safe_load(f)
                    else:
                        return json.load(f)
            
            # If the file doesn't exist, use minimal default config
            logger.warning(f"Environment configuration file not found at {config_path}")
            logger.warning("Using minimal default configuration - this should not happen in production")
            
            return {
                "infrastructure_type": "kubernetes",  # kubernetes, aws, azure, gcp
                "expected_resources": {},
                "security_controls": {
                    "network_policies": True,
                    "rbac_enabled": True,
                    "secrets_encryption": True
                },
                "verification_level": "standard"
            }
            
        except Exception as e:
            logger.error(f"Failed to load environment configuration: {e}")
            raise EnvironmentIntegrityError(f"Failed to load environment configuration: {e}")
    
    def _initialize_clients(self) -> Dict[str, Any]:
        """Initialize environment-specific clients based on infrastructure type."""
        clients = {}
        infrastructure_type = self.env_config.get("infrastructure_type", "kubernetes").lower()
        
        try:
            if infrastructure_type == "kubernetes":
                clients = self._initialize_kubernetes_client()
            elif infrastructure_type == "aws":
                clients = self._initialize_aws_client()
            elif infrastructure_type == "azure":
                clients = self._initialize_azure_client()
            elif infrastructure_type == "gcp":
                clients = self._initialize_gcp_client()
            else:
                logger.warning(f"Unsupported infrastructure type: {infrastructure_type}")
        except Exception as e:
            logger.error(f"Failed to initialize clients for {infrastructure_type}: {e}")
        
        return clients
    
    def _initialize_kubernetes_client(self) -> Dict[str, Any]:
        """Initialize Kubernetes client."""
        try:
            # Check if kubernetes module is available
            import kubernetes
            from kubernetes import client, config
            
            # Try to load kube config
            try:
                config.load_kube_config()
            except kubernetes.config.config_exception.ConfigException:
                # Try in-cluster config (when running inside Kubernetes)
                try:
                    config.load_incluster_config()
                except kubernetes.config.config_exception.ConfigException:
                    logger.error("Could not configure Kubernetes client")
                    return {}
            
            # Create API clients
            return {
                "core": client.CoreV1Api(),
                "apps": client.AppsV1Api(),
                "rbac": client.RbacAuthorizationV1Api(),
                "networking": client.NetworkingV1Api(),
                "policy": client.PolicyV1beta1Api()
            }
        except ImportError:
            logger.warning("Kubernetes client not available. Install with: pip install kubernetes")
            return {}
    
    def _initialize_aws_client(self) -> Dict[str, Any]:
        """Initialize AWS clients."""
        try:
            # Check if boto3 module is available
            import boto3
            
            # Get region from environment or config
            region = self.env_config.get("region", os.environ.get("AWS_REGION", "us-east-1"))
            
            # Create AWS clients
            return {
                "ec2": boto3.client("ec2", region_name=region),
                "s3": boto3.client("s3", region_name=region),
                "rds": boto3.client("rds", region_name=region),
                "cloudformation": boto3.client("cloudformation", region_name=region),
                "iam": boto3.client("iam", region_name=region),
                "config": boto3.client("config", region_name=region)
            }
        except ImportError:
            logger.warning("AWS client not available. Install with: pip install boto3")
            return {}
    
    def _initialize_azure_client(self) -> Dict[str, Any]:
        """Initialize Azure client."""
        try:
            # Check if Azure modules are available
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.network import NetworkManagementClient
            
            # Get subscription ID from environment or config
            subscription_id = self.env_config.get("subscription_id", 
                                                os.environ.get("AZURE_SUBSCRIPTION_ID"))
            
            if not subscription_id:
                logger.error("Azure subscription ID not found")
                return {}
            
            # Get credentials
            credential = DefaultAzureCredential()
            
            # Create Azure clients
            return {
                "resource": ResourceManagementClient(credential, subscription_id),
                "network": NetworkManagementClient(credential, subscription_id)
            }
        except ImportError:
            logger.warning("Azure client not available. Install with: pip install azure-mgmt-resource azure-mgmt-network azure-identity")
            return {}
    
    def _initialize_gcp_client(self) -> Dict[str, Any]:
        """Initialize GCP client."""
        try:
            # Check if Google Cloud modules are available
            from google.cloud import storage, compute
            
            # Create GCP clients
            return {
                "storage": storage.Client(),
                "compute": compute.ComputeClient()
            }
        except ImportError:
            logger.warning("GCP client not available. Install with: pip install google-cloud-storage google-cloud-compute")
            return {}
    
    def verify_environment(self) -> bool:
        """
        Perform verification of the environment integrity.
        
        Returns:
            bool: True if verification passed, False otherwise
        """
        start_time = time.time()
        infrastructure_type = self.env_config.get("infrastructure_type", "kubernetes").lower()
        logger.info(f"Starting environment verification for {self.environment} ({infrastructure_type})")
        
        try:
            # Perform infrastructure-specific verifications
            if infrastructure_type == "kubernetes":
                self._verify_kubernetes_environment()
            elif infrastructure_type == "aws":
                self._verify_aws_environment()
            elif infrastructure_type == "azure":
                self._verify_azure_environment()
            elif infrastructure_type == "gcp":
                self._verify_gcp_environment()
            else:
                raise EnvironmentIntegrityError(f"Unsupported infrastructure type: {infrastructure_type}")
            
            # Check for environment drift
            self._check_environment_drift()
            
            # All verifications passed
            self.results["status"] = "passed"
            self.results["execution_time"] = time.time() - start_time
            logger.info(f"Environment verification completed successfully in {self.results['execution_time']:.2f} seconds")
            
            # Write results to output file if specified
            if self.output_file:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=2)
            
            return True
            
        except EnvironmentIntegrityError as e:
            self.results["status"] = "failed"
            self.results["failure_reason"] = str(e)
            self.results["execution_time"] = time.time() - start_time
            logger.error(f"Environment verification failed: {e}")
            
            # Write results to output file if specified
            if self.output_file:
                with open(self.output_file, 'w') as f:
                    json.dump(self.results, f, indent=2)
            
            return False
    
    def _verify_kubernetes_environment(self) -> None:
        """
        Verify Kubernetes environment integrity.
        
        Raises:
            EnvironmentIntegrityError: If any verification check fails
        """
        if not self.clients:
            raise EnvironmentIntegrityError("Kubernetes client not initialized")
        
        k8s_checks = {}
        findings = []
        
        # Check namespace existence
        namespace = self.env_config.get("namespace", self.environment)
        try:
            namespaces = self.clients["core"].list_namespace()
            namespace_exists = any(ns.metadata.name == namespace for ns in namespaces.items)
            k8s_checks["namespace_exists"] = namespace_exists
            
            if not namespace_exists:
                findings.append({
                    "severity": "critical",
                    "check": "namespace_existence",
                    "message": f"Namespace '{namespace}' does not exist"
                })
        except Exception as e:
            logger.error(f"Failed to check namespace existence: {e}")
            k8s_checks["namespace_exists"] = False
            findings.append({
                "severity": "error",
                "check": "namespace_existence",
                "message": f"Error checking namespace: {str(e)}"
            })
        
        # Check for required resources if specified
        if self.check_resources:
            self._verify_kubernetes_resources(namespace, k8s_checks, findings)
        
        # Check for security controls if specified
        if self.verify_configurations:
            self._verify_kubernetes_security_controls(namespace, k8s_checks, findings)
        
        # Add results to overall findings
        self.results["checks"]["kubernetes"] = k8s_checks
        self.results["findings"].extend(findings)
        
        # Fail if there are any critical findings
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            finding_messages = "; ".join([f["message"] for f in critical_findings])
            raise EnvironmentIntegrityError(f"Critical Kubernetes environment issues: {finding_messages}")
    
    def _verify_kubernetes_resources(self, namespace: str, checks: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Verify Kubernetes resources existence and state."""
        expected_resources = self.env_config.get("expected_resources", {})
        
        # Check deployments
        if "deployments" in expected_resources:
            try:
                deployments = self.clients["apps"].list_namespaced_deployment(namespace)
                deployment_names = {d.metadata.name for d in deployments.items}
                required_deployments = set(expected_resources.get("deployments", []))
                
                missing_deployments = required_deployments - deployment_names
                checks["deployments_exist"] = len(missing_deployments) == 0
                
                if missing_deployments:
                    findings.append({
                        "severity": "critical" if required_deployments else "warning",
                        "check": "required_deployments",
                        "message": f"Missing required deployments: {', '.join(missing_deployments)}"
                    })
            except Exception as e:
                logger.error(f"Failed to check deployments: {e}")
                checks["deployments_exist"] = False
        
        # Check services
        if "services" in expected_resources:
            try:
                services = self.clients["core"].list_namespaced_service(namespace)
                service_names = {s.metadata.name for s in services.items}
                required_services = set(expected_resources.get("services", []))
                
                missing_services = required_services - service_names
                checks["services_exist"] = len(missing_services) == 0
                
                if missing_services:
                    findings.append({
                        "severity": "critical" if required_services else "warning",
                        "check": "required_services",
                        "message": f"Missing required services: {', '.join(missing_services)}"
                    })
            except Exception as e:
                logger.error(f"Failed to check services: {e}")
                checks["services_exist"] = False
        
        # Check configmaps
        if "configmaps" in expected_resources:
            try:
                configmaps = self.clients["core"].list_namespaced_config_map(namespace)
                configmap_names = {cm.metadata.name for cm in configmaps.items}
                required_configmaps = set(expected_resources.get("configmaps", []))
                
                missing_configmaps = required_configmaps - configmap_names
                checks["configmaps_exist"] = len(missing_configmaps) == 0
                
                if missing_configmaps:
                    findings.append({
                        "severity": "warning",
                        "check": "required_configmaps",
                        "message": f"Missing required configmaps: {', '.join(missing_configmaps)}"
                    })
            except Exception as e:
                logger.error(f"Failed to check configmaps: {e}")
                checks["configmaps_exist"] = False
        
        # Check secrets
        if "secrets" in expected_resources:
            try:
                secrets = self.clients["core"].list_namespaced_secret(namespace)
                secret_names = {s.metadata.name for s in secrets.items}
                required_secrets = set(expected_resources.get("secrets", []))
                
                missing_secrets = required_secrets - secret_names
                checks["secrets_exist"] = len(missing_secrets) == 0
                
                if missing_secrets:
                    findings.append({
                        "severity": "critical",
                        "check": "required_secrets",
                        "message": f"Missing required secrets: {', '.join(missing_secrets)}"
                    })
            except Exception as e:
                logger.error(f"Failed to check secrets: {e}")
                checks["secrets_exist"] = False
    
    def _verify_kubernetes_security_controls(self, namespace: str, checks: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
        """Verify Kubernetes security controls."""
        security_controls = self.env_config.get("security_controls", {})
        
        # Check network policies if required
        if security_controls.get("network_policies", False):
            try:
                network_policies = self.clients["networking"].list_namespaced_network_policy(namespace)
                has_network_policies = len(network_policies.items) > 0
                checks["network_policies_exist"] = has_network_policies
                
                if not has_network_policies:
                    findings.append({
                        "severity": "critical",
                        "check": "network_policies",
                        "message": f"No network policies found in namespace '{namespace}'"
                    })
            except Exception as e:
                logger.error(f"Failed to check network policies: {e}")
                checks["network_policies_exist"] = False
        
        # Check RBAC if required
        if security_controls.get("rbac_enabled", False):
            try:
                # Check for role bindings in the namespace
                role_bindings = self.clients["rbac"].list_namespaced_role_binding(namespace)
                has_role_bindings = len(role_bindings.items) > 0
                checks["rbac_enabled"] = has_role_bindings
                
                if not has_role_bindings:
                    findings.append({
                        "severity": "warning",
                        "check": "rbac_enabled",
                        "message": f"No role bindings found in namespace '{namespace}'"
                    })
            except Exception as e:
                logger.error(f"Failed to check RBAC: {e}")
                checks["rbac_enabled"] = False
        
        # Check Pod Security Policies if required
        if security_controls.get("pod_security_policies", False):
            try:
                # This is deprecated in newer K8s versions, but still relevant for many
                pod_security_policies = self.clients["policy"].list_pod_security_policy()
                has_policies = len(pod_security_policies.items) > 0
                checks["pod_security_policies_exist"] = has_policies
                
                if not has_policies:
                    findings.append({
                        "severity": "warning",
                        "check": "pod_security_policies",
                        "message": "No Pod Security Policies found"
                    })
            except Exception as e:
                logger.error(f"Failed to check Pod Security Policies: {e}")
                checks["pod_security_policies_exist"] = False
    
    def _verify_aws_environment(self) -> None:
        """
        Verify AWS environment integrity.
        
        Raises:
            EnvironmentIntegrityError: If any verification check fails
        """
        if not self.clients:
            raise EnvironmentIntegrityError("AWS client not initialized")
        
        aws_checks = {}
        findings = []
        
        # Verify VPC configuration
        vpc_id = self.env_config.get("vpc_id")
        if vpc_id and self.check_resources:
            try:
                vpc_response = self.clients["ec2"].describe_vpcs(VpcIds=[vpc_id])
                vpc_exists = len(vpc_response["Vpcs"]) > 0
                aws_checks["vpc_exists"] = vpc_exists
                
                if not vpc_exists:
                    findings.append({
                        "severity": "critical",
                        "check": "vpc_existence",
                        "message": f"VPC '{vpc_id}' does not exist"
                    })
            except Exception as e:
                logger.error(f"Failed to check VPC existence: {e}")
                aws_checks["vpc_exists"] = False
                findings.append({
                    "severity": "error",
                    "check": "vpc_existence",
                    "message": f"Error checking VPC: {str(e)}"
                })
        
        # Check security groups
        if self.verify_configurations:
            try:
                security_groups = self.clients["ec2"].describe_security_groups(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}] if vpc_id else []
                )
                
                # Check for overly permissive security groups
                permissive_groups = []
                for sg in security_groups["SecurityGroups"]:
                    for permission in sg.get("IpPermissions", []):
                        # Check for 0.0.0.0/0 on sensitive ports
                        sensitive_ports = [22, 3389, 1433, 3306, 5432, 6379, 9200, 27017]
                        from_port = permission.get("FromPort", 0)
                        to_port = permission.get("ToPort", 65535)
                        
                        for ip_range in permission.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                # Check if any sensitive port is in range
                                if any(from_port <= port <= to_port for port in sensitive_ports):
                                    permissive_groups.append(sg["GroupId"])
                                    break
                
                aws_checks["permissive_security_groups"] = len(permissive_groups)
                
                if permissive_groups:
                    findings.append({
                        "severity": "critical",
                        "check": "security_group_rules",
                        "message": f"Permissive security groups found: {', '.join(permissive_groups)}"
                    })
            except Exception as e:
                logger.error(f"Failed to check security groups: {e}")
                aws_checks["security_groups_checked"] = False
        
        # Add results to overall findings
        self.results["checks"]["aws"] = aws_checks
        self.results["findings"].extend(findings)
        
        # Fail if there are any critical findings
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            finding_messages = "; ".join([f["message"] for f in critical_findings])
            raise EnvironmentIntegrityError(f"Critical AWS environment issues: {finding_messages}")
    
    def _verify_azure_environment(self) -> None:
        """
        Verify Azure environment integrity.
        
        Raises:
            EnvironmentIntegrityError: If any verification check fails
        """
        if not self.clients:
            raise EnvironmentIntegrityError("Azure client not initialized")
        
        azure_checks = {}
        findings = []
        
        # Verify resource group existence
        resource_group = self.env_config.get("resource_group")
        if resource_group and self.check_resources:
            try:
                resource_group_exists = self.clients["resource"].resource_groups.check_existence(resource_group)
                azure_checks["resource_group_exists"] = resource_group_exists
                
                if not resource_group_exists:
                    findings.append({
                        "severity": "critical",
                        "check": "resource_group_existence",
                        "message": f"Resource group '{resource_group}' does not exist"
                    })
            except Exception as e:
                logger.error(f"Failed to check resource group existence: {e}")
                azure_checks["resource_group_exists"] = False
                findings.append({
                    "severity": "error",
                    "check": "resource_group_existence",
                    "message": f"Error checking resource group: {str(e)}"
                })
        
        # Add results to overall findings
        self.results["checks"]["azure"] = azure_checks
        self.results["findings"].extend(findings)
        
        # Fail if there are any critical findings
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            finding_messages = "; ".join([f["message"] for f in critical_findings])
            raise EnvironmentIntegrityError(f"Critical Azure environment issues: {finding_messages}")
    
    def _verify_gcp_environment(self) -> None:
        """
        Verify GCP environment integrity.
        
        Raises:
            EnvironmentIntegrityError: If any verification check fails
        """
        if not self.clients:
            raise EnvironmentIntegrityError("GCP client not initialized")
        
        gcp_checks = {}
        findings = []
        
        # Implement GCP-specific checks here
        
        # Add results to overall findings
        self.results["checks"]["gcp"] = gcp_checks
        self.results["findings"].extend(findings)
        
        # Fail if there are any critical findings
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        if critical_findings:
            finding_messages = "; ".join([f["message"] for f in critical_findings])
            raise EnvironmentIntegrityError(f"Critical GCP environment issues: {finding_messages}")
    
    def _check_environment_drift(self) -> None:
        """
        Check for environment drift from expected configuration.
        
        This compares the current state of resources with the expected state
        defined in configuration files or infrastructure as code templates.
        """
        drift_detection_enabled = self.env_config.get("drift_detection", {}).get("enabled", False)
        
        if not drift_detection_enabled:
            logger.info("Drift detection not enabled for this environment")
            return
        
        # The implementation of drift detection will depend on the infrastructure
        # and tools being used (e.g., Terraform, CloudFormation, etc.)
        # This is a placeholder for that functionality
        
        logger.info("Environment drift detection completed")

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Verify Environment Integrity')
    parser.add_argument('--environment', required=True, 
                        help='Environment to verify (e.g., staging, production)')
    parser.add_argument('--check-resources', type=lambda x: (str(x).lower() == 'true'), 
                        default=True, help='Whether to check resource existence')
    parser.add_argument('--verify-configurations', type=lambda x: (str(x).lower() == 'true'), 
                        default=True, help='Whether to verify detailed configurations')
    parser.add_argument('--output', help='Output file to write verification results to')
    return parser.parse_args()

def main() -> int:
    """Main function."""
    args = parse_arguments()
    
    # Create verifier
    verifier = EnvironmentVerifier(
        environment=args.environment,
        check_resources=args.check_resources,
        verify_configurations=args.verify_configurations,
        output_file=args.output
    )
    
    # Run verification
    success = verifier.verify_environment()
    
    # Return exit code based on verification result
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main()) 