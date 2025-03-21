# Supply Chain Security Implementation

This directory contains an implementation of robust supply chain security measures for your CI/CD pipeline, ensuring the integrity, authenticity, and security of your software delivery process.

## Overview

The supply chain security implementation includes:

1. **Dependency Management & Verification**: Ensure dependencies come from trusted sources and contain no vulnerabilities.
2. **Artifact Signing & Verification**: Cryptographically sign and verify build artifacts to prevent tampering.
3. **Software Bill of Materials (SBOM)**: Generate and validate SBOMs to understand software composition.
4. **Container Security**: Verify container image provenance and integrity.
5. **Secure Build Environment**: Ensure builds occur in secure, ephemeral environments.
6. **Integrated Secrets Management**: Securely handle signing keys and credentials.

## Components

### 1. GitHub Actions Workflow

The `supply-chain-security.yml` workflow automates the verification of your software supply chain:

- **Dependency Verification**: Checks lockfiles for integrity and allowed sources
- **Artifact Signing**: Uses Cosign to sign build artifacts
- **Provenance Verification**: Verifies signatures and attestations
- **Container Security**: Scans containers and verifies their integrity
- **Security Gates**: Enforces policy compliance

### 2. Supply Chain Policy Configuration

The `security-policies/supply-chain-policy.yml` file defines the security requirements:

- **Dependency Management Policies**: Allowed sources, lockfile requirements
- **Artifact Signing Policies**: Required algorithms, attestation requirements
- **Container Security Policies**: Allowed registries, build requirements
- **CI/CD Security Policies**: Secrets management, build environment
- **Compliance Requirements**: NIST SSDF, SLSA Level 3

### 3. Supply Chain Verification Script

The `scripts/verify_supply_chain.py` script provides a command-line tool for:

- Validating dependencies
- Verifying artifact signatures
- Checking container provenance
- Validating SBOMs
- Ensuring policy compliance

### 4. Secrets Management Integration

The implementation integrates with the existing `secretes_manager.py` for secure handling of:

- Signing keys
- Verification keys
- Temporary credentials

## Quick Start

### Set Up Signing Keys

Generate signing and verification keys:

```bash
# Generate keys for artifact signing
openssl genpkey -algorithm ED25519 -out artifact-signing-key.pem
openssl pkey -in artifact-signing-key.pem -pubout -out artifact-verification-key.pem

# Store keys securely
python scripts/secretes_manager.py set ARTIFACT_SIGNING_KEY --file artifact-signing-key.pem
python scripts/secretes_manager.py set ARTIFACT_VERIFICATION_KEY --file artifact-verification-key.pem

# Clean up local key files
shred -u artifact-signing-key.pem
shred -u artifact-verification-key.pem

# Generate keys for container signing
cosign generate-key-pair
python scripts/secretes_manager.py set CONTAINER_SIGNING_KEY --file cosign.key
python scripts/secretes_manager.py set CONTAINER_VERIFICATION_KEY --file cosign.pub
```

### Manual Verification

You can manually verify your supply chain:

```bash
# Verify dependencies
python scripts/verify_supply_chain.py --policy security-policies/supply-chain-policy.yml --lockfile Pipfile.lock --output verification-results.json

# Verify container
python scripts/verify_supply_chain.py --policy security-policies/supply-chain-policy.yml --container-image your-app:latest --output verification-results.json

# Comprehensive verification
python scripts/verify_supply_chain.py \
  --policy security-policies/supply-chain-policy.yml \
  --lockfile Pipfile.lock \
  --sbom sbom.json \
  --artifacts-dir ./dist \
  --container-image your-app:latest \
  --container-sbom container-sbom.json \
  --build-info build-info.json \
  --repo-path . \
  --output verification-results.json
```

### GitHub Actions Integration

The workflow will run automatically on push to main branches and pull requests. You can also trigger it manually from the GitHub UI.

## Best Practices

1. **Always Sign Artifacts**: Never deploy unsigned artifacts to production.
2. **Keep Signing Keys Secure**: Use the secrets manager to handle keys.
3. **Generate SBOMs**: Include SBOMs with all releases to document components.
4. **Pin Dependencies**: Use lockfiles with pinned versions and hashes.
5. **Verify Third-Party Artifacts**: Only use third-party artifacts with verified provenance.
6. **Enforce Policy**: Use the security gate to enforce your supply chain policy.

## Advanced Configuration

### Customizing the Policy

Edit `security-policies/supply-chain-policy.yml` to adjust:

- Allowed dependency sources
- Vulnerability thresholds
- Signing requirements
- Container security policies

### Integration with SIEM

The workflow includes integration with your SIEM system:

```yaml
- name: Report to SIEM
  run: |
    python scripts/siem_integration.py \
      --event-type "supply-chain-security" \
      --data-file ./security-gate-result.json \
      --include-sbom ./all-artifacts/dependency-scan-results/sbom.json
```

## Troubleshooting

### Common Issues

1. **Signature Verification Failures**: Ensure the correct verification key is being used.
2. **Missing SBOM Components**: Check that your SBOM generation correctly captures all dependencies.
3. **Container Verification Errors**: Verify that the container was built and signed properly.

### Getting Help

For assistance, check the verification logs in GitHub Actions or run the verification script with more verbose logging:

```bash
python scripts/verify_supply_chain.py --log-level DEBUG ...
``` 