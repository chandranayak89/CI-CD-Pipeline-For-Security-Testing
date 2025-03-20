# CI-CD-Pipeline-For-Security-Testing

A comprehensive CI/CD pipeline implementation focused on security testing, combining Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), Container Security Scanning, Runtime Container Security, Dependency Vulnerability Management, and Compliance and Policy Enforcement to identify vulnerabilities in Python applications.

## Project Overview

This project implements an automated security testing pipeline using GitHub Actions. It includes:

1. **Static Application Security Testing (SAST)** - Analyzing source code for potential security vulnerabilities
2. **Dynamic Application Security Testing (DAST)** - Testing running applications for security issues
3. **Container Security Scanning** - Scanning container images for vulnerabilities
4. **Runtime Container Security** - Monitoring containers during execution for suspicious behavior
5. **Dependency Vulnerability Management** - Automating third-party dependency security checks and updates
6. **Compliance and Policy Enforcement** - Defining and enforcing security policies across the pipeline
7. **Security Dashboard** - Visualizing security findings

## Pipeline Components

### Static Application Security Testing (SAST)

SAST tools analyze the source code without executing it to find potential security vulnerabilities.

Tools implemented:
- **Bandit** - Finds common security issues in Python code
- **Semgrep** - Pattern-based code analysis with custom security rules
- **Pylint** - Code quality and potential security issue detection

### Dynamic Application Security Testing (DAST)

DAST tools test running applications to identify vulnerabilities that might not be apparent in the source code.

Tools implemented:
- **OWASP ZAP** (Zed Attack Proxy)
  - Baseline Scan - Quick security check
  - Full Scan - Comprehensive security assessment

### Container Security Scanning

Container security scanning tools check container images for vulnerabilities in the base image, installed packages, and application dependencies.

Tools implemented:
- **Trivy** - Comprehensive vulnerability scanner for containers
  - OS package vulnerabilities
  - Application dependency vulnerabilities
  - Misconfiguration detection

### Runtime Container Security

Runtime container security monitors containers during execution to detect and prevent suspicious activities in real-time.

Tools implemented:
- **Falco** - Cloud-native runtime security
  - System call monitoring
  - Container behavior analysis
  - Real-time alerts for security violations
  - Custom security rules for application-specific threats

### Dependency Vulnerability Management

Automates the process of checking, reporting, and updating third-party dependencies with security vulnerabilities.

Tools implemented:
- **Safety** - Checks Python dependencies against a database of known vulnerabilities
- **pip-audit** - Audits Python packages for known vulnerabilities
- **pip-licenses** - Generates reports of package licenses for compliance
- **Dependency Locker** - Custom script to generate and maintain lock files
- **Dependency Updater** - Custom script to automatically update vulnerable dependencies

Features:
- Automated vulnerability scanning
- Detailed HTML security reports
- Automated dependency updates via Pull Requests
- License compliance monitoring
- Dependency locking for consistent environments

### Compliance and Policy Enforcement

Establishes security policies and compliance rules that are automatically checked and enforced throughout the CI/CD pipeline.

Tools implemented:
- **Security Policy Framework** - YAML-based policy definition for security requirements
- **TruffleHog** - Advanced secrets detection with custom rules
- **Compliance Checker** - Custom tool to verify compliance with security policies
- **Policy Badges** - Visible indicators of compliance status

Features:
- Centralized security policy management
- Compliance checks against industry standards (OWASP Top 10, NIST 800-53)
- Automated policy enforcement in CI/CD pipeline
- Detailed compliance reports
- Policy violation notifications
- Exception management for approved deviations

### Security Dashboard

Reports and visualizes security findings from all scanning tools.

- HTML reports for SAST, DAST, container scanning, runtime security, dependency vulnerabilities, and compliance status
- GitHub Pages integration for report hosting
- Slack notifications for critical security events and policy violations

## Project Structure

```
CI-CD-Pipeline-For-Security-Testing/
├── .github/
│   ├── templates/
│   │   └── html.tpl                # Trivy HTML report template
│   └── workflows/
│       ├── security-pipeline.yml   # Main CI/CD pipeline
│       ├── sast.yml                # Static Analysis workflow
│       ├── dast.yml                # Dynamic Analysis workflow
│       ├── container-scan.yml      # Container scanning workflow
│       ├── dependency-scan.yml     # Dependency scanning workflow
│       ├── runtime-security.yml    # Runtime security testing workflow
│       └── policy-enforcement.yml  # Policy enforcement workflow
├── .zap/
│   └── rules.tsv                   # ZAP scanning rules configuration
├── falco/
│   ├── falco.yaml                  # Falco configuration
│   └── falco_rules.yaml            # Custom Falco security rules
├── policies/
│   ├── security-policies.yaml      # Centralized security policies
│   └── trufflehog-config.yaml      # TruffleHog secrets detection rules
├── reports/
│   ├── compliance/                 # Compliance and policy reports
│   └── dependency-scan/            # Dependency scan reports
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── packet_capture.py
│   ├── traffic_analyzer.py
│   ├── threat_detector.py
│   ├── alert_system.py
│   └── web_dashboard.py
├── scripts/
│   ├── check_compliance.py         # Policy compliance checking script
│   ├── dependency_maintenance.sh   # Scheduled dependency maintenance script
│   ├── generate_dast_report.py     # DAST report generation script
│   ├── generate_dependency_report.py # Dependency report generator
│   ├── generate_lockfile.py        # Dependency lock file generator
│   ├── runtime_security_monitor.py # Runtime security monitoring script
│   └── update_dependencies.py      # Dependency updater script
├── test/
│   └── ...                         # Test files
├── Dockerfile                      # Container definition
├── docker-compose.yml              # Multi-container application definition
├── requirements.txt                # Project dependencies
├── requirements.lock               # Locked dependencies (generated)
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Docker and Docker Compose (for container-based deployment and scanning)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/chandranayak89/CI-CD-Pipeline-For-Security-Testing.git
   cd CI-CD-Pipeline-For-Security-Testing
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python -m src.main --dashboard
   ```

### Container-Based Deployment

To run the application in a Docker container with runtime security monitoring:

```bash
# Build and start the containers with Falco runtime security
docker-compose up -d

# View logs
docker-compose logs -f

# Monitor Falco security alerts in real-time
tail -f falco/logs/falco.log

# Stop containers
docker-compose down
```

## Running Security Tests Locally

### SAST

```bash
# Run Bandit
bandit -r src/ -f json -o bandit-results.json

# Run Safety
safety check -r requirements.txt --json > safety-results.json

# Run Semgrep
semgrep --config=p/python --config=p/security-audit src/ --json > semgrep-results.json
```

### DAST

To run DAST tests locally, you need Docker and OWASP ZAP:

```bash
# Start the application
python -m src.main --dashboard &

# Run ZAP Baseline Scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:8080 -I

# Run ZAP Full Scan
docker run -t owasp/zap2docker-stable zap-full-scan.py -t http://localhost:8080 -I
```

### Container Security Scanning

To scan container images locally:

```bash
# Build the container image
docker build -t security-testing-pipeline:latest .

# Run Trivy to scan the image
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/reports:/reports aquasec/trivy image \
  security-testing-pipeline:latest --format json -o /reports/trivy-results.json

# Or use the docker-compose service
docker-compose up security-scan
```

### Runtime Container Security

To run runtime security monitoring locally:

```bash
# Install Falco (Ubuntu/Debian)
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update -y
sudo apt-get install -y falco

# Start the application containers
docker-compose up -d security-app

# Run Falco with our custom rules
sudo falco -c falco/falco.yaml -r falco/falco_rules.yaml

# In another terminal, run our monitoring script
python scripts/runtime_security_monitor.py --log-file /var/log/falco/falco.log

# Test by triggering some security events
docker exec security-app sh -c "cat /etc/passwd"
docker exec security-app sh -c "apt-get update"
```

### Dependency Vulnerability Management

To check and update dependencies locally:

```bash
# Create reports directory
mkdir -p reports/dependency-scan

# Run dependency vulnerability checks
safety check -r requirements.txt --json > reports/dependency-scan/safety-report.json
pip-audit -r requirements.txt -f json > reports/dependency-scan/pip-audit-report.json

# Generate dependency reports
python scripts/generate_dependency_report.py

# Check for vulnerable dependencies and get update recommendations
python scripts/update_dependencies.py

# Apply updates to vulnerable dependencies
python scripts/update_dependencies.py --apply

# Generate a lock file for consistent dependencies
python scripts/generate_lockfile.py --json

# Run the complete dependency maintenance process
bash scripts/dependency_maintenance.sh
```

### Compliance and Policy Enforcement

To check compliance with security policies locally:

```bash
# Create compliance reports directory
mkdir -p reports/compliance

# Check compliance against security policies
python scripts/check_compliance.py --policy-file policies/security-policies.yaml --output-dir reports/compliance

# Run with strict mode (fail on any violation)
python scripts/check_compliance.py --strict

# Run TruffleHog secrets scanning with custom rules
trufflehog filesystem --config policies/trufflehog-config.yaml ./

# Generate HTML compliance report
python scripts/check_compliance.py --format html

# View current policy requirements
cat policies/security-policies.yaml
```

#### Setting Up Pre-commit Hooks for Policy Enforcement

Pre-commit hooks automatically enforce security policies by checking code before it's committed:

```bash
# Install pre-commit hooks for policy enforcement
python scripts/setup_policy_hooks.py

# Run manual check on all files
pre-commit run --all-files

# Run specific hook
pre-commit run bandit --all-files
pre-commit run gitleaks --all-files
```

These hooks will prevent commits that violate security policies, such as:
- Introducing security vulnerabilities in Python code
- Adding hardcoded secrets or credentials
- Committing insecure configurations
- Adding vulnerable dependencies

## CI/CD Pipeline

The security testing is integrated into GitHub Actions workflows:

1. On pull requests and pushes to main:
   - SAST scans are run
   - DAST scans are run if application components are changed
   - Container scanning is run if Dockerfile or docker-compose.yml changes
   - Runtime security tests are run to validate security rules
   - Dependency vulnerability scans are run if requirements.txt changes
   - Policy compliance checks are run to enforce security policies
   - Test results are uploaded as artifacts

2. On scheduled weekly runs:
   - Complete security scans are performed
   - Dependency updates are automated via PRs
   - Compliance status is verified and reported
   - Security dashboard is updated

## Dependency Management Features

The dependency vulnerability management component includes:

1. **Vulnerability Scanning**: Multiple scanners identify known vulnerabilities in dependencies:
   - Safety for CVE and vulnerability database checks
   - pip-audit for additional vulnerability sources
   - Custom severity-based classification

2. **Automated Updates**: The system can automatically update vulnerable dependencies:
   - Creates a separate Git branch for updates
   - Generates detailed update reports
   - Tests compatibility of updated dependencies
   - Creates pull requests for review

3. **Dependency Locking**: Ensures consistent environments:
   - Generates detailed lock files with exact versions
   - Captures all direct and transitive dependencies
   - JSON format for machine readability
   - Verification to ensure lock files match requirements

4. **License Compliance**: Monitors licenses of all dependencies:
   - Generates comprehensive license reports
   - Identifies potential compliance issues
   - Documents license distribution across dependencies

5. **Scheduled Maintenance**: Regular dependency maintenance:
   - Can be scheduled via cron jobs
   - Automated notifications for security issues
   - Detailed logs of all maintenance activities

## Compliance and Policy Enforcement Features

The compliance and policy enforcement component includes:

1. **Centralized Policy Definition**: A single source of truth for security requirements:
   - YAML-based configuration for readability and version control
   - Policies for SAST, DAST, container security, dependencies, and secrets
   - Severity thresholds and allowed/disallowed configurations
   - Mapping to compliance frameworks like OWASP Top 10 and NIST 800-53

2. **Automated Compliance Checking**: Regular verification of policy compliance:
   - Checks tools, configurations, and reports against policies
   - Validates that security controls are properly implemented
   - Generates detailed compliance reports with specific violations
   - Supports different levels of enforcement (strict vs. advisory)

3. **Policy Enforcement in CI/CD**: Automated enforcement of security policies:
   - Blocks pipeline on critical/high severity violations
   - Provides detailed remediation guidance for violations
   - Generates compliance badges for visibility
   - Publishes compliance reports to GitHub Pages

4. **Pre-commit Policy Enforcement**: Local enforcement at development time:
   - Prevents security issues before code is committed
   - Scans for secrets, vulnerabilities, and insecure patterns
   - Enforces secure coding standards automatically
   - Integrates with standard Git workflow

5. **Secrets Detection and Prevention**: Prevents secrets from being committed:
   - Custom TruffleHog rules for detecting various types of secrets
   - Pre-commit hooks for local checks
   - CI/CD integration for catching secrets in PRs
   - Different severity levels based on secret type

6. **Exception Management**: Handles approved policy exceptions:
   - Documented process for requesting exceptions
   - Time-limited exceptions with expiration dates
   - Approval tracking for audit purposes
   - Regular review of active exceptions

## Runtime Security Features

The runtime security implementation includes:

1. **Behavioral Monitoring**: Detection of suspicious behaviors like:
   - Unexpected process execution
   - Unauthorized file access
   - Package installations
   - Shell spawning
   - Network connections to suspicious destinations

2. **Real-time Alerting**: Alerts are sent via multiple channels:
   - Log files
   - Security dashboard integration
   - Slack notifications for critical issues

3. **Customized Rules**: Application-specific security rules that detect:
   - Container escape attempts
   - Unauthorized access to sensitive files
   - Execution of prohibited binaries
   - Modification of immutable files
   - Crypto mining detection

4. **Integration with CI/CD**: Automated testing ensures rules work correctly before deployment

## Container Security Best Practices

This project follows these container security best practices:

1. **Minimal Base Images**: Using slim variants to reduce attack surface
2. **Non-Root User**: Running containers as non-root user
3. **Dependency Management**: Pinning dependencies to specific versions
4. **Multi-Stage Builds**: Separating build and runtime environments
5. **No Secrets in Images**: Avoiding hardcoded secrets in container images
6. **Runtime Security**: Monitoring container behavior during execution
7. **Regular Scanning**: Automated container scanning in CI/CD pipeline
8. **Health Checks**: Implementing container health checks

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
