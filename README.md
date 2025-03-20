# CI-CD-Pipeline-For-Security-Testing

A comprehensive CI/CD pipeline implementation focused on security testing, combining Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), and Container Security Scanning to identify vulnerabilities in Python applications.

## Project Overview

This project implements an automated security testing pipeline using GitHub Actions. It includes:

1. **Static Application Security Testing (SAST)** - Analyzing source code for potential security vulnerabilities
2. **Dynamic Application Security Testing (DAST)** - Testing running applications for security issues
3. **Container Security Scanning** - Scanning container images for vulnerabilities
4. **Runtime Container Security** - Monitoring containers during execution for suspicious behavior
5. **Dependency Scanning** - Checking for vulnerabilities in dependencies
6. **Security Dashboard** - Visualizing security findings

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

### Dependency Scanning

Checks for known vulnerabilities in third-party dependencies.

Tools implemented:
- **Safety** - Checks Python dependencies against a database of known vulnerabilities

### Security Dashboard

Reports and visualizes security findings from all scanning tools.

- HTML reports for SAST, DAST, container scanning, and runtime security
- GitHub Pages integration for report hosting
- Slack notifications for critical security events

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
│       └── runtime-security.yml    # Runtime security testing workflow
├── .zap/
│   └── rules.tsv                   # ZAP scanning rules configuration
├── falco/
│   ├── falco.yaml                  # Falco configuration
│   └── falco_rules.yaml            # Custom Falco security rules
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── packet_capture.py
│   ├── traffic_analyzer.py
│   ├── threat_detector.py
│   ├── alert_system.py
│   └── web_dashboard.py
├── scripts/
│   ├── generate_dast_report.py     # DAST report generation script
│   └── runtime_security_monitor.py # Runtime security monitoring script
├── test/
│   └── ...                         # Test files
├── Dockerfile                      # Container definition
├── docker-compose.yml              # Multi-container application definition
├── requirements.txt                # Project dependencies
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

## CI/CD Pipeline

The security testing is integrated into GitHub Actions workflows:

1. On pull requests and pushes to main:
   - SAST scans are run
   - DAST scans are run if application components are changed
   - Container scanning is run if Dockerfile or docker-compose.yml changes
   - Runtime security tests are run to validate security rules
   - Test results are uploaded as artifacts

2. On scheduled weekly runs:
   - Complete security scans are performed
   - Security dashboard is updated

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
