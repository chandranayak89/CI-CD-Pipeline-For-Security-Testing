# CI-CD-Pipeline-For-Security-Testing

A comprehensive CI/CD pipeline implementation focused on security testing, combining Static Application Security Testing (SAST) and Dynamic Application Security Testing (DAST) to identify vulnerabilities in Python applications.

## Project Overview

This project implements an automated security testing pipeline using GitHub Actions. It includes:

1. **Static Application Security Testing (SAST)** - Analyzing source code for potential security vulnerabilities
2. **Dynamic Application Security Testing (DAST)** - Testing running applications for security issues
3. **Dependency Scanning** - Checking for vulnerabilities in dependencies
4. **Security Dashboard** - Visualizing security findings

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

### Dependency Scanning

Checks for known vulnerabilities in third-party dependencies.

Tools implemented:
- **Safety** - Checks Python dependencies against a database of known vulnerabilities

### Security Dashboard

Reports and visualizes security findings from all scanning tools.

- HTML reports for SAST and DAST findings
- GitHub Pages integration for report hosting

## Project Structure

```
CI-CD-Pipeline-For-Security-Testing/
├── .github/
│   └── workflows/
│       ├── security-pipeline.yml  # Main CI/CD pipeline
│       ├── sast.yml               # Static Analysis workflow
│       └── dast.yml               # Dynamic Analysis workflow
├── .zap/
│   └── rules.tsv                  # ZAP scanning rules configuration
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── packet_capture.py
│   ├── traffic_analyzer.py
│   ├── threat_detector.py
│   ├── alert_system.py
│   └── web_dashboard.py
├── scripts/
│   └── generate_dast_report.py    # DAST report generation script
├── test/
│   └── ...                        # Test files
├── requirements.txt               # Project dependencies
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git

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

## CI/CD Pipeline

The security testing is integrated into GitHub Actions workflows:

1. On pull requests and pushes to main:
   - SAST scans are run
   - DAST scans are run if application components are changed
   - Test results are uploaded as artifacts

2. On scheduled weekly runs:
   - Complete security scans are performed
   - Security dashboard is updated

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
