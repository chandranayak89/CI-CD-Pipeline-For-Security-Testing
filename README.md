# CI/CD Pipeline for Security Testing

A comprehensive CI/CD pipeline implementation that integrates security testing into the development workflow. This project demonstrates automated security scanning, including SAST, DAST, and dependency checks.

## Features

- Network packet capture and analysis for intrusion detection
- Traffic anomaly detection
- Pattern-based threat detection
- Alert generation and logging
- Web-based dashboard for monitoring

## Security Features

This project implements a complete CI/CD pipeline with security scanning:

- Static Application Security Testing (SAST) using Bandit
- Automated security scanning on every commit
- Code quality and vulnerability checks
- Dependency vulnerability scanning

## Setup and Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/CI-CD-Pipeline-For-Security-Testing.git
   cd CI-CD-Pipeline-For-Security-Testing
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the application:
   ```
   python src/main.py
   ```

## Development

1. Install development dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run tests:
   ```
   pytest
   ```

3. Run SAST manually:
   ```
   bandit -r src/ -f json -o bandit-results.json
   ```

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration and security scanning:

- Automated tests on every push
- SAST scanning with Bandit
- Dependency vulnerability checks
- Code quality metrics

## License

MIT 