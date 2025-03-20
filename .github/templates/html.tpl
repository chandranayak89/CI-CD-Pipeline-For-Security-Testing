<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Security Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary-box {
            text-align: center;
            padding: 15px;
            border-radius: 5px;
            flex: 1;
            margin: 0 10px;
        }
        .critical-risk {
            background-color: #f8d7da;
            border-left: 5px solid #721c24;
        }
        .high-risk {
            background-color: #ffdddd;
            border-left: 5px solid #dc3545;
        }
        .medium-risk {
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
        }
        .low-risk {
            background-color: #d1ecf1;
            border-left: 5px solid #17a2b8;
        }
        .vuln-item {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-id {
            font-weight: bold;
            font-size: 18px;
        }
        .vuln-severity {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        .vuln-details {
            margin-top: 10px;
        }
        .vuln-section {
            margin-bottom: 5px;
        }
        .vuln-section-title {
            font-weight: bold;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            text-align: center;
        }
        .timestamp {
            text-align: right;
            color: #6c757d;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Container Security Scan Report</h1>
            <p>CI/CD Pipeline for Security Testing</p>
        </div>
        
        <div class="summary">
            <div class="critical-risk summary-box">
                <h3>Critical Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{{ range . }}{{ if eq .Severity "CRITICAL" }}{{ len .Vulnerabilities }}{{ end }}{{ else }}0{{ end }}</p>
            </div>
            <div class="high-risk summary-box">
                <h3>High Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{{ range . }}{{ if eq .Severity "HIGH" }}{{ len .Vulnerabilities }}{{ end }}{{ else }}0{{ end }}</p>
            </div>
            <div class="medium-risk summary-box">
                <h3>Medium Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{{ range . }}{{ if eq .Severity "MEDIUM" }}{{ len .Vulnerabilities }}{{ end }}{{ else }}0{{ end }}</p>
            </div>
            <div class="low-risk summary-box">
                <h3>Low Risk</h3>
                <p style="font-size: 24px; font-weight: bold;">{{ range . }}{{ if eq .Severity "LOW" }}{{ len .Vulnerabilities }}{{ end }}{{ else }}0{{ end }}</p>
            </div>
        </div>
        
        <h2>Container Image: {{ $.Target }}</h2>

        <!-- Critical Vulnerabilities -->
        {{ range . }}
        {{ if eq .Severity "CRITICAL" }}
        <h3>Critical Vulnerabilities ({{ len .Vulnerabilities }})</h3>
        {{ range .Vulnerabilities }}
        <div class="vuln-item critical-risk">
            <div class="vuln-header">
                <div class="vuln-id">{{ .VulnerabilityID }}</div>
                <div class="vuln-severity" style="background-color: #721c24;">CRITICAL</div>
            </div>
            <div class="vuln-details">
                <div class="vuln-section">
                    <span class="vuln-section-title">Package:</span> 
                    {{ .PkgName }} ({{ .InstalledVersion }})
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Fixed Version:</span> 
                    {{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}Not Fixed{{ end }}
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Description:</span> 
                    <p>{{ .Description }}</p>
                </div>
                {{ if .References }}
                <div class="vuln-section">
                    <span class="vuln-section-title">References:</span> 
                    <ul>
                    {{ range .References }}
                        <li><a href="{{ . }}" target="_blank">{{ . }}</a></li>
                    {{ end }}
                    </ul>
                </div>
                {{ end }}
            </div>
        </div>
        {{ end }}
        {{ end }}
        {{ end }}

        <!-- High Vulnerabilities -->
        {{ range . }}
        {{ if eq .Severity "HIGH" }}
        <h3>High Vulnerabilities ({{ len .Vulnerabilities }})</h3>
        {{ range .Vulnerabilities }}
        <div class="vuln-item high-risk">
            <div class="vuln-header">
                <div class="vuln-id">{{ .VulnerabilityID }}</div>
                <div class="vuln-severity" style="background-color: #dc3545;">HIGH</div>
            </div>
            <div class="vuln-details">
                <div class="vuln-section">
                    <span class="vuln-section-title">Package:</span> 
                    {{ .PkgName }} ({{ .InstalledVersion }})
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Fixed Version:</span> 
                    {{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}Not Fixed{{ end }}
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Description:</span> 
                    <p>{{ .Description }}</p>
                </div>
                {{ if .References }}
                <div class="vuln-section">
                    <span class="vuln-section-title">References:</span> 
                    <ul>
                    {{ range .References }}
                        <li><a href="{{ . }}" target="_blank">{{ . }}</a></li>
                    {{ end }}
                    </ul>
                </div>
                {{ end }}
            </div>
        </div>
        {{ end }}
        {{ end }}
        {{ end }}

        <!-- Medium Vulnerabilities -->
        {{ range . }}
        {{ if eq .Severity "MEDIUM" }}
        <h3>Medium Vulnerabilities ({{ len .Vulnerabilities }})</h3>
        {{ range .Vulnerabilities }}
        <div class="vuln-item medium-risk">
            <div class="vuln-header">
                <div class="vuln-id">{{ .VulnerabilityID }}</div>
                <div class="vuln-severity" style="background-color: #ffc107;">MEDIUM</div>
            </div>
            <div class="vuln-details">
                <div class="vuln-section">
                    <span class="vuln-section-title">Package:</span> 
                    {{ .PkgName }} ({{ .InstalledVersion }})
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Fixed Version:</span> 
                    {{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}Not Fixed{{ end }}
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Description:</span> 
                    <p>{{ .Description }}</p>
                </div>
                {{ if .References }}
                <div class="vuln-section">
                    <span class="vuln-section-title">References:</span> 
                    <ul>
                    {{ range .References }}
                        <li><a href="{{ . }}" target="_blank">{{ . }}</a></li>
                    {{ end }}
                    </ul>
                </div>
                {{ end }}
            </div>
        </div>
        {{ end }}
        {{ end }}
        {{ end }}

        <!-- Low Vulnerabilities -->
        {{ range . }}
        {{ if eq .Severity "LOW" }}
        <h3>Low Vulnerabilities ({{ len .Vulnerabilities }})</h3>
        {{ range .Vulnerabilities }}
        <div class="vuln-item low-risk">
            <div class="vuln-header">
                <div class="vuln-id">{{ .VulnerabilityID }}</div>
                <div class="vuln-severity" style="background-color: #17a2b8;">LOW</div>
            </div>
            <div class="vuln-details">
                <div class="vuln-section">
                    <span class="vuln-section-title">Package:</span> 
                    {{ .PkgName }} ({{ .InstalledVersion }})
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Fixed Version:</span> 
                    {{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}Not Fixed{{ end }}
                </div>
                <div class="vuln-section">
                    <span class="vuln-section-title">Description:</span> 
                    <p>{{ .Description }}</p>
                </div>
                {{ if .References }}
                <div class="vuln-section">
                    <span class="vuln-section-title">References:</span> 
                    <ul>
                    {{ range .References }}
                        <li><a href="{{ . }}" target="_blank">{{ . }}</a></li>
                    {{ end }}
                    </ul>
                </div>
                {{ end }}
            </div>
        </div>
        {{ end }}
        {{ end }}
        {{ end }}

        <div class="timestamp">
            <p>Report generated on: {{ now | date "2006-01-02 15:04:05" }}</p>
        </div>
    </div>
</body>
</html> 