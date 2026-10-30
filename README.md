# ReconSage Lite
### Nmap-Based Security Assessment & Reporting Tool

ReconSage Lite is a lightweight Python CLI tool that analyzes Nmap XML scan results, identifies potentially exposed network services using predefined detection rules, prioritizes findings by severity, and generates structured Markdown security reports.

## Features

- **Nmap XML Parsing:** Extracts host, port, protocol, and service information.
- **Service Detection:** Identifies 13 predefined network services.
- **Severity Classification:** Categorizes findings as HIGH, MEDIUM, or LOW.
- **Finding Prioritization:** Sorts findings according to severity.
- **Rule-Based Explanations:** Provides evidence, security context, and remediation recommendations.
- **Automated Reporting:** Generates Markdown reports with unique report and finding IDs.
- **Multi-Host Support:** Analyzes multiple hosts in a single scan.
- **Input Validation:** Handles malformed XML, missing files, and invalid port entries.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core development |
| ElementTree | XML parsing |
| argparse | CLI interface |
| pathlib | File handling |
| unittest | Unit testing |
| Nmap | Network scanning input |

## Architecture

```text
Nmap XML
   |
   v
XML Parser
   |
   v
Service Detection
   |
   v
Rule-Based Analysis
   |
   v
Severity Prioritization
   |
   v
Explanation Engine
   |
   v
Markdown Report
```

## Project Structure

```text
reconsage-lite/
├── reconsage/
│   ├── cli.py
│   ├── parser.py
│   ├── rules.py
│   ├── explanations.py
│   └── report.py
├── samples/
├── tests/
├── reports/
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

```powershell
git clone <YOUR_REPOSITORY_URL>
cd reconsage-lite

python -m venv .venv
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

## Usage

Generate an Nmap XML scan for an authorized target:

```bash
nmap -sV -oX scan.xml <TARGET>
```

Run ReconSage Lite:

```powershell
python -m reconsage.cli --input scan.xml
```

Specify a custom report destination:

```powershell
python -m reconsage.cli --input scan.xml --output reports/custom_report.md
```

View available options:

```powershell
python -m reconsage.cli --help
```

## Sample Output

```text
[*] Parsing Nmap XML...
[+] Hosts processed: 4
[*] Analyzing potential security risks...
[+] Findings identified: 3

Prioritized findings:

[HIGH] Telnet - 192.168.1.10:23
[MEDIUM] MySQL - 192.168.1.20:3306
[LOW] SMTP - 192.168.1.30:25

ReconSage analysis complete.
```

## Testing

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

**Current status: 36 tests passing.**

## Limitations

- Detection is limited to predefined service rules.
- Findings indicate potential security concerns, not confirmed vulnerabilities.
- The tool does not perform exploitation or CVE verification.
- Analysis depends on the information available in the supplied Nmap XML.

## Future Improvements

- Expandable detection rules.
- CVE intelligence integration.
- JSON and HTML reporting.
- Enhanced scan metadata extraction.
- Additional security assessment integrations.

## Responsible Use

Use ReconSage Lite only on systems and networks you own or are explicitly authorized to assess.

---

**Author:** Dishant Pramod Deore

*ReconSage Lite — Turning Nmap scan results into prioritized security insights.*