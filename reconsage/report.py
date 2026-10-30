from datetime import datetime, timezone, timedelta
from pathlib import Path
import secrets

from reconsage.explanations import explain_findings


SEVERITY_RANK = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

SEVERITY_RATIONALE = {
    "HIGH": (
        "Higher-priority concern requiring prompt verification "
        "and appropriate mitigation."
    ),
    "MEDIUM": (
        "Potentially meaningful exposure that should be reviewed "
        "and addressed according to the environment."
    ),
    "LOW": (
        "Lower-priority configuration concern that should be "
        "reviewed when appropriate."
    ),
}


def escape_table_value(value):
    """Escape values before inserting them into a Markdown table."""

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def generate_report(hosts, findings, output_path):
    """Generate a prioritized Markdown security report in IST."""

    if not isinstance(hosts, list):
        raise ValueError("Hosts must be provided as a list.")

    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate IST timestamp and unique report identifier.
    ist = timezone(timedelta(hours=5, minutes=30))
    now = datetime.now(ist)

    generated_at = now.strftime("%Y-%m-%d %H:%M IST")

    report_id = (
        f"RPT-{now.strftime('%Y%m%d-%H%M%S')}"
        f"-{secrets.token_hex(2).upper()}"
    )

    # Prioritize findings by severity.
    sorted_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_RANK.get(
            finding.get("severity", "LOW"), 0
        ),
        reverse=True,
    )

    explanations = explain_findings(sorted_findings)

    # Count findings by severity.
    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in sorted_findings:
        severity = finding.get("severity", "LOW")

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Summarize distinct affected services.
    affected_services = sorted({
        finding.get("service", "Unknown service")
        for finding in sorted_findings
    })

    lines = [
        "# ReconSage Lite - Security Assessment Report",
        "",
        f"**Generated:** {generated_at}",
        f"**Report ID:** {report_id}",
        "**Input:** Nmap XML scan",
        "**Explanation mode:** Offline rule-based",
        "",
        "## Executive Summary",
        "",
        f"- Hosts processed: {len(hosts)}",
        f"- Total findings: {len(sorted_findings)}",
        f"- High severity: {severity_counts['HIGH']}",
        f"- Medium severity: {severity_counts['MEDIUM']}",
        f"- Low severity: {severity_counts['LOW']}",
        (
            "- Services requiring review: "
            + (
                ", ".join(affected_services)
                if affected_services
                else "None identified by the configured rules"
            )
        ),
        "",
        "## Discovered Hosts",
        "",
        "| Host | Status | Hostname | Open Ports |",
        "|---|---|---|---|",
    ]

    # Add discovered hosts.
    for host in hosts:
        if not isinstance(host, dict):
            continue

        address = escape_table_value(
            host.get("address", "Unknown")
        )

        status = escape_table_value(
            host.get("status", "Unknown")
        )

        hostname = escape_table_value(
            host.get("hostname") or "N/A"
        )

        ports = host.get("ports", [])

        if not isinstance(ports, list):
            ports = []

        open_ports = [
            str(port.get("port"))
            for port in ports
            if isinstance(port, dict)
            and port.get("state") == "open"
        ]

        ports_text = escape_table_value(
            ", ".join(open_ports) if open_ports else "None"
        )

        lines.append(
            f"| {address} | {status} | {hostname} | {ports_text} |"
        )

    lines.extend([
        "",
        "## Prioritized Findings",
        "",
    ])

    if not sorted_findings:
        lines.extend([
            "No findings matched the configured detection rules.",
            "",
        ])

    else:
        for index, finding in enumerate(sorted_findings):

            explanation = explanations[index]

            severity = finding.get("severity", "UNKNOWN")

            finding_id = f"RS-{report_id}-{index + 1:03d}"

            rationale = SEVERITY_RATIONALE.get(
                severity,
                "Severity is unclassified; manually review this finding.",
            )

            lines.extend([
                f"### {finding_id}: [{severity}] "
                f"{finding.get('service', 'Unknown service')}",
                "",
                f"- **Host:** {finding.get('host', 'Unknown')}",
                f"- **Port:** {finding.get('port', 'Unknown')}/"
                f"{finding.get('protocol', 'unknown')}",
                f"- **Evidence:** {finding.get('evidence', 'N/A')}",
                f"- **Priority rationale:** {rationale}",
                f"- **Explanation:** {explanation.get('summary', 'N/A')}",
                (
                    f"- **Why it matters:** "
                    f"{explanation.get('why_it_matters', finding.get('reason', 'N/A'))}"
                ),
                (
                    f"- **Recommendation:** "
                    f"{explanation.get('recommendation', finding.get('recommendation', 'N/A'))}"
                ),
                (
                    f"- **Explanation source:** "
                    f"{explanation.get('source', 'rule-based')}"
                ),
                "",
            ])

    lines.extend([
        "## Scope and Limitations",
        "",
        "- Findings indicate potential security concerns, not confirmed vulnerabilities.",
        "- Severity is a preliminary triage category, not a verified risk score.",
        "- Services not matched by configured rules may still require investigation.",
        "- Results depend on the services and ports present in the supplied Nmap XML.",
        "- Exposed services are not necessarily misconfigured or exploitable.",
        "- Explanations use offline rule-based logic, not a language model.",
        "- Validate findings and recommendations before taking remediation action.",
        "",
    ])

    report_content = "\n".join(lines)

    output_path.write_text(
        report_content,
        encoding="utf-8",
    )

    return output_path
