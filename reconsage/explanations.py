"""Optional offline explanations for ReconSage Lite findings."""


def explain_finding(finding):
    """Explain a security finding without requiring an AI service."""

    service = finding.get("service", "Unknown service")
    severity = finding.get("severity", "UNKNOWN")
    reason = finding.get(
        "reason",
        "Further investigation is required.",
    )
    evidence = finding.get(
        "evidence",
        "No supporting evidence was provided.",
    )
    recommendation = finding.get(
        "recommendation",
        "Investigate the service configuration.",
    )

    return {
        "service": service,
        "severity": severity,
        "summary": (
            f"{service} was identified as a potential security concern. "
            "Verify the evidence before treating it as a confirmed vulnerability."
        ),
        "why_it_matters": reason,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": "rule-based",
    }


def explain_findings(findings):
    """Explain multiple findings using the offline fallback."""

    return [explain_finding(finding) for finding in findings]
