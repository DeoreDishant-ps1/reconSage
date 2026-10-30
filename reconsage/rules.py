# ReconSage Lite: Explainable security rules
RULES = {
    21: {
        "service": "FTP",
        "expected_services": {"ftp"},
        "severity": "MEDIUM",
        "reason": (
            "FTP may transmit credentials and data without encryption, "
            "depending on its configuration."
        ),
        "recommendation": (
            "Prefer SFTP or properly configured FTPS and verify "
            "the server's security settings."
        ),
    },
    23: {
        "service": "Telnet",
        "expected_services": {"telnet"},
        "severity": "HIGH",
        "reason": (
            "Telnet does not protect session data with encryption, "
            "creating a risk of credential exposure."
        ),
        "recommendation": (
            "Disable Telnet where possible and use SSH instead."
        ),
    },
    25: {
        "service": "SMTP",
        "expected_services": {"smtp"},
        "severity": "LOW",
        "reason": (
            "An exposed SMTP service may require review of relay "
            "permissions, authentication, and transport encryption."
        ),
        "recommendation": (
            "Verify that open relay is disabled and review "
            "authentication and TLS configuration."
        ),
    },
    135: {
        "service": "MSRPC",
        "expected_services": {"msrpc", "epmap", "dce-rpc"},
        "severity": "MEDIUM",
        "reason": (
            "Exposed Microsoft RPC services may increase the "
            "remote attack surface."
        ),
        "recommendation": (
            "Restrict access to trusted networks and disable "
            "unnecessary RPC exposure."
        ),
    },
    139: {
        "service": "NetBIOS-SSN",
        "expected_services": {"netbios-ssn"},
        "severity": "MEDIUM",
        "reason": (
            "Exposed NetBIOS session services may reveal or expose "
            "legacy Windows file-sharing functionality."
        ),
        "recommendation": (
            "Restrict access to trusted networks and disable "
            "NetBIOS services if they are not required."
        ),
    },
    445: {
        "service": "SMB",
        "expected_services": {"microsoft-ds", "smb"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed SMB service may increase the file-sharing "
            "attack surface."
        ),
        "recommendation": (
            "Restrict access to trusted hosts and review SMB "
            "configuration, protocol versions, and patch status."
        ),
    },
    1433: {
        "service": "Microsoft SQL Server",
        "expected_services": {"ms-sql-s", "mssql"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed SQL Server service may be reachable by "
            "unintended clients."
        ),
        "recommendation": (
            "Restrict database access and verify authentication, "
            "patching, and encryption settings."
        ),
    },
    3306: {
        "service": "MySQL",
        "expected_services": {"mysql"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed MySQL service may be reachable by "
            "unintended clients."
        ),
        "recommendation": (
            "Restrict database access and verify authentication, "
            "patching, and encryption settings."
        ),
    },
    3389: {
        "service": "RDP",
        "expected_services": {"ms-wbt-server", "rdp"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed remote desktop service increases the "
            "remote-access attack surface."
        ),
        "recommendation": (
            "Restrict access, enforce strong authentication, "
            "and review Network Level Authentication settings."
        ),
    },
    5432: {
        "service": "PostgreSQL",
        "expected_services": {"postgresql"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed PostgreSQL service may be reachable by "
            "unintended clients."
        ),
        "recommendation": (
            "Restrict database access and review authentication, "
            "patching, and encryption settings."
        ),
    },
    5900: {
        "service": "VNC",
        "expected_services": {"vnc"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed VNC service may provide remote graphical "
            "access and increase the attack surface."
        ),
        "recommendation": (
            "Restrict access, use secure tunnelling where appropriate, "
            "and verify authentication settings."
        ),
    },
    6379: {
        "service": "Redis",
        "expected_services": {"redis"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed Redis service may allow unintended clients "
            "to interact with an in-memory data store."
        ),
        "recommendation": (
            "Bind Redis to trusted interfaces, restrict network access, "
            "and review authentication and TLS settings."
        ),
    },
    27017: {
        "service": "MongoDB",
        "expected_services": {"mongodb"},
        "severity": "MEDIUM",
        "reason": (
            "An exposed MongoDB service may be reachable by "
            "unintended clients."
        ),
        "recommendation": (
            "Restrict network access and verify authentication, "
            "authorization, and encryption settings."
        ),
    },
}

SEVERITY_RANK = {
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def normalize_service(service):
    """Normalize service names for consistent matching."""
    if not isinstance(service, str):
        return ""

    return service.strip().lower()


def is_valid_port(port_number):
    """Check whether a port number is a valid TCP/UDP port integer."""
    return (
        isinstance(port_number, int)
        and not isinstance(port_number, bool)
        and 1 <= port_number <= 65535
    )


def analyze_hosts(hosts):
    """Return prioritized, evidence-backed potential exposure findings."""

    findings = []

    if not isinstance(hosts, list):
        return findings

    for host in hosts:

        if not isinstance(host, dict):
            continue

        ports = host.get("ports", [])

        if not isinstance(ports, list):
            continue

        for port in ports:

            if not isinstance(port, dict):
                continue

            if port.get("state") != "open":
                continue

            port_number = port.get("port")

            if not is_valid_port(port_number):
                continue

            rule = RULES.get(port_number)

            if rule is None:
                continue

            detected_service = normalize_service(
                port.get("service")
            )

            if detected_service not in rule["expected_services"]:
                continue

            protocol = port.get("protocol")

            if not isinstance(protocol, str) or not protocol.strip():
                protocol = "unknown"
            else:
                protocol = protocol.strip().lower()

            product = port.get("product")
            version = port.get("version")

            version_info = ""

            if isinstance(product, str) and product.strip():
                version_info = f"; product: {product.strip()}"

                if isinstance(version, str) and version.strip():
                    version_info += f" {version.strip()}"

            host_address = host.get("address", "unknown")

            if not isinstance(host_address, str):
                host_address = "unknown"

            findings.append({
                "host": host_address,
                "port": port_number,
                "protocol": protocol,
                "service": rule["service"],
                "severity": rule["severity"],
                "reason": rule["reason"],
                "evidence": (
                    f"Scan reports {port_number}/{protocol} open; "
                    f"service: {detected_service}{version_info}."
                ),
                "recommendation": rule["recommendation"],
            })

    findings.sort(
        key=lambda finding: SEVERITY_RANK.get(
            finding["severity"], 0
        ),
        reverse=True,
    )

    return findings
