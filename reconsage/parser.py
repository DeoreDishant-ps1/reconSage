import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(file_path):
    """Parse and validate an Nmap XML file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Scan file not found: {path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML file: {exc}") from exc
    except OSError as exc:
        raise OSError(f"Unable to read scan file: {exc}") from exc

    root = tree.getroot()

    # Validate the document type.
    if root.tag != "nmaprun":
        raise ValueError(
            "File is not a recognized Nmap XML document"
        )

    hosts = []

    for host in root.findall("host"):

        address_element = host.find("address")
        status_element = host.find("status")

        address = (
            address_element.get("addr")
            if address_element is not None
            else "unknown"
        )

        status = (
            status_element.get("state")
            if status_element is not None
            else "unknown"
        )

        hostname_element = host.find("hostnames/hostname")

        hostname = (
            hostname_element.get("name")
            if hostname_element is not None
            else None
        )

        ports = []

        for port in host.findall("ports/port"):

            port_id = port.get("portid")

            try:
                port_number = int(port_id)
            except (TypeError, ValueError):
                continue

            # Valid TCP/UDP port range.
            if not 1 <= port_number <= 65535:
                continue

            state_element = port.find("state")
            service_element = port.find("service")

            state = (
                state_element.get("state")
                if state_element is not None
                else "unknown"
            )

            service_data = (
                service_element.attrib
                if service_element is not None
                else {}
            )

            ports.append({
                "port": port_number,
                "protocol": port.get("protocol", "unknown"),
                "state": state,
                "service": service_data.get("name", "unknown"),
                "product": service_data.get("product"),
                "version": service_data.get("version"),
            })

        hosts.append({
            "address": address,
            "hostname": hostname,
            "status": status,
            "ports": ports,
        })

    return hosts
