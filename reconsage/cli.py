import argparse
import sys
from datetime import datetime
from pathlib import Path

from reconsage.parser import parse_nmap_xml
from reconsage.rules import analyze_hosts
from reconsage.report import generate_report


def get_output_path(output_arg):
    """Return a safe report path without overwriting existing files."""

    if output_arg:
        output = Path(output_arg).expanduser()

        # Create parent directories when necessary.
        output.parent.mkdir(parents=True, exist_ok=True)

        if output.exists():
            raise FileExistsError(
                f"Report already exists: {output}. "
                "Choose a different output path."
            )

        return output

    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = reports_dir / f"security_report_{timestamp}.md"

    # Prevent accidental overwrites during repeated executions.
    counter = 1

    while output.exists():
        output = reports_dir / (
            f"security_report_{timestamp}_{counter}.md"
        )
        counter += 1

    return output


def create_argument_parser():
    """Configure command-line arguments."""

    cli_parser = argparse.ArgumentParser(
        description=(
            "ReconSage Lite - Nmap Security Report Analyzer"
        ),
        allow_abbrev=False,
        epilog=(
            "Examples:\n"
            "  python -m reconsage.cli "
            "--input samples/sample_scan.xml\n"
            "  python -m reconsage.cli "
            "--input samples/sample_scan.xml "
            "--output reports/custom_report.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    cli_parser.add_argument(
        "--input",
        required=True,
        help="Path to the Nmap XML scan file.",
    )

    cli_parser.add_argument(
        "--output",
        default=None,
        help=(
            "Optional Markdown report path. "
            "Existing files will not be overwritten."
        ),
    )

    return cli_parser


def main():
    cli_parser = create_argument_parser()
    args = cli_parser.parse_args()

    try:
        print("[*] Parsing Nmap XML...")

        # Parse input before preparing the report destination.
        hosts = parse_nmap_xml(
            Path(args.input).expanduser()
        )

        print(f"[+] Hosts processed: {len(hosts)}")

        print("[*] Analyzing potential security risks...")

        findings = analyze_hosts(hosts)

        print(f"[+] Findings identified: {len(findings)}")

        output_path = get_output_path(args.output)

        report_path = generate_report(
            hosts,
            findings,
            output_path,
        )

        print(
            f"[+] Report generated: "
            f"{Path(report_path).resolve()}"
        )

        if findings:
            print("\nPrioritized findings:")

            for finding in findings:
                print(
                    f"  [{finding['severity']}] "
                    f"{finding['service']} - "
                    f"{finding['host']}:{finding['port']}"
                )
        else:
            print("[+] No findings matched the configured rules.")

        print("\nReconSage analysis complete.")

    except (
        FileNotFoundError,
        FileExistsError,
        ValueError,
        OSError,
    ) as error:
        print(f"[!] Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
