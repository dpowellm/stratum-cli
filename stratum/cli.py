"""Click CLI entry point for Stratum."""
from __future__ import annotations

import json
import logging
import sys

import click

from stratum import __version__
from stratum.scanner import scan
from stratum.output.terminal import render
from stratum.telemetry.history import load_last, save_history, compute_diff
from stratum.telemetry.profile import build_profile


@click.group()
@click.version_option(version=__version__, prog_name="stratum")
def cli() -> None:
    """Stratum - Agent Risk Profiler."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, help="Expand all signals with full detail")
@click.option("--json-output", "--json", "json_output", is_flag=True,
              help="JSON to stdout instead of Rich")
@click.option("--ci", is_flag=True, help="CI mode: JSON output + exit codes")
@click.option("--no-telemetry", is_flag=True, help="Skip telemetry profile save")
def scan_cmd(path: str, verbose: bool, json_output: bool, ci: bool,
             no_telemetry: bool) -> None:
    """Scan a project directory for agent risk paths."""
    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(name)s: %(message)s",
    )

    result = scan(path)

    # History
    import os
    stratum_dir = os.path.join(os.path.abspath(path), ".stratum")
    prev = load_last(stratum_dir)

    if prev:
        result.diff = compute_diff(result, prev)

    save_history(result, stratum_dir)

    # Telemetry
    if not no_telemetry:
        profile = build_profile(result)
        profile_path = os.path.join(stratum_dir, "last-scan.json")
        try:
            import dataclasses
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(profile), f, indent=2)
        except OSError:
            pass

    # Output
    if ci or json_output:
        import dataclasses
        out = dataclasses.asdict(result)
        click.echo(json.dumps(out, indent=2))

        if ci:
            all_findings = result.top_paths + result.signals
            has_critical = any(f.severity.value == "CRITICAL" for f in all_findings)
            has_high = any(f.severity.value == "HIGH" for f in all_findings)

            if result.diff:
                new_criticals = any(
                    fid.startswith("STRATUM") and any(
                        f.id == fid and f.severity.value == "CRITICAL"
                        for f in all_findings
                    )
                    for fid in result.diff.new_finding_ids
                )
                score_increase = result.diff.risk_score_delta > 10
                if new_criticals or score_increase:
                    sys.exit(1)
                if any(
                    fid.startswith("STRATUM") and any(
                        f.id == fid and f.severity.value == "HIGH"
                        for f in all_findings
                    )
                    for fid in result.diff.new_finding_ids
                ):
                    sys.exit(2)
            else:
                # First run
                if has_critical:
                    sys.exit(1)
                if has_high:
                    sys.exit(2)
    else:
        render(result, verbose=verbose)


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
