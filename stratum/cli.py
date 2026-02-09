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
@click.option("--share-telemetry", is_flag=True,
              help="Submit anonymized telemetry profile to Stratum")
@click.option("--fail-above", type=int, default=None,
              help="Exit 1 if risk score exceeds this threshold (for CI gates)")
def scan_cmd(path: str, verbose: bool, json_output: bool, ci: bool,
             no_telemetry: bool, share_telemetry: bool, fail_above: int | None) -> None:
    """Scan a project directory for agent risk paths."""
    # Conflict check
    if share_telemetry and no_telemetry:
        click.echo("Error: --share-telemetry and --no-telemetry are mutually exclusive.", err=True)
        sys.exit(1)

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
    profile = None
    if not no_telemetry:
        profile = build_profile(result)
        profile_path = os.path.join(stratum_dir, "last-scan.json")
        try:
            import dataclasses
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(profile), f, indent=2)
        except OSError:
            pass

    # Share telemetry
    if share_telemetry and profile is not None:
        import dataclasses
        from stratum.telemetry.share import submit_profile
        profile_dict = dataclasses.asdict(profile)
        submit_profile(profile_dict)

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
        render(result, verbose=verbose, shared=share_telemetry)

    # --fail-above threshold check (works with all output modes)
    if fail_above is not None and result.risk_score > fail_above:
        sys.exit(1)


@cli.group()
def config() -> None:
    """Manage Stratum configuration."""
    pass


def _get_config_path(path: str = ".") -> str:
    """Get the path to the Stratum config file."""
    import os
    return os.path.join(os.path.abspath(path), ".stratum", "config.json")


def _load_config(config_path: str) -> dict:
    """Load config from file, returning empty dict if not found."""
    import os
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_config(config_path: str, cfg: dict) -> None:
    """Save config to file."""
    import os
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


@config.command("suppress-share-prompt")
@click.argument("path", default=".", type=click.Path(exists=True))
def suppress_share_prompt(path: str) -> None:
    """Suppress the share-telemetry nudge message."""
    config_path = _get_config_path(path)
    cfg = _load_config(config_path)
    cfg["suppress_share_prompt"] = True
    _save_config(config_path, cfg)
    click.echo("Share prompt suppressed. Run in project directory to affect that project.")


@config.command("suppress-benchmark-teaser")
@click.argument("path", default=".", type=click.Path(exists=True))
def suppress_benchmark_teaser(path: str) -> None:
    """Suppress the benchmark teaser message."""
    config_path = _get_config_path(path)
    cfg = _load_config(config_path)
    cfg["suppress_benchmark_teaser"] = True
    _save_config(config_path, cfg)
    click.echo("Benchmark teaser suppressed. Run in project directory to affect that project.")


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
