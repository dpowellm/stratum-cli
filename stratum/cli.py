"""Click CLI entry point for Stratum."""
from __future__ import annotations

import json
import logging
import os
import sys

import click

from stratum import __version__
from stratum.scanner import scan
from stratum.output.terminal import render, print_first_run_notice, print_comparison_url
from stratum.telemetry.history import load_last, save_history, compute_diff
from stratum.telemetry.profile import build_profile, build_scan_profile


@click.group()
@click.version_option(version=__version__, prog_name="stratum")
def cli() -> None:
    """Stratum - Security audit for AI agents."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, help="Expand all signals with full detail")
@click.option("--json-output", "--json", "json_output", is_flag=True,
              help="JSON to stdout instead of Rich")
@click.option("--ci", is_flag=True, help="CI mode: JSON output + exit codes")
@click.option("--no-telemetry", is_flag=True,
              help="Don't send anonymized statistics this scan")
@click.option("--offline", is_flag=True,
              help="No network calls, no local telemetry file")
@click.option("--fail-above", type=int, default=None,
              help="Exit 1 if risk score exceeds this threshold (for CI gates)")
@click.option("--security", "security_mode", is_flag=True,
              help="Security-first ordering (severity-based, default for --ci)")
@click.option("--format", "output_format", type=click.Choice(["terminal", "json", "sarif"]),
              default="terminal", help="Output format")
@click.option("--fix", "apply_fix", is_flag=True,
              help="Auto-apply safe fixes (human_input, memory, timeout) to source files")
@click.option("--patch-output", type=click.Path(),
              help="Generate a .patch file with fixes instead of applying them")
@click.option("--badge", "generate_badge", is_flag=True,
              help="Generate stratum-badge.svg in the scanned directory")
@click.option("--profile-output", type=click.Path(),
              help="Write ScanProfile as standalone JSON to this path")
@click.option("--export-graph", "export_graph_flag", is_flag=True,
              help="Export full scan graph to .stratum/graph.json for analysis")
@click.option("--quiet", is_flag=True,
              help="Minimal output: score + top 3 actions")
@click.option("--upload", is_flag=True,
              help="Upload profile to Stratum dashboard (requires --token)")
@click.option("--token", "api_token", type=str, default=None,
              help="Stratum API token for --upload")
@click.option("--reliability", "reliability_mode", is_flag=True, default=False,
              help="Include reliability findings in output (auto-enabled for multi-agent)")
@click.option("--security-only", "security_only", is_flag=True, default=False,
              help="Disable reliability scanner, backward-compatible schema_id 7 output")
@click.option("--output-dir", "output_dir", type=click.Path(),
              default=None,
              help="Write full ReliabilityScanOutput to <output-dir>/graphs/<repo_id>.json")
def scan_cmd(path: str, verbose: bool, json_output: bool, ci: bool,
             no_telemetry: bool, offline: bool, fail_above: int | None,
             security_mode: bool, output_format: str, apply_fix: bool,
             patch_output: str | None, generate_badge: bool,
             profile_output: str | None,
             export_graph_flag: bool = False,
             quiet: bool = False,
             upload: bool = False, api_token: str | None = None,
             reliability_mode: bool = False,
             security_only: bool = False,
             output_dir: str | None = None) -> None:
    """Run a security audit on an AI agent project."""
    # --ci implies --security ordering
    if ci:
        security_mode = True

    log_level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(name)s: %(message)s",
    )

    abs_path = os.path.abspath(path)
    stratum_dir = os.path.join(abs_path, ".stratum")

    # Detect first run (no .stratum/ directory)
    is_first_run = not os.path.exists(stratum_dir)

    # First-run disclosure (before scan)
    if is_first_run:
        if json_output or ci:
            print_first_run_notice(file=sys.stderr)
        else:
            print_first_run_notice()

    # Determine if telemetry should be POSTed
    config = _load_config(_get_config_path(path))
    env_override = os.environ.get("STRATUM_TELEMETRY", "").lower()
    telemetry_enabled = (
        config.get("telemetry", True)      # default: on
        and not no_telemetry               # not suppressed this scan
        and not offline                    # not in offline mode
        and env_override != "off"          # not suppressed by env var
    )

    # Track scan timing
    import time as _time
    _scan_start = _time.monotonic()

    # Run scan
    result = scan(path)

    # Determine effective reliability mode:
    # --security-only disables reliability, --reliability enables it,
    # otherwise auto-enable for multi-agent projects (>= 2 agents)
    show_reliability = reliability_mode
    if security_only:
        show_reliability = False
    elif not reliability_mode:
        # Auto-enable if multi-agent
        show_reliability = len(getattr(result, 'agent_definitions', [])) >= 2

    # History (always writes, even --offline)
    prev = load_last(stratum_dir)
    if prev:
        result.diff = compute_diff(result, prev)
    save_history(result, stratum_dir)

    # Telemetry profile (save locally unless --offline)
    profile = None
    scan_profile = None
    if not offline:
        profile = build_profile(result)
        profile_path = os.path.join(stratum_dir, "last-scan.json")
        try:
            import dataclasses
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(profile), f, indent=2)
        except OSError:
            pass

        # ScanProfile (enterprise intelligence schema)
        prev_profile = _load_previous_profile(stratum_dir)
        scan_profile = build_scan_profile(result, previous_profile=prev_profile)
        _save_scan_profile(scan_profile, stratum_dir)

        # --profile-output: standalone JSON for batch pipeline
        if profile_output:
            try:
                import dataclasses as dc
                os.makedirs(os.path.dirname(os.path.abspath(profile_output)), exist_ok=True)
                with open(profile_output, "w", encoding="utf-8") as f:
                    json.dump(dc.asdict(scan_profile), f, indent=2)
            except OSError as e:
                click.echo(f"  Failed to write profile: {e}", err=True)

    # Set archetype on result for terminal display
    if profile is not None:
        result._archetype = profile.archetype_class

    # POST telemetry
    submission_success = False
    if telemetry_enabled and profile is not None:
        import dataclasses
        from stratum.telemetry.share import submit_profile, build_usage_ping, submit_usage_ping
        profile_dict = dataclasses.asdict(profile)
        submission_success = submit_profile(profile_dict)

        # Build and send lightweight usage ping (v3 telemetry)
        _scan_duration = int((_time.monotonic() - _scan_start) * 1000)
        _flags = []
        if apply_fix: _flags.append("fix")
        if patch_output: _flags.append("patch")
        if generate_badge: _flags.append("badge")
        if verbose: _flags.append("verbose")
        if quiet: _flags.append("quiet")
        if json_output: _flags.append("json")
        if ci: _flags.append("ci")
        _out_mode = "quiet" if quiet else ("json" if json_output or ci else ("verbose" if verbose else "default"))
        _fix_ct = 0
        if apply_fix or patch_output:
            from stratum.fix import count_fixable_findings
            _fix_ct = count_fixable_findings(result)
        usage_ping = build_usage_ping(
            result, scan_profile=scan_profile,
            duration_ms=_scan_duration, flags_used=_flags,
            fix_count=_fix_ct, output_mode=_out_mode,
        )
        submit_usage_ping(usage_ping)

    # --upload: push profile to Stratum dashboard
    if upload and scan_profile is not None:
        import dataclasses as dc
        token = api_token or os.environ.get("STRATUM_TOKEN", "")
        if not token:
            click.echo("  --upload requires --token or STRATUM_TOKEN env var", err=True)
        else:
            from stratum.api.upload import upload_profile
            profile_dict_for_upload = dc.asdict(scan_profile)
            ok, msg = upload_profile(profile_dict_for_upload, token)
            if ok:
                click.echo(f"  Profile uploaded to Stratum dashboard.")
            else:
                click.echo(f"  Upload failed: {msg}", err=True)

    # --export-graph: serialize full scan graph to .stratum/graph.json
    if export_graph_flag and result.graph is not None:
        try:
            from stratum.graph.export import export_graph
            all_findings_for_export = result.top_paths + result.signals
            tc_matches = getattr(result, 'tc_matches', [])
            graph_path = export_graph(
                result.graph, all_findings_for_export, tc_matches,
                result.scan_id, stratum_dir,
            )
            click.echo(f"  Graph exported: {graph_path}")
        except Exception as e:
            click.echo(f"  Failed to export graph: {e}", err=True)

    # --output-dir: write full ReliabilityScanOutput to <output-dir>/graphs/<repo_id>.json
    if output_dir and not security_only:
        try:
            import dataclasses as dc
            from datetime import datetime, timezone
            from stratum.reliability.schema import ReliabilityScanOutput
            from stratum.reliability.metrics_compute import classify_gap

            _rel_findings_out = getattr(result, 'reliability_findings', [])
            _comp_findings_out = getattr(result, 'composite_findings', [])
            _rel_score_out = getattr(result, 'reliability_score', 0)
            _obs_points_out = getattr(result, 'observation_points', [])
            _motifs_out = getattr(result, 'graph_motifs', [])
            _metrics_out = getattr(result, 'reliability_metrics', {})
            _per_node_out = getattr(result, 'per_node_metrics', [])

            # Serialize graph
            _graph_dict = {}
            if result.graph:
                _graph_dict = {
                    "nodes": [
                        {
                            "id": nid,
                            "label": n.label,
                            "node_type": n.node_type.value if hasattr(n.node_type, 'value') else str(n.node_type),
                            "source_file": n.source_file or "",
                        }
                        for nid, n in result.graph.nodes.items()
                    ],
                    "edges": [
                        {
                            "source": e.source,
                            "target": e.target,
                            "edge_type": e.edge_type.value if hasattr(e.edge_type, 'value') else str(e.edge_type),
                        }
                        for e in result.graph.edges
                    ],
                }

            # Serialize findings
            def _finding_to_dict(f):
                return {
                    "id": f.id,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "title": f.title,
                    "path": f.path,
                    "description": f.description,
                    "evidence": f.evidence[:5],
                    "remediation": f.remediation,
                }

            _sec_findings_out = result.top_paths + result.signals
            _gap = classify_gap(float(result.risk_score), float(_rel_score_out))

            rel_output = ReliabilityScanOutput(
                repo_id=result.scan_id,
                framework=result.detected_frameworks[0] if result.detected_frameworks else "unknown",
                scan_timestamp=datetime.now(timezone.utc).isoformat(),
                scanner_version=__version__,
                schema_id=8,
                graph=_graph_dict,
                structural_metrics={
                    "global": _metrics_out,
                    "per_node": _per_node_out,
                },
                preconditions=[
                    _finding_to_dict(f) for f in _rel_findings_out
                    if not f.id.startswith("STRAT-ANOMALY") and not f.id.startswith("STRAT-COMP") and not f.id.startswith("STRAT-XCOMP")
                ],
                compositions=[_finding_to_dict(f) for f in _comp_findings_out],
                structural_anomalies=[
                    _finding_to_dict(f) for f in _rel_findings_out
                    if f.id.startswith("STRAT-ANOMALY")
                ],
                graph_motifs=_motifs_out,
                observation_points=_obs_points_out,
                security_risk_score=float(result.risk_score),
                reliability_risk_score=float(_rel_score_out),
                gap_classification=_gap,
                security_findings=[_finding_to_dict(f) for f in _sec_findings_out],
            )

            graphs_dir = os.path.join(output_dir, "graphs")
            os.makedirs(graphs_dir, exist_ok=True)
            out_path = os.path.join(graphs_dir, f"{result.scan_id}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(dc.asdict(rel_output), f, indent=2)
            click.echo(f"  ReliabilityScanOutput written: {out_path}")
        except Exception as e:
            click.echo(f"  Failed to write reliability output: {e}", err=True)

    # Populate citation field on findings for JSON output
    from stratum.research.citations import get_citation
    for finding in result.top_paths + result.signals:
        cit = get_citation(finding.id)
        if cit:
            finding.citation = {"stat": cit.stat, "source": cit.source, "url": cit.url}

    # --json-output and --ci override --format
    if json_output or ci:
        output_format = "json"

    # Build telemetry profile dict for JSON output
    telemetry_profile_dict = None
    if scan_profile is not None:
        import dataclasses as dc
        telemetry_profile_dict = dc.asdict(scan_profile)

    # Output
    if output_format == "sarif":
        from stratum.output.sarif import generate_sarif
        sarif = generate_sarif(result)
        click.echo(json.dumps(sarif, indent=2))

    elif output_format == "json" or ci:
        from stratum.telemetry.ping import build_v72_ping
        scan_duration_ms = int((_time.monotonic() - _scan_start) * 1000)
        ping = build_v72_ping(
            result, profile, scan_profile,
            scan_duration_ms=scan_duration_ms,
        )

        # Inject reliability data into JSON output (schema_id 8)
        if show_reliability and not security_only:
            ping["schema_id"] = 8
            _rel_findings = getattr(result, 'reliability_findings', [])
            _comp_findings = getattr(result, 'composite_findings', [])
            ping["reliability"] = {
                "findings": [
                    {
                        "id": f.id,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "title": f.title,
                        "path": f.path,
                        "description": f.description,
                        "evidence": f.evidence[:3],
                        "remediation": f.remediation,
                    }
                    for f in _rel_findings
                    if f.finding_class == "reliability"
                ],
                "composite_findings": [
                    {
                        "id": f.id,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "title": f.title,
                        "description": f.description,
                        "evidence": f.evidence[:3],
                    }
                    for f in _comp_findings
                ],
                "score": getattr(result, 'reliability_score', 0),
                "metrics": getattr(result, 'reliability_metrics', {}),
                "observation_points": getattr(result, 'observation_points', []),
            }
            _repo_profile = getattr(result, 'repo_profile', {})
            if _repo_profile:
                ping["repo_profile"] = _repo_profile

        click.echo(json.dumps(ping, indent=2))

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
        render(result, verbose=verbose, security_mode=security_mode, quiet=quiet)

        # Comparison URL (only if submission succeeded, terminal mode only)
        if submission_success:
            print_comparison_url(result.scan_id)

    # --patch-output: generate a .patch file without modifying source
    if patch_output:
        from stratum.fix import generate_patch, write_patch_file
        patches = generate_patch(result, abs_path)
        if patches:
            os.makedirs(os.path.dirname(os.path.abspath(patch_output)), exist_ok=True)
            write_patch_file(patches, patch_output)
            click.echo()
            click.echo(f"  Generated {len(patches)} fix(es) in {patch_output}:")
            click.echo()
            for p in patches:
                click.echo(f"    {p.file_path}")
            click.echo()
            click.echo(f"  To apply:  git apply {patch_output}")
            click.echo(f"  To review: cat {patch_output}")
        else:
            click.echo()
            click.echo("  No auto-fixable issues found.")

    # --fix mode: apply auto-remediations in place
    elif apply_fix:
        from stratum.fix import apply_fixes
        fixes = apply_fixes(result, abs_path)
        if fixes:
            click.echo()
            click.echo(f"  Applied {len(fixes)} fix(es):")
            click.echo()
            for fix in fixes:
                click.echo(f"  {fix.finding_id}  {fix.description}")
                click.echo(f"               {fix.file_path}")
            click.echo()
            click.echo("  Re-run `stratum scan .` to verify.")
        else:
            click.echo()
            click.echo("  No auto-fixable issues found.")

    # Show fix CTA in terminal mode if there are fixable findings
    elif output_format == "terminal" and not quiet:
        from stratum.fix import count_fixable_findings
        fixable = count_fixable_findings(result)
        if fixable > 0:
            click.echo(f"  Run 'stratum scan . --fix' to auto-fix {fixable} finding{'s' if fixable != 1 else ''}.")
            click.echo()

    # --badge: generate SVG badge
    if generate_badge:
        from stratum.output.badge import generate_badge_svg
        finding_count = len(result.top_paths) + len(result.signals)
        svg = generate_badge_svg(result.risk_score, finding_count)
        badge_path = os.path.join(abs_path, "stratum-badge.svg")
        try:
            with open(badge_path, "w", encoding="utf-8") as f:
                f.write(svg)
            click.echo(f"\n  Badge saved: {badge_path}")
            click.echo(f"  Embed: ![Stratum Risk Score](./stratum-badge.svg)")
        except OSError as e:
            click.echo(f"  Failed to write badge: {e}", err=True)

    # --fail-above threshold check (works with all output modes)
    if fail_above is not None and result.risk_score > fail_above:
        sys.exit(1)


@cli.group()
def config() -> None:
    """Manage Stratum configuration."""
    pass


def _get_config_path(path: str = ".") -> str:
    """Get the path to the Stratum config file."""
    return os.path.join(os.path.abspath(path), ".stratum", "config.json")


def _load_config(config_path: str) -> dict:
    """Load config from file, returning empty dict if not found."""
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_config(config_path: str, cfg: dict) -> None:
    """Save config to file."""
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


@config.command("set")
@click.argument("key")
@click.argument("value")
@click.argument("path", default=".", type=click.Path(exists=True))
def config_set(key: str, value: str, path: str) -> None:
    """Set a configuration value. Supports: telemetry (on/off)."""
    if key == "telemetry":
        if value not in ("on", "off"):
            click.echo("Value must be 'on' or 'off'", err=True)
            sys.exit(1)
        config_path = _get_config_path(path)
        cfg = _load_config(config_path)
        cfg["telemetry"] = (value == "on")
        _save_config(config_path, cfg)
        click.echo(f"Telemetry {'enabled' if value == 'on' else 'disabled'}.")
    else:
        click.echo(f"Unknown config key: {key}", err=True)
        sys.exit(1)


@config.command("get")
@click.argument("key")
@click.argument("path", default=".", type=click.Path(exists=True))
def config_get(key: str, path: str) -> None:
    """Get a configuration value."""
    if key == "telemetry":
        config_path = _get_config_path(path)
        cfg = _load_config(config_path)
        status = "on" if cfg.get("telemetry", True) else "off"
        click.echo(f"telemetry: {status}")
    else:
        click.echo(f"Unknown config key: {key}", err=True)
        sys.exit(1)


def _load_previous_profile(stratum_dir: str):
    """Load the previous ScanProfile from last-profile.json for delta tracking."""
    from stratum.models import ScanProfile
    profile_path = os.path.join(stratum_dir, "last-profile.json")
    try:
        if not os.path.exists(profile_path):
            return None
        with open(profile_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        p = ScanProfile()
        for k, v in data.items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _save_scan_profile(scan_profile, stratum_dir: str) -> None:
    """Save ScanProfile to last-profile.json for delta tracking."""
    import dataclasses
    profile_path = os.path.join(stratum_dir, "last-profile.json")
    try:
        os.makedirs(stratum_dir, exist_ok=True)
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(dataclasses.asdict(scan_profile), f, indent=2)
    except OSError:
        pass


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
