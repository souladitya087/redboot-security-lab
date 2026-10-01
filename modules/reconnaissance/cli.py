"""
CLI Entrypoint for RedBoot Reconnaissance Module
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from modules.core.config import RedBootConfig
from modules.core.logger import get_logger
from modules.core.scope import ScopeValidator, ScopeViolation
from modules.reconnaissance.scanner import ReconScanner


@click.command(name="redboot-recon")
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target IP address, hostname, or CIDR range.",
)
@click.option(
    "--config",
    "-c",
    default=None,
    help="Path to redboot.yaml configuration file.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output JSON file path.",
)
@click.option(
    "--ports",
    "-p",
    default=None,
    help="Comma-separated list of ports to scan (e.g. '21,22,80,443').",
)
@click.option(
    "--timeout",
    default=0.5,
    type=float,
    help="Socket connection timeout in seconds.",
)
def main(
    target: str,
    config: str | None,
    output: str | None,
    ports: str | None,
    timeout: float,
) -> None:
    """Run scope-enforced network reconnaissance scan."""
    logger = get_logger("recon-cli")
    try:
        if config and Path(config).exists():
            cfg = RedBootConfig.load(config)
            validator = ScopeValidator.from_config(cfg.scope)
        else:
            # Fallback to local scope including the target if not given
            validator = ScopeValidator(
                allowed_networks=[target] if "/" in target else [],
                allowed_hosts=[target],
            )
    except Exception as e:
        logger.error(f"Failed to load scope configuration: {e}")
        sys.exit(1)

    port_list = [int(p.strip()) for p in ports.split(",")] if ports else None
    scanner = ReconScanner(validator=validator, timeout=timeout)

    try:
        if "/" in target:
            results = scanner.scan_range(target, ports=port_list)
        else:
            host_res = scanner.scan_host(target, ports=port_list)
            results = {
                "module": "reconnaissance",
                "target": target,
                "findings": [host_res] if host_res["open_ports_count"] > 0 else [],
            }

        formatted_json = json.dumps(results, indent=2)
        click.echo(formatted_json)

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(formatted_json, encoding="utf-8")
            logger.info(f"Scan results saved to {output}")

    except ScopeViolation as sv:
        logger.error(f"Scan aborted due to scope violation: {sv}")
        click.echo(f"Error: {sv}", err=True)
        sys.exit(2)
    except Exception as e:
        logger.error(f"Scan error: {e}")
        click.echo(f"Scan error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
