"""CLI entrypoint for csaf-vex."""

import json
import logging
from pathlib import Path
from typing import Any

import click

from csaf_vex.models import CSAFVEX
from csaf_vex.validation.validator import Validator
from csaf_vex.verification import VerificationReport, VerificationStatus, Verifier


def _display_result_details(details: dict[str, Any], indent: str, truncate: bool) -> None:
    """Display details for a verification result."""
    for key, value in details.items():
        if truncate and isinstance(value, list) and len(value) > 3:
            click.echo(f"{indent}  {key}: {value[:3]}... ({len(value)} total)")
        else:
            click.echo(f"{indent}  {key}: {value}")


def _display_verification_results(
    report: VerificationReport,
    *,
    verbose: bool = False,
    indent: str = "",
) -> None:
    """Display verification results in a consistent format.

    Args:
        report: The verification report to display
        verbose: If True, show all results including passed/skipped and full details
        indent: String to prepend to each line for indentation
    """
    for result in report.results:
        if result.status == VerificationStatus.PASS:
            if verbose:
                click.secho(f"{indent}✓ {result.test_id}: {result.test_name}", fg="green")
        elif result.status == VerificationStatus.FAIL:
            click.secho(f"{indent}✗ {result.test_id}: {result.test_name}", fg="red")
            click.echo(f"{indent}  {result.message}")
            if result.details:
                _display_result_details(result.details, indent, truncate=not verbose)
        elif result.status == VerificationStatus.WARN:
            click.secho(f"{indent}⚠ {result.test_id}: {result.test_name}", fg="yellow")
            click.echo(f"{indent}  {result.message}")
        elif result.status == VerificationStatus.SKIP and verbose:
            click.secho(f"{indent}○ {result.test_id}: {result.test_name} (skipped)", dim=True)


def _extract_cpe_format_summary(report: VerificationReport) -> str | None:
    """Extract CPE format summary from verification results."""
    for result in report.results:
        if result.test_id == "2.3" and result.details:
            cpe_23_count = result.details.get("cpe_23_count", 0)
            cpe_22_count = result.details.get("cpe_22_count", 0)
            if cpe_23_count > 0 or cpe_22_count > 0:
                parts = []
                if cpe_23_count > 0:
                    parts.append("CPE 2.3")
                if cpe_22_count > 0:
                    parts.append("CPE 2.2")
                return ", ".join(parts)
    return None


def _display_verification_summary(report: VerificationReport) -> None:
    """Display verification summary."""
    click.echo("")

    # Display CPE format summary if available
    cpe_summary = _extract_cpe_format_summary(report)
    if cpe_summary:
        click.echo(f"CPE formats detected: {cpe_summary}")

    click.echo(
        f"Summary: {report.passed_count} passed, {report.failed_count} failed, "
        f"{report.warning_count} warnings, {report.skipped_count} skipped"
    )

    if report.passed:
        click.secho("Verification PASSED", fg="green", bold=True)
    else:
        click.secho("Verification FAILED", fg="red", bold=True)


def _display_validation_results(report, *, verbose: bool = False, indent: str = "") -> None:
    """Display validation plugin results in a consistent format."""
    for r in report.results:
        if r.success:
            if verbose:
                click.secho(f"{indent}✓ {r.validator_name}", fg="green")
        else:
            click.secho(f"{indent}✗ {r.validator_name}", fg="red")
            for e in r.errors:
                click.echo(f"{indent}  - {e.message}")


def _display_validation_summary(report) -> None:
    """Display validation summary."""
    click.echo("")
    click.echo(f"Summary: {report.passed_count} passed, {report.failed_count} failed")
    if report.passed:
        click.secho("Validation PASSED", fg="green", bold=True)
    else:
        click.secho("Validation FAILED", fg="red", bold=True)


@click.group()
def main():
    """CSAF VEX file manipulation tool."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--verify/--no-verify", default=True, help="Enable/disable verification")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed verification results")
@click.pass_context
def read(ctx: click.Context, file: Path, verify: bool, verbose: bool):
    """Read and parse a CSAF VEX JSON file."""
    try:
        with file.open() as f:
            data = json.load(f)

        csaf_vex = CSAFVEX.from_dict(data)

        click.echo(f"Successfully read CSAF VEX file: {file}")
        click.echo(f"Title: {csaf_vex.document.title}")
        click.echo(f"Tracking ID: {csaf_vex.document.tracking.id}")
        click.echo(f"Product tree entries: {len(csaf_vex.product_tree.branches)}")
        click.echo(f"Vulnerabilities: {len(csaf_vex.vulnerabilities)}")

        if verify:
            click.echo("")
            click.echo("Running verification...")
            verifier = Verifier(data)
            report = verifier.run_all()

            # Show summary
            if report.passed:
                click.secho(
                    f"✓ Verification PASSED ({report.passed_count}/{report.total_tests} tests)",
                    fg="green",
                )
            else:
                click.secho(
                    f"✗ Verification FAILED ({report.failed_count} failures, "
                    f"{report.warning_count} warnings)",
                    fg="red",
                )

            # Show details if verbose or if there are failures
            if verbose or not report.passed:
                click.echo("")
                _display_verification_results(report, verbose=verbose, indent="  ")

            if not report.passed:
                ctx.exit(1)

    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {file}: {e}") from None
    except Exception as e:
        raise click.ClickException(f"Error reading file {file}: {e}") from None


@main.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--test-set",
    type=click.Choice(["all", "csaf", "data"]),
    default="all",
    help="Which test set to run",
)
@click.option("--test-id", "-t", multiple=True, help="Run specific test(s) by ID")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed verification results")
@click.pass_context
def verify(ctx: click.Context, file: Path, test_set: str, test_id: tuple[str, ...], verbose: bool):
    """Verify a CSAF VEX file against the CSAF standard."""
    try:
        log_level = logging.DEBUG if verbose else logging.INFO
        verifier = Verifier.from_file(file, log_level=log_level)

        click.echo(f"Verifying: {file}")
        if verifier.document_id:
            click.echo(f"Document ID: {verifier.document_id}")
        click.echo("")

        # Run the appropriate tests
        if test_id:
            report = verifier.run_tests(list(test_id))
        elif test_set == "csaf":
            report = verifier.run_csaf_compliance()
        elif test_set == "data":
            report = verifier.run_data_type_checks()
        else:
            report = verifier.run_all()

        # Display results
        _display_verification_results(report, verbose=verbose)
        _display_verification_summary(report)

    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {file}: {e}") from None
    except Exception as e:
        raise click.ClickException(f"Error verifying file {file}: {e}") from None


@main.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, default=False, help="Output results as JSON")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed verification results")
@click.pass_context
@click.option(
    "--verify/--skip-verify",
    default=True,
    help="Run CSAF verification for CSAF schema issues and data types checks",
)
def validate(ctx: click.Context, file: Path, as_json: bool, verbose: bool, verify: bool):
    """Validate a CSAF VEX JSON file using installed validator plugins."""
    try:
        log_level = logging.DEBUG if verbose else logging.INFO

        verification_report = None
        if verify:
            verifier = Verifier.from_file(file, log_level=log_level)
            verification_report = verifier.run_all()

        validator = Validator.from_file(file, log_level=log_level)
        report = validator.run_all()

        if as_json:
            output = {
                "document_id": report.document_id,
                "summary": {
                    "total": report.total,
                    "passed": report.passed_count,
                    "failed": report.failed_count,
                },
                "verification": verification_report.to_dict() if verification_report else None,
                "results": [
                    {
                        "validator_name": r.validator_name,
                        "success": r.success,
                        "duration_ms": r.duration_ms,
                        "errors": [{"message": e.message} for e in r.errors],
                    }
                    for r in report.results
                ],
            }
            click.echo(json.dumps(output, indent=2))
        else:
            if verification_report:
                click.echo("Verification results:")
                _display_verification_results(verification_report, verbose=verbose)
                _display_verification_summary(verification_report)
                click.echo("")

            if not report.results:
                click.echo("No validation plugins found.")
            else:
                click.echo("Validation results:")
                _display_validation_results(report, verbose=verbose)
                _display_validation_summary(report)

    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {file}: {e}") from None
    except Exception as e:
        raise click.ClickException(f"Error validating file {file}: {e}") from None


if __name__ == "__main__":
    main()
