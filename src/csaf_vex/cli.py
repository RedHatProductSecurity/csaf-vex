"""CLI entrypoint for csaf-vex."""

import json
from pathlib import Path
from typing import Any

import click

from csaf_vex.models import CSAFVEXDocument
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


def _display_verification_summary(report: VerificationReport) -> None:
    """Display verification summary."""
    click.echo("")
    click.echo(
        f"Summary: {report.passed_count} passed, {report.failed_count} failed, "
        f"{report.warning_count} warnings, {report.skipped_count} skipped"
    )

    if report.passed:
        click.secho("Verification PASSED", fg="green", bold=True)
    else:
        click.secho("Verification FAILED", fg="red", bold=True)


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

        csaf_vex = CSAFVEXDocument.from_dict(data)

        click.echo(f"Successfully read CSAF VEX file: {file}")
        click.echo(f"Title: {csaf_vex.document.title}")
        click.echo(f"Tracking ID: {csaf_vex.document.tracking_id}")
        click.echo(f"Product tree entries: {len(csaf_vex.product_tree)}")
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
        verifier = Verifier.from_file(file)

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

        if not report.passed:
            ctx.exit(1)

    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {file}: {e}") from None
    except Exception as e:
        raise click.ClickException(f"Error verifying file {file}: {e}") from None


if __name__ == "__main__":
    main()
