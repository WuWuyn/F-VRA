import typer

from pyshare_server.commands import advisories, localization_debug, localize, summaries

app = typer.Typer(
    name="pyshare-server",
    help="Server-side CVE-to-vulnerable-function tools",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.command(name="localize")(localize.localize)
app.add_typer(advisories.app, name="advisories")
app.add_typer(localization_debug.app, name="localization")
app.add_typer(summaries.app, name="summaries")


if __name__ == "__main__":
    app()
