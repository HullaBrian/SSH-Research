from typing import Optional
import typer
from loguru import logger

from SSH import __app_name__, __version__
from SSH.initialization import connect as connect_to_client
from SSH.types import IP


app = typer.Typer()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    )
) -> None:
    return


@app.command()
def connect(ip: str):
    try:
        ip = IP(*ip.split("."))
    except TypeError:
        logger.error("Can not connect to client IP: IP is not in a valid format!")
        return
    logger.info(f"Connecting to {str(ip)}")
    connect_to_client(ip)


if __name__ == "__main__":
    app()
