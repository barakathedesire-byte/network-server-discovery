"""Web interface CLI launcher."""

import click
from .web import WebInterface
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@click.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, type=int, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def main(host: str, port: int, debug: bool):
    """Launch the web interface for network server discovery."""
    click.echo(f"🌐 Starting Network Server Discovery Web Interface")
    click.echo(f"   Address: http://{host}:{port}")
    click.echo(f"   Debug mode: {debug}")
    click.echo()
    
    web = WebInterface(host=host, port=port)
    web.run(debug=debug)


if __name__ == '__main__':
    main()
