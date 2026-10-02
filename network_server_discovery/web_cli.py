from pathlib import Path

from .web import app


def run_web_server():
    host = "0.0.0.0"
    port = 5000
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_web_server()
