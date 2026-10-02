from pathlib import Path

from .web import app


def run_web_server():
    app.static_folder = str(Path(__file__).resolve().parent.parent / "static")
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    run_web_server()
