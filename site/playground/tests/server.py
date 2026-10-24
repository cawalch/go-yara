"""Serve the built site under its Pages base path for browser checks."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DIST = Path(__file__).resolve().parents[2] / 'dist'


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIST), **kwargs)

    def do_GET(self):
        if not self.path.startswith('/go-yara/'):
            self.send_error(404)
            return
        self.path = '/' + self.path[len('/go-yara/'):]
        super().do_GET()

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(('127.0.0.1', 4333), Handler).serve_forever()
