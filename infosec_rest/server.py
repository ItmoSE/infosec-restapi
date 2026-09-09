from __future__ import annotations

import os
from http.server import ThreadingHTTPServer

from infosec_rest.app import Api
from infosec_rest.db import connect, initialize


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    connection = connect()
    initialize(connection, admin_password=os.environ.get("INFOSEC_ADMIN_PASSWORD"))
    api = Api(connection)
    server = ThreadingHTTPServer((host, port), api.handler())
    print(f"Serving on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
