#!/usr/bin/env python3
"""Start Ryu 4.34 with its legacy Eventlet WSGI import compatibility shim.

Ryu 4.34 imports eventlet.wsgi.ALREADY_HANDLED even though newer Eventlet
removed that symbol. This project uses ordinary HTTP routes, not Ryu's
WebSocket wrapper, so supplying the old sentinel lets the WSGI app load.
"""

import eventlet.wsgi

if not hasattr(eventlet.wsgi, "ALREADY_HANDLED"):
    eventlet.wsgi.ALREADY_HANDLED = object()

from ryu.cmd.manager import main  # noqa: E402 - import after compatibility shim


if __name__ == "__main__":
    main()
