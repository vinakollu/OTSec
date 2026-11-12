"""A small HTTP server that streams the event bus to a browser.

Hand-rolled on ``asyncio.start_server`` rather than built on
:mod:`http.server`, for one reason: the stock server is synchronous and
threaded, so feeding it would mean handing events across a thread boundary
while a control loop is running on this side of it. Everything else in this
project already frames its own protocol — Modbus, DNP3, GOOSE, the OPC UA
transport — and HTTP/1.1 for two GET routes is the smallest of them.

It serves exactly what it needs to and refuses the rest:

* ``GET /`` the page,
* ``GET /events`` the stream, as server-sent events, optionally resuming from
  ``?after=`` or the ``Last-Event-ID`` header the browser sends by itself,
* ``GET /healthz`` so a script can wait for the port rather than sleep.

It binds loopback by default and that default is deliberate. The page shows the
state of a control system and exposes no authentication of any kind, so putting
it on an interface anybody else can reach would be an own goal in a project
about operational technology. Binding elsewhere takes an explicit host.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Iterable

from .bus import EventBus
from .page import PAGE

log = logging.getLogger(__name__)

#: Sent when nothing has happened for a while, so that a proxy or a phone's
#: radio does not quietly drop an idle connection. A comment line is the
#: cheapest legal thing in the protocol.
_KEEPALIVE_S = 15.0

_HEAD = (
    "HTTP/1.1 {status}\r\n"
    "Content-Type: {ctype}\r\n"
    "Cache-Control: no-store\r\n"
    "Connection: {conn}\r\n"
    "{extra}"
    "\r\n"
)


class LiveServer:
    """Serves the page and streams the bus to every browser watching."""

    def __init__(
        self,
        bus: EventBus,
        host: str = "127.0.0.1",
        port: int = 8765,
    ) -> None:
        self.bus = bus
        self.host = host
        self.port = port
        self._server: asyncio.AbstractServer | None = None
        self.clients = 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        if self.port == 0:
            self.port = self._server.sockets[0].getsockname()[1]
        log.info("live view on %s", self.url)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        # Not wait_closed(): on 3.12 and later it waits for every open
        # connection to finish, and an SSE connection is open on purpose and
        # for as long as the browser is looking at it. Closing the listener is
        # what shutdown means here.
        self._server = None

    async def __aenter__(self) -> "LiveServer":
        await self.start()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # One connection
    # ------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return

        try:
            head = request.decode("latin-1").split("\r\n")
            method, target, _version = (head[0].split() + ["", "", ""])[:3]
            headers = _parse_headers(head[1:])
        except Exception:
            await self._send(writer, "400 Bad Request", "text/plain", b"bad request")
            return

        path, _, query = target.partition("?")
        if method != "GET":
            await self._send(writer, "405 Method Not Allowed", "text/plain", b"GET only")
            return

        if path == "/":
            await self._send(writer, "200 OK", "text/html; charset=utf-8",
                             PAGE.encode("utf-8"))
        elif path == "/healthz":
            await self._send(writer, "200 OK", "text/plain", b"ok")
        elif path == "/events":
            after = _after(query, headers.get("last-event-id", ""))
            await self._stream(writer, after)
        else:
            await self._send(writer, "404 Not Found", "text/plain", b"not found")

    async def _send(
        self, writer: asyncio.StreamWriter, status: str, ctype: str, body: bytes
    ) -> None:
        head = _HEAD.format(
            status=status, ctype=ctype, conn="close",
            extra=f"Content-Length: {len(body)}\r\n",
        )
        try:
            writer.write(head.encode("latin-1") + body)
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def _stream(self, writer: asyncio.StreamWriter, after: int) -> None:
        """Hold the connection open and write events as they arrive."""
        head = _HEAD.format(
            status="200 OK", ctype="text/event-stream", conn="keep-alive",
            # Without this, a reverse proxy will happily buffer a stream that
            # by definition must not be buffered.
            extra="X-Accel-Buffering: no\r\n",
        )
        subscription = self.bus.subscribe()
        self.clients += 1
        try:
            writer.write(head.encode("latin-1"))
            # Brief the page before anything new arrives, so it draws a full
            # screen immediately instead of an empty one that fills in.
            writer.write(_frames(self.bus.catch_up(after)))
            await writer.drain()

            while True:
                try:
                    event = await asyncio.wait_for(subscription.get(), timeout=_KEEPALIVE_S)
                except asyncio.TimeoutError:
                    writer.write(b": keepalive\n\n")
                    await writer.drain()
                    continue
                writer.write(_frames([event]))
                await writer.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            self.clients -= 1
            self.bus.unsubscribe(subscription)
            with contextlib.suppress(Exception):
                writer.close()


def _frames(events: Iterable) -> bytes:
    """Encode events as SSE frames.

    The ``id:`` line is what makes reconnection cheap: the browser sends the
    last one it saw back as ``Last-Event-ID``, and the server replays only
    what came after it.
    """
    out = []
    for event in events:
        out.append(f"id: {event.seq}\ndata: {event.to_json()}\n\n")
    return "".join(out).encode("utf-8")


def _parse_headers(lines: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return headers


def _after(query: str, last_event_id: str) -> int:
    """Where to resume from, preferring an explicit query over the header."""
    for candidate in (_query_value(query, "after"), last_event_id):
        try:
            value = int(candidate)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def _query_value(query: str, key: str) -> str:
    for part in query.split("&"):
        name, sep, value = part.partition("=")
        if sep and name == key:
            return value
    return ""


__all__ = ["LiveServer"]
