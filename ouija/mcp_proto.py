"""Minimal, dependency-free MCP (Model Context Protocol) client + server.

WHY THIS EXISTS (a packet-vs-repo adaptation, documented per the build rules):
Packet 02 sketches the MCP target adapter against ``from mcp import ClientSession``
and the lab fixture against ``from necromancer_mcp import Server, Finding`` (the
Packet 01 contract). On this machine **neither is available**: the ``mcp`` Python
SDK is not installed in ouija's venv, and ``necromancer_mcp`` exists only as a Go
package (``~/dev/necromancer/necromancer-mcp/go``) — there is no Python ``Server``
class to import. ouija's hard constraint is "no new mandatory deps" (pyproject
pins only httpx + pydantic) and "headless, no network installs in CI".

So ouija ships its own tiny MCP implementation of the *subset of the wire protocol
the attack surface needs*: ``initialize``, ``tools/list``, ``tools/call``,
``resources/list``, ``resources/read``. MCP is JSON-RPC 2.0; this models that
faithfully enough to (a) drive a target server's advertised surface for the
tool-poisoning lint and dynamic confirm, and (b) stand up the deliberately
vulnerable lab server (Appendix A) in-process. When the real ``mcp`` SDK *is*
installed, :func:`real_sdk_available` reports it and :class:`SdkBridge` adapts a
streamable-HTTP MCP endpoint — so a live MCP server (the §16 acceptance tier-3
smoke, or a real engagement target) is reachable without changing the modules.

[Worker decision: an in-process transport (direct method dispatch, no sockets) is
the default because it is deterministic, headless, and needs no port — exactly
what the test plan wants. A JSON-RPC framing layer is provided too so the same
``Server`` can run over stdio if ever needed, but the lab and tests use the
in-process path.]
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

PROTOCOL_VERSION = "2025-11-25"  # the MCP spec revision the packet cites (§2)


# --- advertised surface types ----------------------------------------------


@dataclass
class ToolDef:
    """A tool as advertised by ``tools/list`` — name, description, input schema.

    The ``description`` and ``input_schema`` are the *advertised* surface the
    model reads; the tool-poisoning linter (Appendix B) scans exactly these.
    """

    name: str
    description: str
    input_schema: dict = field(default_factory=dict)

    def to_wire(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass
class ResourceDef:
    uri: str
    name: str
    description: str = ""

    def to_wire(self) -> dict:
        return {"uri": self.uri, "name": self.name, "description": self.description}


class McpError(Exception):
    """A JSON-RPC / MCP-level error surfaced to the caller."""


# --- server -----------------------------------------------------------------


_Handler = Callable[..., Any]


class Server:
    """A minimal MCP server.

    Register tools with the :meth:`tool` decorator. The tool's ``__doc__`` becomes
    its advertised ``description`` (this is the channel a tool-poisoning attack
    abuses — a hidden instruction in the docstring). A tool may be a plain or
    ``async`` function; both are awaited correctly.

    This mirrors the Packet 01 ``necromancer_mcp.Server`` shape closely enough
    that the lab fixture (Appendix A) reads almost verbatim, but is self-contained.
    """

    def __init__(self, name: str, version: str = "0.0.1") -> None:
        self.name = name
        self.version = version
        self._tools: dict[str, ToolDef] = {}
        self._handlers: dict[str, _Handler] = {}
        self._resources: dict[str, ResourceDef] = {}
        self._resource_readers: dict[str, Callable[[], str]] = {}
        self._initialized = False

    # registration -----------------------------------------------------------

    def tool(self, fn: _Handler | None = None, *, name: str | None = None,
             description: str | None = None, input_schema: dict | None = None):
        """Register *fn* as an MCP tool.

        Usable bare (``@srv.tool``) or parameterised
        (``@srv.tool(name=..., description=...)``). The description defaults to the
        function's docstring — deliberately, so a poisoned docstring becomes a
        poisoned advertised description (the lab's whole point).
        """

        def register(func: _Handler) -> _Handler:
            tname = name or func.__name__
            tdesc = description if description is not None else (func.__doc__ or "")
            schema = input_schema if input_schema is not None else _schema_from_sig(func)
            self._tools[tname] = ToolDef(tname, tdesc, schema)
            self._handlers[tname] = func
            return func

        if fn is not None:  # bare @srv.tool
            return register(fn)
        return register  # @srv.tool(...)

    def set_tool_description(self, name: str, description: str) -> None:
        """Mutate a tool's advertised description in place (drives rug-pull tests)."""
        if name not in self._tools:
            raise KeyError(name)
        td = self._tools[name]
        self._tools[name] = ToolDef(td.name, description, td.input_schema)

    def resource(self, uri: str, name: str, description: str = ""):
        """Register a resource and its reader (used for protected-resource metadata)."""

        def register(reader: Callable[[], str]) -> Callable[[], str]:
            self._resources[uri] = ResourceDef(uri, name, description)
            self._resource_readers[uri] = reader
            return reader

        return register

    # JSON-RPC dispatch ------------------------------------------------------

    async def handle(self, request: dict) -> dict:
        """Dispatch a single JSON-RPC request object, return a response object."""
        rid = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        try:
            result = await self._dispatch(method, params)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except McpError as exc:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32000, "message": str(exc)}}
        except Exception as exc:  # noqa: BLE001 — surface as JSON-RPC error
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": f"internal error: {exc}"}}

    async def _dispatch(self, method: str | None, params: dict) -> Any:
        if method == "initialize":
            self._initialized = True
            return {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {"name": self.name, "version": self.version},
                "capabilities": {"tools": {}, "resources": {}},
            }
        if method == "tools/list":
            return {"tools": [t.to_wire() for t in self._tools.values()]}
        if method == "resources/list":
            return {"resources": [r.to_wire() for r in self._resources.values()]}
        if method == "resources/read":
            uri = params.get("uri", "")
            reader = self._resource_readers.get(uri)
            if reader is None:
                raise McpError(f"unknown resource {uri!r}")
            return {"contents": [{"uri": uri, "text": reader()}]}
        if method == "tools/call":
            tname = params.get("name", "")
            args = params.get("arguments", {}) or {}
            handler = self._handlers.get(tname)
            if handler is None:
                raise McpError(f"unknown tool {tname!r}")
            value = handler(**args)
            if inspect.isawaitable(value):
                value = await value
            text = value if isinstance(value, str) else json.dumps(value)
            return {"content": [{"type": "text", "text": text}], "isError": False}
        raise McpError(f"unknown method {method!r}")

    # stdio loop (provided for parity; lab/tests use the in-process client) ---

    def serve_stdio(self) -> None:  # pragma: no cover - not exercised headless
        """Run a blocking newline-delimited JSON-RPC loop over stdin/stdout."""
        import asyncio
        import sys

        async def loop() -> None:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                resp = await self.handle(json.loads(line))
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

        asyncio.run(loop())

    # convenient alias matching the Appendix A sketch
    def run(self) -> None:  # pragma: no cover
        self.serve_stdio()


def _schema_from_sig(func: _Handler) -> dict:
    """Derive a trivial JSON-schema-ish object from a function signature."""
    props: dict[str, dict] = {}
    required: list[str] = []
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return {"type": "object", "properties": {}}
    for pname, param in sig.parameters.items():
        if pname in ("self", "ctx"):
            continue
        props[pname] = {"type": "string"}
        if param.default is inspect.Parameter.empty:
            required.append(pname)
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


# --- client -----------------------------------------------------------------


class ClientSession:
    """An MCP client session bound to a :class:`Server` over the in-process transport.

    Models the subset of ``mcp.ClientSession`` the adapters use: ``initialize``,
    ``list_tools``, ``call_tool``, ``list_resources``, ``read_resource``. Each call
    is a JSON-RPC round-trip against the server's :meth:`Server.handle`.
    """

    def __init__(self, server: Server) -> None:
        self._server = server
        self._id = 0

    async def _call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method,
               "params": params or {}}
        resp = await self._server.handle(req)
        if "error" in resp:
            raise McpError(resp["error"].get("message", "MCP error"))
        return resp.get("result", {})

    async def initialize(self) -> dict:
        return await self._call("initialize")

    async def list_tools(self) -> list[ToolDef]:
        res = await self._call("tools/list")
        return [
            ToolDef(t["name"], t.get("description", ""), t.get("inputSchema", {}))
            for t in res.get("tools", [])
        ]

    async def call_tool(self, name: str, arguments: dict | None = None) -> str:
        res = await self._call("tools/call",
                               {"name": name, "arguments": arguments or {}})
        parts = res.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text")

    async def list_resources(self) -> list[ResourceDef]:
        res = await self._call("resources/list")
        return [
            ResourceDef(r["uri"], r.get("name", ""), r.get("description", ""))
            for r in res.get("resources", [])
        ]

    async def read_resource(self, uri: str) -> str:
        res = await self._call("resources/read", {"uri": uri})
        parts = res.get("contents", [])
        return "".join(p.get("text", "") for p in parts)


def real_sdk_available() -> bool:
    """True iff the real ``mcp`` Python SDK is importable (optional ``[mcp]`` extra)."""
    try:
        import mcp  # noqa: F401
        return True
    except Exception:
        return False


class SdkBridge:  # pragma: no cover - exercised only with the optional SDK + a live server
    """Adapt a live streamable-HTTP MCP endpoint via the real ``mcp`` SDK.

    Used only when :func:`real_sdk_available` and the operator points ouija at a
    real, allow-listed MCP server. Mirrors the :class:`ClientSession` surface the
    adapters call. Kept import-light: the SDK is imported lazily inside methods so
    ouija never imports it unless this path is taken.
    """

    def __init__(self, url: str, headers: dict | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    async def list_tools(self) -> list[ToolDef]:
        from mcp import ClientSession as _CS
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(self.url, headers=self.headers) as (r, w, _):
            async with _CS(r, w) as s:
                await s.initialize()
                tools = (await s.list_tools()).tools
                return [
                    ToolDef(t.name, t.description or "", dict(t.inputSchema or {}))
                    for t in tools
                ]

    async def call_tool(self, name: str, arguments: dict | None = None) -> str:
        from mcp import ClientSession as _CS
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(self.url, headers=self.headers) as (r, w, _):
            async with _CS(r, w) as s:
                await s.initialize()
                result = await s.call_tool(name, arguments or {})
                out = []
                for c in getattr(result, "content", []) or []:
                    out.append(getattr(c, "text", ""))
                return "".join(out)
