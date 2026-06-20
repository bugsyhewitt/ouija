"""MCPServer target adapter — the §8 centerpiece (Packet 02 §5/§8).

Wraps an MCP client session (:class:`ouija.mcp_proto.ClientSession` for an
in-process / lab server; :class:`ouija.mcp_proto.SdkBridge` for a live
streamable-HTTP server via the optional real ``mcp`` SDK). ``capabilities()``
calls ``tools/list`` + ``resources/list``; ``list_surface()`` returns the raw
advertised tool descriptions + schemas the §8.1 linter scans; ``send()`` can read
descriptions, call a tool with crafted args, or (when an agent is wired) drive an
agent and observe whether a poisoned tool/description changes behaviour.

Construct one of:
* ``MCPServer.from_server(server)`` — wrap an in-process :class:`ouija.mcp_proto.Server`.
* ``MCPServer(url=..., token=...)`` — wrap a live HTTP MCP endpoint (needs the SDK).
"""

from __future__ import annotations

from ouija.mcp_proto import ClientSession, SdkBridge, Server
from ouija.targets.base import Turn


class MCPServer:
    """Adapter over an MCP server (in-process lab server or live HTTP endpoint)."""

    kind = "mcp"

    def __init__(self, url: str | None = None, token: str | None = None,
                 *, session=None) -> None:
        self.url = url or "inproc://mcp"
        self._token = token
        if session is not None:
            self._session = session
        elif url is not None:
            # Live endpoint via the optional real SDK bridge.
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            self._session = SdkBridge(url, headers=headers)
        else:
            raise ValueError("MCPServer needs a url= or an in-process session=")
        self._tools_cache: list | None = None

    @classmethod
    def from_server(cls, server: Server, *, url: str | None = None) -> "MCPServer":
        """Wrap an in-process :class:`ouija.mcp_proto.Server` (the lab path)."""
        sess = ClientSession(server)
        obj = cls(url=url or "inproc://mcp", session=sess)
        return obj

    async def list_surface(self) -> dict:
        """Return the advertised tool surface (names, descriptions, schemas).

        This is what the §8.1 *static* tool-poisoning lint runs against — no agent
        required. Descriptions/schemas are the channel a tool-poisoning attack
        abuses (the model reads them; the user doesn't).
        """
        if hasattr(self._session, "initialize"):
            try:
                await self._session.initialize()
            except Exception:
                pass
        tools = await self._session.list_tools()
        self._tools_cache = tools
        return {
            "tools": [
                {"name": t.name, "description": t.description,
                 "schema": t.input_schema}
                for t in tools
            ]
        }

    async def call_tool(self, name: str, arguments: dict | None = None) -> Turn:
        """Call a tool with crafted args; surface the result as a Turn."""
        result = await self._session.call_tool(name, arguments or {})
        return Turn(
            sent={"tool": name, "arguments": arguments or {}},
            received=result,
            tool_calls=[{"name": name, "args": arguments or {}}],
            raw={"transport": type(self._session).__name__},
        )

    async def read_resource(self, uri: str) -> str:
        """Read a resource (e.g. protected-resource metadata for SSRF probing)."""
        if hasattr(self._session, "read_resource"):
            return await self._session.read_resource(uri)
        return ""

    async def list_resources(self) -> list:
        if hasattr(self._session, "list_resources"):
            return await self._session.list_resources()
        return []

    async def send(self, payload: str | dict) -> Turn:
        """Generic send: a dict ``{"tool":.., "arguments":..}`` calls a tool;
        a bare string is treated as a tool-name with no args."""
        if isinstance(payload, dict) and "tool" in payload:
            return await self.call_tool(payload["tool"], payload.get("arguments", {}))
        if isinstance(payload, str):
            return await self.call_tool(payload, {})
        raise ValueError("MCPServer.send expects a tool name or {'tool':..,'arguments':..}")

    async def reset(self) -> None:
        self._tools_cache = None

    def capabilities(self) -> dict:
        names = [t.name for t in (self._tools_cache or [])]
        return {"kind": self.kind, "tools": names, "resources": [], "retrievers": []}
