"""Generic search escape hatches: raw LDAP filter and DN lookup."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def ldap_search(
        search_filter: Annotated[
            str,
            Field(
                description=(
                    "Raw RFC 4515 LDAP filter, e.g. '(&(objectClass=user)(department=Finance))'. "
                    "Caller is responsible for filter escaping."
                )
            ),
        ],
        base_dn: Annotated[
            str,
            Field(default="", description="Search base. Defaults to the configured base DN."),
        ] = "",
        scope: Annotated[
            str,
            Field(default="subtree", description="One of: base, level (one), subtree."),
        ] = "subtree",
        attributes: Annotated[
            list[str] | None,
            Field(
                default=None,
                description=(
                    "Attributes to return. Omit for all attributes. "
                    "Pass a short list to reduce response size."
                ),
            ),
        ] = None,
        limit: Annotated[int, Field(default=50, ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        """Run an arbitrary read-only LDAP search. Escape hatch for advanced queries."""
        results = client.search(
            search_filter=search_filter,
            base_dn=base_dn or None,
            scope=scope,
            attributes=attributes,
            size_limit=limit,
            page_size=limit,
        )
        return {"count": len(results), "entries": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_object_by_dn(
        dn: Annotated[str, Field(description="Full distinguishedName of any AD object.")],
        attributes: Annotated[
            list[str] | None,
            Field(default=None, description="Attributes to return. Omit for all."),
        ] = None,
    ) -> dict[str, Any]:
        """Return any AD object by its distinguishedName."""
        obj = client.read_object(dn, attributes=attributes)
        if obj is None:
            return {"found": False, "dn": dn}
        return {"found": True, "object": obj}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def count_objects(
        search_filter: Annotated[
            str,
            Field(description="LDAP filter to count matches for, e.g. '(objectCategory=person)'."),
        ],
        base_dn: Annotated[str, Field(default="")] = "",
    ) -> dict[str, Any]:
        """Return the number of objects matching a filter (up to the max page size cap)."""
        # We rely on the server's max_page_size ceiling — this is a rough count, not an exact one.
        results = client.search(
            search_filter=search_filter,
            base_dn=base_dn or None,
            attributes=["distinguishedName"],
        )
        return {
            "search_filter": search_filter,
            "count": len(results),
            "capped": len(results) >= client._settings.max_page_size,  # noqa: SLF001
        }
