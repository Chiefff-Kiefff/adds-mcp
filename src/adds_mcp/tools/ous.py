"""Organizational-unit tools, including OU tree rendering."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from ..client import ReadOnlyADClient, escape_filter
from ._common import OU_ATTRS


def register(mcp: FastMCP, client: ReadOnlyADClient) -> None:
    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_ous(
        base_dn: Annotated[
            str,
            Field(
                default="",
                description="OU or domain DN to search under. Defaults to the domain root.",
            ),
        ] = "",
        query: Annotated[
            str,
            Field(default="", description="Substring match on OU name or description."),
        ] = "",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List organizational units under a given base."""
        filt = "(objectCategory=organizationalUnit)"
        if query:
            q = escape_filter(query)
            filt = f"(&{filt}(|(ou=*{q}*)(description=*{q}*)))"
        results = client.search(
            search_filter=filt,
            base_dn=base_dn or None,
            attributes=OU_ATTRS,
            size_limit=limit,
        )
        return {"count": len(results), "ous": results}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_ou(
        dn: Annotated[str, Field(description="Full distinguishedName of the OU.")],
    ) -> dict[str, Any]:
        """Return the full attribute set for an OU (including gPLink)."""
        obj = client.read_object(dn, attributes=OU_ATTRS)
        if obj is None:
            return {"found": False, "dn": dn}
        return {"found": True, "ou": obj}

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def list_ou_children(
        dn: Annotated[str, Field(description="Parent OU or container DN.")],
        object_types: Annotated[
            str,
            Field(
                default="all",
                description="Filter direct children: 'ou', 'users', 'groups', 'computers', or 'all'.",
            ),
        ] = "all",
        limit: Annotated[int, Field(default=200, ge=1, le=500)] = 200,
    ) -> dict[str, Any]:
        """List direct children (one-level) of a given OU / container."""
        type_filter = {
            "ou": "(objectCategory=organizationalUnit)",
            "users": "(&(objectCategory=person)(objectClass=user))",
            "groups": "(objectCategory=group)",
            "computers": "(objectCategory=computer)",
            "all": "(objectClass=*)",
        }.get(object_types.lower(), "(objectClass=*)")
        results = client.search(
            search_filter=type_filter,
            base_dn=dn,
            scope="level",
            attributes=[
                "cn",
                "ou",
                "distinguishedName",
                "objectClass",
                "description",
                "sAMAccountName",
            ],
            size_limit=limit,
        )
        return {
            "parent_dn": dn,
            "object_types": object_types,
            "count": len(results),
            "children": results,
        }

    @mcp.tool(
        annotations={
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    def get_ou_tree(
        base_dn: Annotated[
            str,
            Field(
                default="",
                description="Root of the tree. Defaults to the configured domain base DN.",
            ),
        ] = "",
        max_depth: Annotated[
            int,
            Field(default=6, ge=1, le=20, description="How deep to descend."),
        ] = 6,
        limit: Annotated[
            int,
            Field(
                default=1000,
                ge=1,
                le=2000,
                description="Cap on OUs returned across the whole tree.",
            ),
        ] = 1000,
    ) -> dict[str, Any]:
        """Return the OU hierarchy as a nested tree.

        Uses a single subtree search then rebuilds parent/child relationships in memory.
        """
        results = client.search(
            search_filter="(objectCategory=organizationalUnit)",
            base_dn=base_dn or None,
            scope="subtree",
            attributes=["ou", "distinguishedName", "description", "gPLink"],
            size_limit=limit,
        )

        # Map DN -> node.
        nodes: dict[str, dict[str, Any]] = {}
        for entry in results:
            dn = entry["dn"]
            attrs = entry.get("attributes", {})
            nodes[dn.lower()] = {
                "dn": dn,
                "name": attrs.get("ou") or dn.split(",", 1)[0].split("=", 1)[-1],
                "description": attrs.get("description"),
                "has_gpo_links": bool(attrs.get("gPLink")),
                "children": [],
            }

        root_dn = (base_dn or "").lower()
        roots: list[dict[str, Any]] = []
        for dn_lower, node in nodes.items():
            parent = dn_lower.split(",", 1)[1] if "," in dn_lower else ""
            if parent in nodes:
                nodes[parent]["children"].append(node)
            else:
                roots.append(node)

        def _truncate(node: dict[str, Any], depth: int) -> dict[str, Any]:
            if depth >= max_depth:
                node = {**node, "children": [], "truncated": bool(node["children"])}
                return node
            return {**node, "children": [_truncate(c, depth + 1) for c in node["children"]]}

        pruned = [_truncate(r, 0) for r in roots]
        return {
            "base_dn": base_dn or "(configured default)",
            "ou_count": len(results),
            "roots": pruned,
        }
