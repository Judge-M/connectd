"""Bounded tree traversal; the model is only a choice provider, never authority."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


class RouteError(Exception):
    pass


@dataclass(frozen=True)
class Hop:
    number: int
    node_id: str
    selected_option_id: str


@dataclass(frozen=True)
class Route:
    leaf: Mapping[str, Any]
    hops: tuple[Hop, ...]


def traverse(tree: Mapping[str, Any], choose: Callable[[str, tuple[Mapping[str, Any], ...]], str]) -> Route:
    """Accept only choices present at each node and resolve one leaf in at most three hops."""
    nodes = tree["nodes"]
    node_id = tree["root_node"]
    hops: list[Hop] = []
    seen: set[str] = set()
    for expected_hop in range(1, 4):
        if node_id in seen or node_id not in nodes:
            raise RouteError("cycle or missing routing node")
        seen.add(node_id)
        node = nodes[node_id]
        if node.get("hop") != expected_hop:
            raise RouteError("invalid hop order")
        options = tuple(node["options"])
        if not 1 <= len(options) <= 4:
            raise RouteError("each node must have one to four options")
        selected = choose(node_id, options)
        matches = [option for option in options if option.get("id") == selected]
        if len(matches) != 1:
            raise RouteError("choice is not an option at this node")
        option = matches[0]
        hops.append(Hop(expected_hop, node_id, selected))
        next_node = option.get("next_node")
        if next_node == "LEAF_RESOLVED":
            if expected_hop < 2:
                raise RouteError("leaf resolved before second hop")
            return Route(option, tuple(hops))
        if not isinstance(next_node, str):
            raise RouteError("option has no next node")
        node_id = next_node
    raise RouteError("tree exceeded three hops")


def one_tool_schema(route: Route, registry: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    tool_id = route.leaf.get("resolved_tool_id")
    if not isinstance(tool_id, str) or tool_id not in registry:
        raise RouteError("leaf does not resolve to an active tool")
    return registry[tool_id]
