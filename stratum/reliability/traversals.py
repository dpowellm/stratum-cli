"""Five reusable graph traversal primitives for reliability analysis.

1. PATH — find all paths of given edge types between node sets
2. PAIR_SHARED_STATE — find agent pairs sharing data stores
3. CYCLE — detect cycles in delegation/data flow subgraphs
4. CENTRALITY — compute betweenness centrality for agent nodes
5. TRANSITIVE_CLOSURE — compute transitive capability reachability
"""
from __future__ import annotations

from collections import defaultdict

from stratum.graph.models import EdgeType, GraphNode, NodeType, RiskGraph


# ---------------------------------------------------------------------------
# 1. PATH: Find all paths through specified edge types
# ---------------------------------------------------------------------------

def find_paths(
    graph: RiskGraph,
    edge_types: set[str],
    source_filter: str | None = None,
    min_length: int = 2,
    max_length: int = 10,
) -> list[list[str]]:
    """Find all paths through edges of given types.

    Args:
        graph: The risk graph
        edge_types: Set of edge type values to traverse
        source_filter: If set, only start from nodes of this NodeType
        min_length: Minimum path length (in nodes)
        max_length: Maximum path length (in nodes)

    Returns:
        List of paths, each path is a list of node IDs
    """
    # Build adjacency list for specified edge types
    adj: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        etype = edge.edge_type.value if hasattr(edge.edge_type, 'value') else edge.edge_type
        if etype in edge_types:
            adj[edge.source].append(edge.target)

    # Determine start nodes
    start_nodes = []
    for nid, node in graph.nodes.items():
        if source_filter:
            ntype = node.node_type.value if hasattr(node.node_type, 'value') else node.node_type
            if ntype != source_filter:
                continue
        if nid in adj:
            start_nodes.append(nid)

    # DFS to find all paths
    all_paths: list[list[str]] = []

    def _dfs(current: str, path: list[str], visited: set[str]) -> None:
        if len(path) >= min_length:
            all_paths.append(list(path))
        if len(path) >= max_length:
            return
        for neighbor in adj.get(current, []):
            if neighbor not in visited:
                visited.add(neighbor)
                path.append(neighbor)
                _dfs(neighbor, path, visited)
                path.pop()
                visited.discard(neighbor)

    for start in start_nodes:
        _dfs(start, [start], {start})

    return all_paths


# ---------------------------------------------------------------------------
# 2. PAIR_SHARED_STATE: Find agent pairs sharing data stores
# ---------------------------------------------------------------------------

def find_pairs_shared_state(
    graph: RiskGraph,
    require_write: bool = True,
) -> list[tuple[str, str, list[str]]]:
    """Find pairs of agents that share data stores.

    Args:
        graph: The risk graph
        require_write: If True, at least one agent must write to the shared store

    Returns:
        List of (agent_a, agent_b, shared_store_ids) tuples
    """
    # Build agent -> tools -> data stores maps
    agent_tools: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF:
            agent_tools[edge.target].add(edge.source)

    # Build tool -> data store read/write maps
    tool_reads: dict[str, set[str]] = defaultdict(set)
    tool_writes: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.READS_FROM:
            tool_reads[edge.target].add(edge.source)  # READS_FROM: ds -> cap
        elif edge.edge_type == EdgeType.WRITES_TO:
            tool_writes[edge.source].add(edge.target)  # WRITES_TO: cap -> ds

    # Build agent -> data stores read/written
    agent_reads: dict[str, set[str]] = defaultdict(set)
    agent_writes: dict[str, set[str]] = defaultdict(set)

    for agent_id, tools in agent_tools.items():
        for tool_id in tools:
            agent_reads[agent_id].update(tool_reads.get(tool_id, set()))
            agent_writes[agent_id].update(tool_writes.get(tool_id, set()))

    # Also check for agents that share data stores directly (without tools)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.READS_FROM:
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if src and src.node_type == NodeType.DATA_STORE:
                if tgt and tgt.node_type == NodeType.AGENT:
                    agent_reads[edge.target].add(edge.source)
        elif edge.edge_type == EdgeType.WRITES_TO:
            src = graph.nodes.get(edge.source)
            tgt = graph.nodes.get(edge.target)
            if tgt and tgt.node_type == NodeType.DATA_STORE:
                if src and src.node_type == NodeType.AGENT:
                    agent_writes[edge.source].add(edge.target)

    # Find pairs
    agents = [
        nid for nid, n in graph.nodes.items()
        if n.node_type == NodeType.AGENT
    ]

    pairs: list[tuple[str, str, list[str]]] = []
    seen: set[tuple[str, str]] = set()

    for i, a in enumerate(agents):
        a_stores = agent_reads.get(a, set()) | agent_writes.get(a, set())
        for b in agents[i + 1:]:
            b_stores = agent_reads.get(b, set()) | agent_writes.get(b, set())
            shared = a_stores & b_stores
            if not shared:
                continue

            if require_write:
                # At least one must write to a shared store
                a_writes_shared = agent_writes.get(a, set()) & shared
                b_writes_shared = agent_writes.get(b, set()) & shared
                if not a_writes_shared and not b_writes_shared:
                    continue

            key = (min(a, b), max(a, b))
            if key not in seen:
                seen.add(key)
                pairs.append((a, b, sorted(shared)))

    return pairs


# ---------------------------------------------------------------------------
# 3. CYCLE: Detect cycles in the graph
# ---------------------------------------------------------------------------

def detect_cycles(
    graph: RiskGraph,
    edge_types: set[str] | None = None,
    node_type_filter: str | None = None,
) -> list[list[str]]:
    """Detect all cycles using DFS-based algorithm.

    Args:
        graph: The risk graph
        edge_types: Edge types to consider (default: delegates_to, feeds_into)
        node_type_filter: Only consider nodes of this type (default: agent)

    Returns:
        List of cycles, each cycle is a list of node IDs
    """
    if edge_types is None:
        edge_types = {EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value}

    # Build adjacency
    adj: dict[str, list[str]] = defaultdict(list)
    for edge in graph.edges:
        etype = edge.edge_type.value if hasattr(edge.edge_type, 'value') else edge.edge_type
        if etype in edge_types:
            src_node = graph.nodes.get(edge.source)
            tgt_node = graph.nodes.get(edge.target)
            if node_type_filter:
                if src_node and (src_node.node_type.value if hasattr(src_node.node_type, 'value') else src_node.node_type) != node_type_filter:
                    continue
                if tgt_node and (tgt_node.node_type.value if hasattr(tgt_node.node_type, 'value') else tgt_node.node_type) != node_type_filter:
                    continue
            adj[edge.source].append(edge.target)

    cycles: list[list[str]] = []
    visited: set[str] = set()
    rec_stack: set[str] = set()
    path: list[str] = []

    def _dfs(node: str) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in adj.get(node, []):
            if neighbor not in visited:
                _dfs(neighbor)
            elif neighbor in rec_stack:
                # Found a cycle — extract it
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                # Normalize: start from smallest ID
                min_idx = cycle[:-1].index(min(cycle[:-1]))
                normalized = cycle[min_idx:-1] + cycle[:min_idx] + [cycle[min_idx]]
                cycle_key = tuple(normalized[:-1])
                if cycle_key not in seen_cycles:
                    seen_cycles.add(cycle_key)
                    cycles.append(normalized)

        path.pop()
        rec_stack.discard(node)

    seen_cycles: set[tuple[str, ...]] = set()
    for node in adj:
        if node not in visited:
            _dfs(node)

    return cycles


# ---------------------------------------------------------------------------
# 4. CENTRALITY: Betweenness centrality for agent nodes
# ---------------------------------------------------------------------------

def compute_centrality(
    graph: RiskGraph,
    edge_types: set[str] | None = None,
) -> dict[str, float]:
    """Compute betweenness centrality for agent nodes.

    Uses Brandes' algorithm for unweighted graphs.

    Returns:
        Dict of agent_id -> centrality score (0-1 normalized)
    """
    if edge_types is None:
        edge_types = {
            EdgeType.DELEGATES_TO.value, EdgeType.FEEDS_INTO.value,
            EdgeType.TOOL_OF.value,
        }

    # Build adjacency
    adj: dict[str, list[str]] = defaultdict(list)
    nodes_in_graph: set[str] = set()
    for edge in graph.edges:
        etype = edge.edge_type.value if hasattr(edge.edge_type, 'value') else edge.edge_type
        if etype in edge_types:
            adj[edge.source].append(edge.target)
            nodes_in_graph.add(edge.source)
            nodes_in_graph.add(edge.target)

    if len(nodes_in_graph) < 3:
        return {}

    # Brandes' algorithm
    centrality: dict[str, float] = {n: 0.0 for n in nodes_in_graph}

    for s in nodes_in_graph:
        # BFS from s
        stack: list[str] = []
        pred: dict[str, list[str]] = {n: [] for n in nodes_in_graph}
        sigma: dict[str, int] = {n: 0 for n in nodes_in_graph}
        sigma[s] = 1
        dist: dict[str, int] = {n: -1 for n in nodes_in_graph}
        dist[s] = 0
        queue = [s]

        while queue:
            v = queue.pop(0)
            stack.append(v)
            for w in adj.get(v, []):
                if w not in nodes_in_graph:
                    continue
                if dist[w] < 0:
                    queue.append(w)
                    dist[w] = dist[v] + 1
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        # Accumulation
        delta: dict[str, float] = {n: 0.0 for n in nodes_in_graph}
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / max(sigma[w], 1)) * (1 + delta[w])
            if w != s:
                centrality[w] += delta[w]

    # Normalize
    n = len(nodes_in_graph)
    if n > 2:
        norm = 1.0 / ((n - 1) * (n - 2))
        centrality = {k: v * norm for k, v in centrality.items()}

    # Filter to agent nodes only
    return {
        nid: score for nid, score in centrality.items()
        if nid in graph.nodes and graph.nodes[nid].node_type == NodeType.AGENT
    }


# ---------------------------------------------------------------------------
# 5. TRANSITIVE_CLOSURE: Compute effective capabilities through delegation
# ---------------------------------------------------------------------------

def compute_transitive_capabilities(
    graph: RiskGraph,
) -> dict[str, tuple[set[str], set[str]]]:
    """Compute direct and effective capabilities for each agent.

    Returns:
        Dict of agent_id -> (direct_tool_ids, effective_tool_ids)
        where effective = direct + transitive through delegation
    """
    # Build agent -> direct tools
    agent_direct: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type == EdgeType.TOOL_OF:
            agent_direct[edge.target].add(edge.source)

    # Build delegation adjacency
    delegation_adj: dict[str, set[str]] = defaultdict(set)
    for edge in graph.edges:
        if edge.edge_type in (EdgeType.DELEGATES_TO, EdgeType.FEEDS_INTO):
            delegation_adj[edge.source].add(edge.target)

    result: dict[str, tuple[set[str], set[str]]] = {}

    for agent_id in agent_direct:
        node = graph.nodes.get(agent_id)
        if not node or node.node_type != NodeType.AGENT:
            continue

        direct = agent_direct[agent_id]

        # BFS through delegation to find all reachable agents
        visited: set[str] = set()
        queue = list(delegation_adj.get(agent_id, set()))
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(delegation_adj.get(current, set()) - visited)

        # Collect tools of reachable agents
        effective = set(direct)
        for reached_id in visited:
            effective.update(agent_direct.get(reached_id, set()))

        result[agent_id] = (direct, effective)

    return result
