"""Causal chain tracking for Theron.

Tracks the full lineage of how actions come to be, enabling visualization
of attack chains like: "Email read -> content parsed -> shell command attempted"
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import uuid4

from ..storage.models import SourceTag, CausalNodeCreate


@dataclass
class CausalNode:
    """A node in the causal chain."""

    node_id: str
    request_id: str
    parent_id: Optional[str]
    node_type: str  # user_input, content_read, tool_result, tool_call
    source_tag: SourceTag
    content_hash: str
    content_preview: str
    timestamp: datetime
    threat_score: float = 0.0
    metadata: dict = field(default_factory=dict)
    children: list["CausalNode"] = field(default_factory=list)


@dataclass
class CausalChain:
    """A complete causal chain for a request."""

    chain_id: str
    request_id: str
    root_node: CausalNode
    leaf_nodes: list[CausalNode]
    max_depth: int
    total_nodes: int
    risk_score: float
    created_at: datetime
    untrusted_node_count: int = 0
    tool_call_count: int = 0

    def to_graph_data(self) -> dict:
        """Convert chain to graph visualization format."""
        nodes = []
        edges = []

        def traverse(node: CausalNode, depth: int = 0):
            nodes.append({
                "id": node.node_id,
                "label": f"{node.node_type}: {node.content_preview[:30]}...",
                "type": node.node_type,
                "source_tag": node.source_tag.value if isinstance(node.source_tag, SourceTag) else node.source_tag,
                "threat_score": node.threat_score,
                "depth": depth,
                "timestamp": node.timestamp.isoformat() if isinstance(node.timestamp, datetime) else node.timestamp,
            })
            for child in node.children:
                edges.append({
                    "source": node.node_id,
                    "target": child.node_id,
                })
                traverse(child, depth + 1)

        traverse(self.root_node)

        return {
            "chain_id": self.chain_id,
            "request_id": self.request_id,
            "risk_score": self.risk_score,
            "max_depth": self.max_depth,
            "total_nodes": self.total_nodes,
            "nodes": nodes,
            "edges": edges,
        }


class CausalTracker:
    """Tracks causal chains for requests."""

    def __init__(self, db=None):
        """Initialize the causal tracker.

        Args:
            db: Optional database instance for persistence.
        """
        self.db = db
        # In-memory storage for current chains (request_id -> list of nodes)
        self._current_chains: dict[str, list[CausalNode]] = {}
        # Track parent context (request_id -> current_parent_id)
        self._parent_context: dict[str, str] = {}

    def _hash_content(self, content: str) -> str:
        """Create a hash of content for privacy."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _preview_content(self, content: str, max_len: int = 100) -> str:
        """Create a preview of content."""
        if len(content) <= max_len:
            return content
        return content[:max_len] + "..."

    def start_chain(self, request_id: str, user_message: str) -> CausalNode:
        """Create root node from user input.

        Args:
            request_id: Unique request identifier
            user_message: The user's original message

        Returns:
            The root CausalNode
        """
        node = CausalNode(
            node_id=str(uuid4()),
            request_id=request_id,
            parent_id=None,
            node_type="user_input",
            source_tag=SourceTag.USER_DIRECT,
            content_hash=self._hash_content(user_message),
            content_preview=self._preview_content(user_message),
            timestamp=datetime.utcnow(),
            threat_score=0.0,
            metadata={"message_length": len(user_message)},
        )

        self._current_chains[request_id] = [node]
        self._parent_context[request_id] = node.node_id

        return node

    def add_content_node(
        self,
        request_id: str,
        content: str,
        source_tag: SourceTag,
        source_description: Optional[str] = None,
        threat_score: float = 0.0,
    ) -> CausalNode:
        """Track content read (email, file, web page).

        Args:
            request_id: Request identifier
            content: The content that was read
            source_tag: Trust level of the content
            source_description: Description of where content came from
            threat_score: Threat score from injection detection

        Returns:
            The new CausalNode
        """
        parent_id = self._parent_context.get(request_id)

        node = CausalNode(
            node_id=str(uuid4()),
            request_id=request_id,
            parent_id=parent_id,
            node_type="content_read",
            source_tag=source_tag,
            content_hash=self._hash_content(content),
            content_preview=self._preview_content(content),
            timestamp=datetime.utcnow(),
            threat_score=threat_score,
            metadata={
                "source_description": source_description,
                "content_length": len(content),
            },
        )

        if request_id not in self._current_chains:
            self._current_chains[request_id] = []

        self._current_chains[request_id].append(node)
        self._parent_context[request_id] = node.node_id

        # Link to parent
        self._link_to_parent(request_id, node)

        return node

    def add_tool_result_node(
        self,
        request_id: str,
        tool_name: str,
        result: str,
        source_tag: SourceTag = SourceTag.TOOL_RESULT,
        threat_score: float = 0.0,
    ) -> CausalNode:
        """Track tool execution result.

        Args:
            request_id: Request identifier
            tool_name: Name of the tool that produced the result
            result: The tool's output
            source_tag: Trust level (usually TOOL_RESULT)
            threat_score: Threat score from injection detection

        Returns:
            The new CausalNode
        """
        parent_id = self._parent_context.get(request_id)

        node = CausalNode(
            node_id=str(uuid4()),
            request_id=request_id,
            parent_id=parent_id,
            node_type="tool_result",
            source_tag=source_tag,
            content_hash=self._hash_content(result),
            content_preview=self._preview_content(result),
            timestamp=datetime.utcnow(),
            threat_score=threat_score,
            metadata={
                "tool_name": tool_name,
                "result_length": len(result),
            },
        )

        if request_id not in self._current_chains:
            self._current_chains[request_id] = []

        self._current_chains[request_id].append(node)
        self._parent_context[request_id] = node.node_id

        self._link_to_parent(request_id, node)

        return node

    def add_tool_call_node(
        self,
        request_id: str,
        tool_name: str,
        args: dict,
        risk_tier: int = 1,
        source_tag: Optional[SourceTag] = None,
    ) -> CausalNode:
        """Track tool call (potential dangerous action).

        Args:
            request_id: Request identifier
            tool_name: Name of the tool being called
            args: Arguments to the tool
            risk_tier: Risk tier of the tool (1-4)
            source_tag: Override source tag (defaults to inherited)

        Returns:
            The new CausalNode
        """
        parent_id = self._parent_context.get(request_id)

        # Inherit source tag from parent if not specified
        if source_tag is None and request_id in self._current_chains:
            for node in reversed(self._current_chains[request_id]):
                if node.node_id == parent_id:
                    source_tag = node.source_tag
                    break
        source_tag = source_tag or SourceTag.USER_DIRECT

        args_str = json.dumps(args, default=str)

        node = CausalNode(
            node_id=str(uuid4()),
            request_id=request_id,
            parent_id=parent_id,
            node_type="tool_call",
            source_tag=source_tag,
            content_hash=self._hash_content(f"{tool_name}:{args_str}"),
            content_preview=f"{tool_name}({self._preview_content(args_str, 50)})",
            timestamp=datetime.utcnow(),
            threat_score=0.0,  # Tool calls inherit risk from chain
            metadata={
                "tool_name": tool_name,
                "arguments": args,
                "risk_tier": risk_tier,
            },
        )

        if request_id not in self._current_chains:
            self._current_chains[request_id] = []

        self._current_chains[request_id].append(node)

        self._link_to_parent(request_id, node)

        return node

    def _link_to_parent(self, request_id: str, node: CausalNode) -> None:
        """Link a node to its parent in the chain."""
        if node.parent_id and request_id in self._current_chains:
            for parent_node in self._current_chains[request_id]:
                if parent_node.node_id == node.parent_id:
                    parent_node.children.append(node)
                    break

    def get_chain(self, request_id: str) -> Optional[CausalChain]:
        """Build full chain for visualization.

        Args:
            request_id: Request identifier

        Returns:
            CausalChain if exists, None otherwise
        """
        if request_id not in self._current_chains:
            return None

        nodes = self._current_chains[request_id]
        if not nodes:
            return None

        # Find root node
        root = None
        for node in nodes:
            if node.parent_id is None:
                root = node
                break

        if not root:
            root = nodes[0]

        # Find leaf nodes (nodes with no children)
        leaf_nodes = [n for n in nodes if not n.children]

        # Calculate max depth
        max_depth = self._calculate_depth(root)

        # Calculate risk score
        risk_score = self.calculate_chain_risk(nodes)

        # Count untrusted nodes
        untrusted_count = sum(
            1 for n in nodes
            if n.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT)
        )

        # Count tool calls
        tool_call_count = sum(1 for n in nodes if n.node_type == "tool_call")

        return CausalChain(
            chain_id=str(uuid4()),
            request_id=request_id,
            root_node=root,
            leaf_nodes=leaf_nodes,
            max_depth=max_depth,
            total_nodes=len(nodes),
            risk_score=risk_score,
            created_at=datetime.utcnow(),
            untrusted_node_count=untrusted_count,
            tool_call_count=tool_call_count,
        )

    def _calculate_depth(self, node: CausalNode, current_depth: int = 0) -> int:
        """Calculate the maximum depth of the chain from a node."""
        if not node.children:
            return current_depth

        return max(
            self._calculate_depth(child, current_depth + 1)
            for child in node.children
        )

    def get_path_to_action(self, request_id: str, node_id: str) -> list[CausalNode]:
        """Trace back from action to root.

        Args:
            request_id: Request identifier
            node_id: The node to trace back from

        Returns:
            List of nodes from root to the specified node
        """
        if request_id not in self._current_chains:
            return []

        nodes = self._current_chains[request_id]

        # Find the target node
        target = None
        for node in nodes:
            if node.node_id == node_id:
                target = node
                break

        if not target:
            return []

        # Build path by following parent_id
        path = [target]
        current = target

        while current.parent_id:
            for node in nodes:
                if node.node_id == current.parent_id:
                    path.insert(0, node)
                    current = node
                    break
            else:
                break

        return path

    def calculate_chain_risk(self, nodes: Optional[list[CausalNode]] = None) -> float:
        """Calculate risk score for a chain.

        Risk increases with:
        - Chain depth (more steps = more opportunity for manipulation)
        - Untrusted sources (CONTENT_READ, TOOL_RESULT)
        - High threat scores
        - Tool calls following untrusted content

        Args:
            nodes: List of nodes to analyze (or chain nodes)

        Returns:
            Risk score from 0.0 to 1.0
        """
        if not nodes:
            return 0.0

        risk_factors = []

        # Factor 1: Depth risk (longer chains = higher risk)
        depths = []
        for node in nodes:
            path = []
            current = node
            while current.parent_id:
                path.append(current)
                current = next(
                    (n for n in nodes if n.node_id == current.parent_id),
                    None
                )
                if current is None:
                    break
            depths.append(len(path))

        max_depth = max(depths) if depths else 0
        depth_risk = min(max_depth / 10.0, 1.0)  # Normalize to 0-1
        risk_factors.append(depth_risk * 0.2)  # 20% weight

        # Factor 2: Untrusted source risk
        untrusted_count = sum(
            1 for n in nodes
            if n.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT)
        )
        untrusted_risk = min(untrusted_count / 5.0, 1.0)
        risk_factors.append(untrusted_risk * 0.3)  # 30% weight

        # Factor 3: Threat score aggregation
        threat_scores = [n.threat_score for n in nodes if n.threat_score > 0]
        if threat_scores:
            max_threat = max(threat_scores)
            threat_risk = max_threat / 100.0
            risk_factors.append(threat_risk * 0.3)  # 30% weight
        else:
            risk_factors.append(0)

        # Factor 4: Tool calls following untrusted content
        tool_calls_after_untrusted = 0
        for i, node in enumerate(nodes):
            if node.node_type == "tool_call":
                # Check if any predecessor is untrusted
                for prev_node in nodes[:i]:
                    if prev_node.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT):
                        tool_calls_after_untrusted += 1
                        break

        tc_risk = min(tool_calls_after_untrusted / 3.0, 1.0)
        risk_factors.append(tc_risk * 0.2)  # 20% weight

        return sum(risk_factors)

    def has_untrusted_origin(self, request_id: str, node_id: str) -> bool:
        """Check if a node has untrusted content in its ancestry.

        Args:
            request_id: Request identifier
            node_id: Node to check

        Returns:
            True if any ancestor is from untrusted source
        """
        path = self.get_path_to_action(request_id, node_id)
        return any(
            node.source_tag in (SourceTag.CONTENT_READ, SourceTag.TOOL_RESULT)
            for node in path
        )

    def clear_chain(self, request_id: str) -> None:
        """Clear chain data for a request.

        Args:
            request_id: Request to clear
        """
        self._current_chains.pop(request_id, None)
        self._parent_context.pop(request_id, None)

    async def persist_chain(self, request_id: str) -> None:
        """Persist chain to database.

        Args:
            request_id: Request to persist
        """
        if not self.db or request_id not in self._current_chains:
            return

        for node in self._current_chains[request_id]:
            node_create = CausalNodeCreate(
                node_id=node.node_id,
                request_id=node.request_id,
                parent_id=node.parent_id,
                node_type=node.node_type,
                source_tag=node.source_tag.value if isinstance(node.source_tag, SourceTag) else node.source_tag,
                content_hash=node.content_hash,
                content_preview=node.content_preview,
                threat_score=node.threat_score,
                metadata=node.metadata,
            )
            await self.db.create_causal_node(node_create)

    def get_chain_summary(self, request_id: str) -> dict:
        """Get a summary of the chain for logging/display.

        Args:
            request_id: Request identifier

        Returns:
            Dictionary with chain summary
        """
        chain = self.get_chain(request_id)
        if not chain:
            return {"exists": False}

        return {
            "exists": True,
            "total_nodes": chain.total_nodes,
            "max_depth": chain.max_depth,
            "risk_score": round(chain.risk_score, 3),
            "untrusted_nodes": chain.untrusted_node_count,
            "tool_calls": chain.tool_call_count,
            "has_dangerous_pattern": chain.untrusted_node_count > 0 and chain.tool_call_count > 0,
        }
