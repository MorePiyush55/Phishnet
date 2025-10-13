"""
Playbook Adapter - Converts Phantom playbooks to PhishNet rule format.

This module parses Phantom playbook Python files and extracts:
- Decision trees and conditions
- Action mappings (url_reputation, file_reputation, etc.)
- Data flow between blocks
- Custom code sections

The extracted rules are converted to a structured format that can be
executed by the PhishNet playbook engine.
"""

import ast
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum

from app.config.logging import get_logger

logger = get_logger(__name__)


class ActionType(str, Enum):
    """Types of actions in playbooks."""
    URL_REPUTATION = "url_reputation"
    FILE_REPUTATION = "file_reputation"
    IP_REPUTATION = "ip_reputation"
    DOMAIN_REPUTATION = "domain_reputation"
    DETONATE_FILE = "detonate_file"
    GEOLOCATE_IP = "geolocate_ip"
    SEARCH_HASH = "search_hash"
    CUSTOM = "custom"


@dataclass
class PlaybookCondition:
    """Represents a decision or filter condition."""
    field: str
    operator: str
    value: Any
    condition_type: str  # "decision", "filter", "join"


@dataclass
class PlaybookAction:
    """Represents an action to be executed."""
    name: str
    action_type: ActionType
    parameters: Dict[str, Any]
    callback: Optional[str] = None
    assets: List[str] = None
    
    def __post_init__(self):
        if self.assets is None:
            self.assets = []


@dataclass
class PlaybookBlock:
    """Represents a block (function) in a playbook."""
    name: str
    block_type: str  # "action", "decision", "filter", "custom"
    description: str
    conditions: List[PlaybookCondition] = None
    actions: List[PlaybookAction] = None
    next_blocks: List[str] = None
    custom_code: Optional[str] = None
    
    def __post_init__(self):
        if self.conditions is None:
            self.conditions = []
        if self.actions is None:
            self.actions = []
        if self.next_blocks is None:
            self.next_blocks = []


@dataclass
class PlaybookRule:
    """Complete playbook rule structure."""
    playbook_name: str
    playbook_file: str
    description: str
    entry_point: str
    blocks: Dict[str, PlaybookBlock]
    severity_changes: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.severity_changes is None:
            self.severity_changes = []


class PlaybookAdapter:
    """Parses Phantom playbook files and converts them to PhishNet rules."""
    
    def __init__(self, playbook_dir: Path):
        self.playbook_dir = Path(playbook_dir)
        self.logger = logger
        
    def parse_playbook_file(self, playbook_path: Path) -> Optional[PlaybookRule]:
        """Parse a single playbook Python file."""
        try:
            self.logger.info(f"Parsing playbook: {playbook_path.name}")
            
            content = playbook_path.read_text(encoding='utf-8')
            tree = ast.parse(content)
            
            # Extract module docstring
            description = ast.get_docstring(tree) or "No description"
            
            # Parse all function blocks
            blocks = {}
            entry_point = "on_start"
            severity_changes = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    block = self._parse_function_block(node, content)
                    if block:
                        blocks[block.name] = block
                        
                        # Detect severity changes
                        if "set_severity" in block.name or "severity" in ast.unparse(node):
                            severity_changes.append({
                                "block": block.name,
                                "action": "set_severity"
                            })
            
            # Build rule structure
            rule = PlaybookRule(
                playbook_name=playbook_path.stem,
                playbook_file=playbook_path.name,
                description=description,
                entry_point=entry_point,
                blocks=blocks,
                severity_changes=severity_changes
            )
            
            self.logger.info(f"Parsed {len(blocks)} blocks from {playbook_path.name}")
            return rule
            
        except Exception as e:
            self.logger.error(f"Failed to parse playbook {playbook_path}: {e}")
            return None
    
    def _parse_function_block(self, node: ast.FunctionDef, source: str) -> Optional[PlaybookBlock]:
        """Parse a single function block."""
        try:
            func_name = node.name
            func_doc = ast.get_docstring(node) or ""
            
            # Determine block type
            block_type = self._determine_block_type(node, source)
            
            # Extract conditions
            conditions = self._extract_conditions(node)
            
            # Extract actions
            actions = self._extract_actions(node)
            
            # Extract callbacks (next blocks)
            next_blocks = self._extract_callbacks(node)
            
            # Extract custom code
            custom_code = self._extract_custom_code(node, source)
            
            block = PlaybookBlock(
                name=func_name,
                block_type=block_type,
                description=func_doc,
                conditions=conditions,
                actions=actions,
                next_blocks=next_blocks,
                custom_code=custom_code
            )
            
            return block
            
        except Exception as e:
            self.logger.error(f"Failed to parse function {node.name}: {e}")
            return None
    
    def _determine_block_type(self, node: ast.FunctionDef, source: str) -> str:
        """Determine the type of block."""
        func_source = ast.unparse(node)
        
        if "phantom.act" in func_source:
            return "action"
        elif "phantom.decision" in func_source:
            return "decision"
        elif "phantom.condition" in func_source or "filter" in node.name.lower():
            return "filter"
        elif "phantom.custom" in func_source or "Custom Code" in func_source:
            return "custom"
        else:
            return "logic"
    
    def _extract_conditions(self, node: ast.FunctionDef) -> List[PlaybookCondition]:
        """Extract conditions from decision or filter blocks."""
        conditions = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                
                # Check for phantom.condition or phantom.decision
                if isinstance(func, ast.Attribute):
                    if func.attr in ["condition", "decision"]:
                        # Extract condition parameters
                        for keyword in child.keywords:
                            if keyword.arg == "conditions":
                                # Parse conditions list
                                cond_list = self._parse_condition_list(keyword.value)
                                conditions.extend(cond_list)
        
        return conditions
    
    def _parse_condition_list(self, cond_node) -> List[PlaybookCondition]:
        """Parse a conditions list from AST."""
        conditions = []
        
        if isinstance(cond_node, ast.List):
            for elem in cond_node.elts:
                if isinstance(elem, ast.List) and len(elem.elts) >= 2:
                    # Format: ["field", "operator", "value"]
                    field = self._extract_string_value(elem.elts[0]) if elem.elts else ""
                    operator = self._extract_string_value(elem.elts[1]) if len(elem.elts) > 1 else ""
                    value = self._extract_string_value(elem.elts[2]) if len(elem.elts) > 2 else ""
                    
                    if field and operator:
                        conditions.append(PlaybookCondition(
                            field=field,
                            operator=operator,
                            value=value,
                            condition_type="filter"
                        ))
        
        return conditions
    
    def _extract_string_value(self, node) -> str:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Str):
            return node.s
        else:
            return ast.unparse(node)
    
    def _extract_actions(self, node: ast.FunctionDef) -> List[PlaybookAction]:
        """Extract phantom.act actions."""
        actions = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                func = child.func
                
                # Check for phantom.act
                if isinstance(func, ast.Attribute) and func.attr == "act":
                    action = self._parse_action_call(child)
                    if action:
                        actions.append(action)
        
        return actions
    
    def _parse_action_call(self, call_node: ast.Call) -> Optional[PlaybookAction]:
        """Parse a phantom.act call."""
        try:
            action_name = ""
            action_type = ActionType.CUSTOM
            parameters = {}
            callback = None
            assets = []
            
            # First positional arg is action type
            if call_node.args:
                action_name = self._extract_string_value(call_node.args[0])
                action_type = self._map_action_type(action_name)
            
            # Extract keyword arguments
            for keyword in call_node.keywords:
                if keyword.arg == "parameters":
                    # Parameters is a list or dict
                    parameters = self._extract_parameters(keyword.value)
                elif keyword.arg == "callback":
                    callback = self._extract_string_value(keyword.value)
                elif keyword.arg == "name":
                    action_name = self._extract_string_value(keyword.value)
                elif keyword.arg == "assets":
                    assets = self._extract_list_values(keyword.value)
            
            return PlaybookAction(
                name=action_name,
                action_type=action_type,
                parameters=parameters,
                callback=callback,
                assets=assets
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse action call: {e}")
            return None
    
    def _map_action_type(self, action_name: str) -> ActionType:
        """Map action name to ActionType enum."""
        action_lower = action_name.lower().replace(" ", "_")
        
        mapping = {
            "url_reputation": ActionType.URL_REPUTATION,
            "file_reputation": ActionType.FILE_REPUTATION,
            "ip_reputation": ActionType.IP_REPUTATION,
            "domain_reputation": ActionType.DOMAIN_REPUTATION,
            "detonate_file": ActionType.DETONATE_FILE,
            "geolocate_ip": ActionType.GEOLOCATE_IP,
        }
        
        return mapping.get(action_lower, ActionType.CUSTOM)
    
    def _extract_parameters(self, node) -> Dict[str, Any]:
        """Extract parameters dict or list."""
        if isinstance(node, ast.List):
            # List of parameter dicts
            return {"_list": [self._node_to_value(elem) for elem in node.elts]}
        elif isinstance(node, ast.Dict):
            return self._node_to_value(node)
        else:
            return {}
    
    def _extract_list_values(self, node) -> List[str]:
        """Extract list of string values."""
        if isinstance(node, ast.List):
            return [self._extract_string_value(elem) for elem in node.elts]
        return []
    
    def _node_to_value(self, node) -> Any:
        """Convert AST node to Python value."""
        if isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Dict):
            return {
                self._extract_string_value(k): self._node_to_value(v)
                for k, v in zip(node.keys, node.values)
            }
        elif isinstance(node, ast.List):
            return [self._node_to_value(elem) for elem in node.elts]
        else:
            return ast.unparse(node)
    
    def _extract_callbacks(self, node: ast.FunctionDef) -> List[str]:
        """Extract callback function names."""
        callbacks = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                # Look for callback= arguments
                for keyword in child.keywords:
                    if keyword.arg == "callback":
                        callback_name = self._extract_string_value(keyword.value)
                        if callback_name:
                            callbacks.append(callback_name)
        
        return callbacks
    
    def _extract_custom_code(self, node: ast.FunctionDef, source: str) -> Optional[str]:
        """Extract custom code section."""
        func_source = ast.unparse(node)
        
        # Look for custom code markers
        pattern = r'## Custom Code Start(.*?)## Custom Code End'
        match = re.search(pattern, func_source, re.DOTALL)
        
        if match:
            return match.group(1).strip()
        
        return None
    
    def parse_all_playbooks(self) -> List[PlaybookRule]:
        """Parse all playbooks in the directory."""
        rules = []
        
        if not self.playbook_dir.exists():
            self.logger.error(f"Playbook directory not found: {self.playbook_dir}")
            return rules
        
        for playbook_file in self.playbook_dir.glob("*.py"):
            if playbook_file.stem.startswith("__"):
                continue
                
            rule = self.parse_playbook_file(playbook_file)
            if rule:
                rules.append(rule)
        
        self.logger.info(f"Parsed {len(rules)} playbooks successfully")
        return rules
    
    def export_rules_to_json(self, output_dir: Path) -> List[Path]:
        """Export all parsed rules to JSON files."""
        rules = self.parse_all_playbooks()
        exported_files = []
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for rule in rules:
            output_file = output_dir / f"{rule.playbook_name}.json"
            
            # Convert to dict (handle dataclasses)
            rule_dict = self._rule_to_dict(rule)
            
            output_file.write_text(json.dumps(rule_dict, indent=2), encoding='utf-8')
            exported_files.append(output_file)
            self.logger.info(f"Exported rule to {output_file}")
        
        return exported_files
    
    def _rule_to_dict(self, rule: PlaybookRule) -> Dict[str, Any]:
        """Convert PlaybookRule to dict recursively."""
        return {
            "playbook_name": rule.playbook_name,
            "playbook_file": rule.playbook_file,
            "description": rule.description,
            "entry_point": rule.entry_point,
            "blocks": {
                name: {
                    "name": block.name,
                    "block_type": block.block_type,
                    "description": block.description,
                    "conditions": [
                        {
                            "field": c.field,
                            "operator": c.operator,
                            "value": c.value,
                            "condition_type": c.condition_type
                        }
                        for c in block.conditions
                    ],
                    "actions": [
                        {
                            "name": a.name,
                            "action_type": a.action_type.value,
                            "parameters": a.parameters,
                            "callback": a.callback,
                            "assets": a.assets
                        }
                        for a in block.actions
                    ],
                    "next_blocks": block.next_blocks,
                    "custom_code": block.custom_code
                }
                for name, block in rule.blocks.items()
            },
            "severity_changes": rule.severity_changes
        }


def main():
    """Main function for standalone execution."""
    import sys
    
    # Get playbook directory from args or use default
    if len(sys.argv) > 1:
        playbook_dir = Path(sys.argv[1])
    else:
        # Default: source_playbooks directory within the same module
        playbook_dir = Path(__file__).parent / "source_playbooks"
    
    # Output directory
    output_dir = Path(__file__).parent / "rules"
    
    # Create adapter and export rules
    adapter = PlaybookAdapter(playbook_dir)
    exported_files = adapter.export_rules_to_json(output_dir)
    
    print(f"\n✅ Successfully exported {len(exported_files)} playbook rules to {output_dir}")
    for f in exported_files:
        print(f"   - {f.name}")


if __name__ == "__main__":
    main()
