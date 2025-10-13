"""
Standalone script to parse Phantom playbooks.
Run this from the project root directory.
"""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import ast
import json
from pathlib import Path


def parse_playbook_file(playbook_path):
    """Parse a single playbook file."""
    print(f"Parsing: {playbook_path.name}")
    
    try:
        content = playbook_path.read_text(encoding='utf-8')
        tree = ast.parse(content)
        
        # Extract module docstring
        description = ast.get_docstring(tree) or "No description"
        
        # Count functions
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        
        # Find phantom.act calls
        actions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                try:
                    if hasattr(node.func, 'attr') and node.func.attr == 'act':
                        if node.args:
                            action_name = ast.unparse(node.args[0]).strip('"\'')
                            actions.append(action_name)
                except:
                    pass
        
        result = {
            "file": playbook_path.name,
            "description": description[:200],
            "functions": len(functions),
            "function_names": functions[:10],  # First 10
            "actions": list(set(actions)),
            "lines": len(content.splitlines())
        }
        
        print(f"  ✓ Functions: {len(functions)}")
        print(f"  ✓ Actions: {', '.join(actions) if actions else 'None detected'}")
        print()
        
        return result
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        print()
        return None


def main():
    print("=" * 80)
    print("Phantom Playbook Analyzer")
    print("=" * 80)
    print()
    
    # Find Phishing Playbook directory (now in backend)
    script_dir = Path(__file__).parent
    backend_dir = script_dir.parent
    playbook_dir = backend_dir / "app" / "integrations" / "playbooks" / "source_playbooks"
    
    if not playbook_dir.exists():
        print(f"❌ Playbook directory not found: {playbook_dir}")
        print("   Script location:", script_dir)
        print("   Expected path: backend/app/integrations/playbooks/source_playbooks/")
        return
    
    print(f"📂 Playbook directory: {playbook_dir}")
    print()
    
    # Parse all Python playbooks
    playbooks = list(playbook_dir.glob("*.py"))
    print(f"Found {len(playbooks)} Python playbook files")
    print()
    
    results = []
    for playbook_file in playbooks:
        if not playbook_file.stem.startswith("__"):
            result = parse_playbook_file(playbook_file)
            if result:
                results.append(result)
    
    # Summary
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Total playbooks parsed: {len(results)}")
    print(f"Total functions: {sum(r['functions'] for r in results)}")
    
    all_actions = set()
    for r in results:
        all_actions.update(r['actions'])
    print(f"Unique actions: {', '.join(sorted(all_actions))}")
    
    print()
    print("✅ Analysis complete!")
    print()
    print("Next steps:")
    print("1. Review the playbook structure above")
    print("2. Install required dependencies: pip install -r backend/requirements.txt")
    print("3. Configure Redis for caching")
    print("4. Run the integrated orchestrator with playbook support")


if __name__ == "__main__":
    main()
