import os

def fix_imports(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                    
                    if "from backend.app" in content:
                        print(f"Fixing {filepath}")
                        new_content = content.replace("from backend.app", "from app")
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(new_content)
                    
                    if "import backend.app" in content:
                        print(f"Fixing import backend.app in {filepath}")
                        new_content = content.replace("import backend.app", "import app")
                        with open(filepath, "w", encoding="utf-8") as f:
                            f.write(new_content)
                            
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")

if __name__ == "__main__":
    fix_imports("app")
