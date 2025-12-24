import os

def repair_env():
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    
    # Read existing lines
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
         with open(env_path, 'r', encoding='utf-16') as f: # PowerShell might have saved as utf-16
            lines = f.readlines()
    except Exception:
        print("Could not read .env")
        lines = []

    new_lines = []
    seen_mongo = False
    
    # New URI
    new_uri = "MONGODB_URI=mongodb+srv://Propam:Propam%405553@phisnet-db.4qvmhkw.mongodb.net/?retryWrites=true&w=majority&appName=PhisNet-DB\n"
    
    for line in lines:
        if line.strip().startswith('MONGODB_URI='):
            continue # specific skip
        # Also clean up junk lines if any (lines that look like fragments of the URI)
        if 'phisnet-db.4qvmhkw.mongodb.net' in line and not line.strip().startswith('MONGODB_URI='):
             continue
             
        new_lines.append(line)
    
    # Append new URI at the end
    new_lines.append("\n" + new_uri)
    
    # Write back
    with open(env_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print("Repaired .env file.")

if __name__ == "__main__":
    repair_env()
