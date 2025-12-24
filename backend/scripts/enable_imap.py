import os

def enable_imap():
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    
    try:
        with open(env_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
         # Fallback for PowerShell UTF-16
         with open(env_path, 'r', encoding='utf-16') as f:
            lines = f.readlines()
    except Exception:
        print("Could not read .env")
        return

    new_lines = []
    imap_enabled_found = False
    
    for line in lines:
        if line.strip().startswith('IMAP_ENABLED='):
            new_lines.append("IMAP_ENABLED=True\n")
            imap_enabled_found = True
        else:
            new_lines.append(line)
    
    if not imap_enabled_found:
        if new_lines and not new_lines[-1].endswith('\n'):
            new_lines.append('\n')
        new_lines.append("IMAP_ENABLED=True\n")
    
    with open(env_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print("Enabled IMAP in .env file.")

if __name__ == "__main__":
    enable_imap()
