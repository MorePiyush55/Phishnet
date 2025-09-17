#!/usr/bin/env python3

# Thin wrapper to call the canonical setup script from the infrastructure area
import subprocess
import sys
import os

script_path = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'setup_google_cloud.py')

if __name__ == '__main__':
    print('Running oauth setup via canonical scripts/setup_google_cloud.py')
    subprocess.run([sys.executable, script_path] + sys.argv[1:])
