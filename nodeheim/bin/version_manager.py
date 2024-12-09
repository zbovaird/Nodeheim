#!/usr/bin/env python3
"""
Version Management Script for Nodeheim Splunk App
Handles version updates across all relevant files and creates proper packages.
"""

import os
import sys
import json
import configparser
import shutil
import subprocess
from datetime import datetime

def update_version(new_version):
    """Update version numbers across all relevant files."""
    app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Update app.manifest
    manifest_path = os.path.join(app_root, 'app.manifest')
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        manifest['info']['id']['version'] = new_version
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=4)
            
    # Update app.conf
    app_conf_path = os.path.join(app_root, 'default', 'app.conf')
    if os.path.exists(app_conf_path):
        config = configparser.ConfigParser()
        config.read(app_conf_path)
        if 'launcher' in config:
            config['launcher']['version'] = new_version
        if 'id' in config:
            config['id']['version'] = new_version
        with open(app_conf_path, 'w') as f:
            config.write(f)
            
    # Clean up old package files
    for item in os.listdir(app_root):
        if item.endswith('.spl') or item.endswith('.tar.gz'):
            try:
                os.remove(os.path.join(app_root, item))
                print(f"Removed old package: {item}")
            except Exception as e:
                print(f"Warning: Could not remove {item}: {e}")

def create_package(version):
    """Create a properly named package file."""
    app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    staging_dir = os.path.join(app_root, 'staging')
    
    # Clean staging directory
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
    
    # Create staging area
    staging_app_dir = os.path.join(staging_dir, 'nodeheim')
    os.makedirs(staging_app_dir)
    
    # Copy files to staging
    for item in os.listdir(app_root):
        if item not in ['staging', '.git', '__pycache__']:
            src = os.path.join(app_root, item)
            dst = os.path.join(staging_app_dir, item)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
    
    # Create package
    package_name = f'nodeheim-{version}.spl'
    shutil.make_archive(
        os.path.join(app_root, f'nodeheim-{version}'),
        'zip',
        staging_dir
    )
    os.rename(
        os.path.join(app_root, f'nodeheim-{version}.zip'),
        os.path.join(app_root, package_name)
    )
    
    # Clean up staging directory
    shutil.rmtree(staging_dir)
    
    return package_name

def main():
    """Main function for version management."""
    if len(sys.argv) != 2:
        print("Usage: version_manager.py NEW_VERSION")
        print("Example: version_manager.py 1.0.4")
        sys.exit(1)
        
    new_version = sys.argv[1]
    
    # Validate version format
    parts = new_version.split('.')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        print("Error: Version must be in MAJOR.MINOR.PATCH format (e.g., 1.0.4)")
        sys.exit(1)
        
    try:
        print(f"Updating to version {new_version}...")
        update_version(new_version)
        print("Version updated in configuration files")
        
        package_name = create_package(new_version)
        print(f"Created package: {package_name}")
        
        print("\nVersion update complete!")
        print(f"Next steps:")
        print(f"1. Test the new package")
        print(f"2. Tag the release: git tag -a v{new_version} -m 'Version {new_version}'")
        print(f"3. Push the tag: git push origin v{new_version}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 