#!/usr/bin/env python3
"""
Quick Start Examples for Network Vector

This script demonstrates basic usage of Network Vector for network scanning and visualization.
"""

import subprocess
import sys
import os

def run_example(title, command, description):
    """Run an example command with formatting."""
    print(f"\n{'='*60}")
    print(f"🔍 {title}")
    print(f"{'='*60}")
    print(f"Description: {description}")
    print(f"Command: {command}")
    print(f"{'='*60}")
    
    try:
        # Ask user if they want to run this example
        response = input(f"\nRun this example? (y/N): ").lower().strip()
        if response in ['y', 'yes']:
            print(f"\n🚀 Running: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ Command completed successfully!")
                if result.stdout:
                    print(f"Output:\n{result.stdout}")
            else:
                print("❌ Command failed!")
                if result.stderr:
                    print(f"Error:\n{result.stderr}")
        else:
            print("⏭️  Skipped")
    except KeyboardInterrupt:
        print("\n\n⚠️  Example interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Error running example: {e}")
    
    return True

def main():
    """Run Network Vector examples."""
    print("🌐 Network Vector - Quick Start Examples")
    print("=" * 50)
    print("This script will guide you through basic Network Vector usage.")
    print("Make sure you have permission to scan the targets you specify!")
    print("\n⚠️  Warning: Only scan networks you own or have permission to test.")
    
    # Check if nvector.py exists
    nvector_path = os.path.join("src", "nvector.py")
    if not os.path.exists(nvector_path):
        print(f"\n❌ Error: {nvector_path} not found!")
        print("Make sure you're running this from the Network Vector root directory.")
        return
    
    examples = [
        {
            "title": "Basic Localhost Scan",
            "command": f"python {nvector_path} 127.0.0.1 --threads 10 --no-resolve-hostnames --no-enumerate-shares",
            "description": "Scan localhost with reduced threads and features for a quick test"
        },
        {
            "title": "Single Host Scan with Full Features",
            "command": f"python {nvector_path} 127.0.0.1 --resolve-hostnames --enumerate-shares",
            "description": "Complete scan of localhost including hostname resolution and SMB shares"
        },
        {
            "title": "Custom Port Scan",
            "command": f"python {nvector_path} 127.0.0.1 --ports 22 80 443 3389 5432",
            "description": "Scan only specific ports of interest"
        },
        {
            "title": "Network Range Scan (Small)",
            "command": f"python {nvector_path} 192.168.1.1/30 --threads 50",
            "description": "Scan a small network range (4 IPs) with moderate threading"
        }
    ]
    
    # Run examples
    for example in examples:
        if not run_example(**example):
            break
    
    print("\n" + "="*60)
    print("🎉 Quick Start Examples Complete!")
    print("="*60)
    print("\n📚 Next Steps:")
    print("1. Check the generated 'network_scan.html' file for visualization")
    print("2. Review 'scan_results.json' for detailed results")
    print("3. Try scanning your own network with appropriate permissions")
    print("4. Read the README.md for advanced usage options")
    print("\n💡 Tip: Use --help to see all available options:")
    print(f"   python {nvector_path} --help")

if __name__ == "__main__":
    main()