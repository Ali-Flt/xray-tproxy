import json
import os
import sys
import subprocess
from pathlib import Path
import time

# Add python_v2ray to the system path if it's in a parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from python_v2ray.config_parser import load_configs, ConfigParams, XrayConfigBuilder

# --- Configuration Paths ---
TEMP_CONFIG_PATH = "/tmp/xray_config_next.json"
PRODUCTION_CONFIG_PATH = "/etc/xray/config.json"
SUBSCRIPTION_URL = "https://your_sub" 

def check_root():
    """Ensures the script is running with root/sudo privileges."""
    if os.geteuid() != 0:
        print("! ERROR: This script must be run as root or via sudo to manage system services.")
        sys.exit(1)

def run_command(cmd: list, description: str):
    """Helper function to run system shell commands safely."""
    print(f"* Executing: {description}...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"! Failed execution: {description}")
        print(f"! Error logs: {result.stderr.strip()}")
        sys.exit(1)

def main():
    # 0. Check permissions
    check_root()

    project_root = Path(__file__).parent.parent
    vendor_dir = project_root / "vendor"
    core_engine_dir = project_root / "core_engine"

    # 1. Download necessary Xray binaries
    print("* Checking for required Xray binaries...")
    downloader = BinaryDownloader(project_root)
    downloader.ensure_all()

    # 2. Load and parse subscription
    print(f"* Fetching subscription from source...")
    parsed_configs = load_configs(SUBSCRIPTION_URL, is_subscription=True)
    
    if not parsed_configs:
        print("! Failed to load any configurations from the subscription.")
        sys.exit(1)

    vless_configs = [c for c in parsed_configs if getattr(c, 'protocol', '').lower() == 'vless']
    
    if not vless_configs:
        print("! No VLESS configurations found in the subscription.")
        sys.exit(1)

    # 3. Test configurations for latency in structured batches
    tester = ConnectionTester(vendor_path=str(vendor_dir), core_engine_path=str(core_engine_dir))
    BATCH_SIZE = 100
    results = []
    
    print(f"* Testing {len(vless_configs)} nodes in chunks of {BATCH_SIZE}...")
    for i in range(0, len(vless_configs), BATCH_SIZE):
        batch = vless_configs[i:i + BATCH_SIZE]
        print(f"  -> Testing batch {(i // BATCH_SIZE) + 1}...")
        try:
            batch_results = tester.test_uris(parsed_params=batch, timeout=45)
            if batch_results:
                results.extend(batch_results)
        except Exception as batch_error:
            print(f"  ! Batch execution failed or timed out: {batch_error}")

    successful_results = [r for r in results if r.get('status') == 'success' and r.get('ping_ms', -1) > 0]
    
    if not successful_results:
        print("! All VLESS nodes failed connectivity checks. Aborting systemic adjustments.")
        sys.exit(1)

    successful_results.sort(key=lambda x: x.get('ping_ms'))
    best_result = successful_results[0]
    best_tag = best_result.get('tag')
    
    print(f"\n* Best node identified: {best_tag} ({best_result.get('ping_ms')}ms)")

    best_config_params = next((c for c in vless_configs if getattr(c, 'tag', getattr(c, 'name', '')) == best_tag), None)
    if not best_config_params:
        best_config_params = vless_configs[successful_results.index(best_result)]

    # 4. Generate the new JSON outbound definition
    builder = XrayConfigBuilder()
    new_proxy_outbound = builder.build_outbound_from_params(best_config_params, "proxy")
    sock_opt_json = {
        "sockopt": {
          "mark": 2
        }
    }
    new_proxy_outbound["streamSettings"].update(sock_opt_json)

    # 5. Load and patch current production configuration
    try:
        with open(PRODUCTION_CONFIG_PATH, 'r', encoding='utf-8') as f:
            base_config = json.load(f)
    except FileNotFoundError:
        print(f"! Error: Production file not found at {PRODUCTION_CONFIG_PATH}")
        sys.exit(1)

    outbounds = base_config.get("outbounds", [])
    replaced = False
    for i, outbound in enumerate(outbounds):
        if outbound.get("tag") == "proxy":
            outbounds[i] = new_proxy_outbound
            replaced = True
            break
            
    if not replaced:
        outbounds.insert(0, new_proxy_outbound)

    base_config["outbounds"] = outbounds

    # Write temporarily to verify file operations before service interruption
    with open(TEMP_CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(base_config, f, indent=2, ensure_ascii=False)

    print("\n" + "="*40 + " INITIALIZING SERVICES ROTATION " + "="*40)

    # 6. Stop network and proxy interfaces
    run_command(["systemctl", "stop", "xray", "nftables"], "Stopping services (xray, nftables)")
    time.sleep(5)

    # 7. Relocate verified configuration file to production target
    run_command(["cp", TEMP_CONFIG_PATH, PRODUCTION_CONFIG_PATH], "Deploying configuration to destination")
    time.sleep(3)

    # 8. Start network and proxy interfaces
    run_command(["systemctl", "restart", "xray", "nftables"], "Restarting services (xray, nftables)")

    # Clean up temp file
    if os.path.exists(TEMP_CONFIG_PATH):
        os.remove(TEMP_CONFIG_PATH)

    print("="*112)
    print("* Automation task completed flawlessly. Production proxy updated successfully.")

if __name__ == "__main__":
    main()
