import os
import platform
import importlib.metadata
import requests
from packaging.version import parse as parse_version

API_URL = "https://api.aisbom.io/v1/version"

def check_latest_version() -> str | None:
    """
    Checks for the latest version of aisbom-cli.
    Returns the latest version string if an update is available, otherwise None.
    Respects AISBOM_NO_TELEMETRY env var.
    """
    # 1. Privacy Check
    if os.getenv("AISBOM_NO_TELEMETRY"):
        return None

    try:
        # 2. Get Current Version & Context
        current_version = importlib.metadata.version("aisbom-cli")
        system = platform.system()
        py_ver = platform.python_version()
        is_ci = "true" if (os.getenv("GITHUB_ACTIONS") or os.getenv("CI")) else "false"
        
        user_agent = f"aisbom-cli/{current_version} ({system}; python {py_ver}; ci={is_ci})"

        # 3. Request
        response = requests.get(
            API_URL, 
            headers={"User-Agent": user_agent},
            timeout=1.0 # Strict timeout
        )
        response.raise_for_status()
        
        data = response.json()
        latest_version = data.get("latest")

        if not latest_version:
            return None

        # 4. Compare
        if parse_version(latest_version) > parse_version(current_version):
            return latest_version

    except Exception:
        # Fail silently for any network/parsing issue
        return None
        
    return None
