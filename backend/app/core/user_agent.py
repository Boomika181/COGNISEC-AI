import re
from typing import Dict, Any, Optional


class UserAgentParser:
    """
    Lightweight, robust user-agent and device environment parser.
    Provides best-effort browser, OS, and category detection.
    """

    @classmethod
    def parse(cls, user_agent: Optional[str] = None, platform: Optional[str] = None) -> Dict[str, Any]:
        ua = (user_agent or "").strip()
        plat = (platform or "").strip()

        # 1. Device Type Detection (Desktop, Mobile, Tablet, Unknown)
        device_type = "Desktop"
        ua_lower = ua.lower()
        if any(keyword in ua_lower for keyword in ["ipad", "tablet", "playbook", "silk"]):
            device_type = "Tablet"
        elif any(keyword in ua_lower for keyword in ["mobile", "android", "iphone", "ipod", "blackberry", "windows phone"]):
            device_type = "Mobile"
        elif not ua:
            device_type = "Unknown"

        # 2. Operating System Detection
        os_name = "Unknown"
        os_version = ""

        if "windows nt 10.0" in ua_lower:
            os_name = "Windows"
            os_version = "10/11"
        elif "windows nt 6.3" in ua_lower:
            os_name = "Windows"
            os_version = "8.1"
        elif "windows nt 6.1" in ua_lower:
            os_name = "Windows"
            os_version = "7"
        elif "windows" in ua_lower or "win" in plat.lower():
            os_name = "Windows"
        elif "macintosh" in ua_lower or "mac os x" in ua_lower or "mac" in plat.lower():
            os_name = "macOS"
            match = re.search(r"mac os x ([\d_]+)", ua_lower)
            if match:
                os_version = match.group(1).replace("_", ".")
        elif "android" in ua_lower:
            os_name = "Android"
            match = re.search(r"android ([\d.]+)", ua_lower)
            if match:
                os_version = match.group(1)
        elif any(i in ua_lower for i in ["iphone", "ipad", "ipod"]):
            os_name = "iOS"
            match = re.search(r"os ([\d_]+)", ua_lower)
            if match:
                os_version = match.group(1).replace("_", ".")
        elif "cros" in ua_lower:
            os_name = "Chrome OS"
        elif "linux" in ua_lower or "linux" in plat.lower():
            os_name = "Linux"

        # 3. Browser Name and Version Detection
        browser_name = "Unknown"
        browser_version = ""

        if "edg/" in ua_lower or "edge/" in ua_lower or "edge" in ua_lower:
            browser_name = "Edge"
            match = re.search(r"edg[e]?/([\d.]+)", ua_lower)
            if match:
                browser_version = match.group(1)
        elif "opr/" in ua_lower or "opera" in ua_lower:
            browser_name = "Opera"
            match = re.search(r"(?:opr|opera)/([\d.]+)", ua_lower)
            if match:
                browser_version = match.group(1)
        elif "firefox" in ua_lower:
            browser_name = "Firefox"
            match = re.search(r"firefox[/ ]?([\d.]+)", ua_lower)
            if match:
                browser_version = match.group(1)
        elif "chrome" in ua_lower and "chromium" not in ua_lower:
            browser_name = "Chrome"
            match = re.search(r"chrome[/ ]?([\d.]+)", ua_lower)
            if match:
                browser_version = match.group(1)
        elif "safari" in ua_lower:
            browser_name = "Safari"
            match = re.search(r"(?:version|safari)[/ ]?([\d.]+)", ua_lower)
            if match:
                browser_version = match.group(1)

        # Build readable summary string
        v_str = f" {browser_version.split('.')[0]}" if browser_version else ""
        os_v_str = f" {os_version}" if os_version else ""
        summary = f"{browser_name}{v_str} on {os_name}{os_v_str} ({device_type})"

        return {
            "browser_name": browser_name,
            "browser_version": browser_version,
            "os_name": os_name,
            "os_version": os_version,
            "device_type": device_type,
            "summary": summary
        }
