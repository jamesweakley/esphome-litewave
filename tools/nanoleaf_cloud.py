#!/usr/bin/env python3
"""
Nanoleaf Cloud API client for retrieving device auth tokens and metadata.

We use v2 homesync (IOS app) instead of v4 (MacOS app) because v4 does not seem
to provide all of the devices.

Endpoints:
  - POST https://my.nanoleaf.me/api/v1/users/local/login
  - GET  https://my.nanoleaf.me/api/v2/homesync
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

LOGIN_URL = "https://my.nanoleaf.me/api/v1/users/local/login"
HOMESYNC_URL = "https://my.nanoleaf.me/api/v2/homesync"


class NanoleafCloudClient:
    def __init__(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        access_token: Optional[str] = None,
    ):
        self.username = username or os.environ.get("NANOLEAF_EMAIL") or os.environ.get("NANOLEAF_USERNAME")
        self.password = password or os.environ.get("NANOLEAF_PASSWORD")
        self.access_token = access_token or os.environ.get("NANOLEAF_CLOUD_TOKEN")

    def login(self) -> str:
        """Authenticate with username and password, returns bearer access token."""
        if not self.username or not self.password:
            raise ValueError(
                "Nanoleaf cloud credentials required. Set --cloud-email and --cloud-password, "
                "or NANOLEAF_EMAIL and NANOLEAF_PASSWORD environment variables."
            )

        payload = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            LOGIN_URL,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer",
                "User-Agent": "esphome-litewave/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                self.access_token = res_data.get("access_token")
                if not self.access_token:
                    raise ValueError(f"Login failed: no access_token in response ({res_data})")
                return self.access_token
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Nanoleaf cloud login failed (HTTP {e.code}): {err_body}") from e
        except Exception as e:
            raise RuntimeError(f"Nanoleaf cloud connection error: {e}") from e

    def get_homesync(self) -> Dict[str, Any]:
        """Fetch full homesync payload from Nanoleaf cloud."""
        if not self.access_token:
            self.login()

        req = urllib.request.Request(
            HOMESYNC_URL,
            headers={
                "Authorization": f"Bearer {self.access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "esphome-litewave/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 401 and self.username and self.password:
                # Token might have expired, retry with fresh login
                self.login()
                return self.get_homesync()
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Failed to fetch homesync (HTTP {e.code}): {err_body}") from e

    def get_home_config(self) -> Dict[str, Any]:
        """Fetch primary home config: panID, adminKey, preferredChannel."""
        sync_data = self.get_homesync()
        homes = sync_data.get("homes", [])
        for h in homes:
            if not h.get("deleted", False):
                return {
                    "pan_id": h.get("panID") or "",
                    "admin_key": h.get("adminKey") or "",
                    "channel": int(h.get("preferredChannel")) if h.get("preferredChannel") is not None else None,
                    "home_shared_secret": h.get("sharedSecret") or "",
                    "home_name": h.get("name") or "Home",
                }
        return {
            "pan_id": "",
            "admin_key": "",
            "channel": None,
            "home_shared_secret": "",
            "home_name": "",
        }

    def get_devices(self) -> List[Dict[str, Any]]:
        """
        Fetch devices from Nanoleaf cloud.
        Returns normalized list of devices with:
          - name: device display name
          - model: e.g. "NL65" or "NL44"
          - auth_token: hex token string
          - eui64: lowercased 16-hex character EUI
          - pairing_id: pairing ID string
          - raw: raw device dict
        """
        sync_data = self.get_homesync()
        raw_devices = sync_data.get("devices", [])
        normalized = []

        for d in raw_devices:
            eui_val = d.get("EUI") or d.get("eui") or d.get("eui64") or ""
            eui_raw = str(eui_val).replace(":", "").replace("-", "").lower()

            auth_tok = d.get("auth_token") or d.get("authToken") or ""
            auth_tok = str(auth_tok).strip()

            normalized.append({
                "name": d.get("name") or "Unknown",
                "model": d.get("model") or "?",
                "auth_token": auth_tok,
                "eui64": eui_raw,
                "pairing_id": str(d.get("pairing_id") or ""),
                "cloud_id": str(d.get("cloudID") or ""),
                "deleted": bool(d.get("deleted", False)),
                "raw": d,
            })

        return normalized


if __name__ == "__main__":
    import getpass

    email = sys.argv[1] if len(sys.argv) > 1 else input("Nanoleaf Email: ")
    pw = sys.argv[2] if len(sys.argv) > 2 else getpass.getpass("Password: ")

    client = NanoleafCloudClient(email, pw)
    print("\nLogging in to Nanoleaf Cloud...")
    client.login()
    print("Fetching devices...")
    devices = client.get_devices()

    print(f"\nFound {len(devices)} device(s) in Nanoleaf Cloud:")
    print(f"{'Name':<30} {'Model':<8} {'EUI64':<18} {'Auth Token'}")
    print("─" * 75)
    for d in devices:
        tok_preview = f"{d['auth_token'][:12]}..." if d['auth_token'] else "(none)"
        print(f"{d['name']:<30} {d['model']:<8} {d['eui64']:<18} {tok_preview}")
