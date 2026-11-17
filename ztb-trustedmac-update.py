#!/usr/bin/env python3
"""
Zero Trust Branch (ZTB) Trusted MAC Address Manager
Interacts with ZTB via /api/v3/nac-lite/ endpoints:
  - GET      /api/v3/nac-lite/get       -> Retrieve trusted MACs (--list)
  - POST     /api/v3/nac-lite/validate  -> Validate MAC formatting/schema (--validate)
  - POST     /api/v3/nac-lite/upload    -> Upload MACs as JSON array (--mac or --csv)
  - DELETE   /api/v3/nac-lite/delete    -> Delete MAC addresses (--delete)

Upload Payload Format:
  [
    {
      "description": "string",
      "mac_address": "00:11:22:33:44:55"
    }
  ]

Delete Payload Format:
  {
    "macs": [
      "00:11:22:33:44:55,22:11:22:33:44:55"
    ]
  }
"""

import os
import sys
import re
import csv
import argparse
import logging
from typing import List, Dict, Tuple, Optional, Union
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZTBMacManager")


def load_env_file(filepath: str = ".env") -> None:
    """Loads key-value pairs from a local .env file into os.environ."""
    if not os.path.isfile(filepath):
        return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip("'\"")
            if k not in os.environ:
                os.environ[k] = v


def normalize_mac(mac_raw: str) -> Optional[str]:
    """
    Validates and normalizes MAC address strings into standard colon-separated uppercase format.
    Accepts formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, AABBCCDDEEFF.
    """
    if not mac_raw:
        return None
    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac_raw.strip())
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2].upper() for i in range(0, 12, 2))


def parse_macs_from_csv(csv_path: str) -> Tuple[List[Dict[str, str]], int]:
    """
    Parses MAC addresses and descriptions from a 2-field CSV file.
    Returns a tuple of (entries_list, invalid_count).
    """
    if not os.path.isfile(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    entries = []
    invalid_count = 0

    with open(csv_path, "r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            first_row = next(reader)
        except StopIteration:
            return [], 0

        header_candidates = ["mac", "mac_address", "mac address", "hardware_address", "address"]
        mac_col_idx = 0
        desc_col_idx = None
        has_header = False

        # Identify column indices if header exists
        for idx, col in enumerate(first_row):
            col_clean = col.strip().lower()
            if col_clean in header_candidates:
                mac_col_idx = idx
                has_header = True
            elif col_clean in ["description", "desc"]:
                desc_col_idx = idx

        # Process first row if it was raw data rather than headers
        if not has_header:
            norm = normalize_mac(first_row[mac_col_idx])
            desc = first_row[1].strip() if len(first_row) > 1 else "Imported via CSV"
            if norm:
                entries.append({"mac_address": norm, "description": desc or "Imported via CSV"})
            else:
                invalid_count += 1

        # Process remaining rows
        for row_num, row in enumerate(reader, start=2 if has_header else 1):
            if not row or len(row) <= mac_col_idx:
                continue
            norm = normalize_mac(row[mac_col_idx])
            if norm:
                desc = ""
                if desc_col_idx is not None and len(row) > desc_col_idx:
                    desc = row[desc_col_idx].strip()
                elif len(row) > 1 and mac_col_idx == 0:
                    desc = row[1].strip()
                entries.append({
                    "mac_address": norm,
                    "description": desc or "Imported via CSV"
                })
            else:
                invalid_count += 1
                logger.warning(f"Line {row_num}: Skipped invalid MAC format: '{row[mac_col_idx]}'")

    return entries, invalid_count


class ZTBClient:
    """Client wrapper for ZTB NAC-Lite REST API endpoints."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def authenticate(self) -> str:
        """Exchanges API key for a Bearer delegate token."""
        url = f"{self.base_url}/api/v3/api-key-auth/login"
        resp = self.session.post(url, json={"api_key": self.api_key}, timeout=15)
        resp.raise_for_status()
        token = resp.json().get("result", {}).get("delegate_token")
        if not token:
            raise ValueError("Authentication failed: No delegate_token returned.")
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        logger.info("Successfully authenticated against ZTB tenant API.")
        return token

    def get_trusted_macs(self) -> List[Dict]:
        """Queries existing trusted MAC addresses via GET /api/v3/nac-lite/get."""
        url = f"{self.base_url}/api/v3/nac-lite/get"
        resp = self.session.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        raw_list = data.get("result") or data.get("rows") or (data if isinstance(data, list) else [])
        if isinstance(raw_list, dict) and "trusted_macs" in raw_list:
            return raw_list["trusted_macs"]
        return raw_list

    def validate_macs(self, entries: List[Dict[str, str]]) -> Dict:
        """Validates 2-field MAC entries via POST /api/v3/nac-lite/validate."""
        url = f"{self.base_url}/api/v3/nac-lite/validate"
        payload = entries
        resp = self.session.post(url, json=payload, timeout=20)
        resp.raise_for_status()
        return resp.json()

    def upload_macs(self, entries: List[Dict[str, str]], batch_size: int = 500) -> List[Dict]:
        """
        Uploads MAC addresses to ZTB via POST /api/v3/nac-lite/upload.
        Sends payload as a JSON array of objects:
        [
            {"description": "...", "mac_address": "00:11:22:33:44:55"}
        ]
        Batches requests if the list exceeds batch_size.
        """
        url = f"{self.base_url}/api/v3/nac-lite/upload"
        results = []

        for i in range(0, len(entries), batch_size):
            batch = entries[i:i + batch_size]
            logger.info(f"Uploading batch {i // batch_size + 1} ({len(batch)} MAC entries)...")
            resp = self.session.post(url, json=batch, timeout=30)
            resp.raise_for_status()
            results.append(resp.json())

        return results

    def delete_trusted_mac(self, mac_identifiers: Union[str, List[str]]) -> Dict:
        """
        Deletes trusted MAC address(es) via DELETE /api/v3/nac-lite/delete.
        Payload format:
          {
            "macs": [
              "00:11:22:33:44:55,22:11:22:33:44:55"
            ]
          }
        """
        url = f"{self.base_url}/api/v3/nac-lite/delete"
        if isinstance(mac_identifiers, list):
            macs_str = ",".join(mac_identifiers)
        else:
            macs_str = str(mac_identifiers).strip()

        payload = {"macs": [macs_str]}
        resp = self.session.delete(url, json=payload, timeout=20)
        resp.raise_for_status()
        return resp.json()


def display_trusted_macs(mac_items: List[Dict]) -> None:
    """Formats and prints the list of trusted MAC addresses to stdout."""
    if not mac_items:
        print("\nNo trusted MAC addresses currently configured on tenant.")
        return

    print("\n" + "=" * 65)
    print(f"{'MAC ADDRESS':<22} {'DESCRIPTION':<40}")
    print("=" * 65)

    for item in mac_items:
        mac = item.get("mac_address") or item.get("mac") or "-"
        desc = item.get("description") or "-"
        print(f"{mac:<22} {str(desc)[:38]:<40}")

    print("=" * 65)
    print(f"Total trusted MAC addresses: {len(mac_items)}\n")


def main():
    load_env_file()

    parser = argparse.ArgumentParser(description="ZTB Trusted MAC Automation (/api/v3/nac-lite/)")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--list", action="store_true", help="List current trusted MAC addresses via /get")
    input_group.add_argument("--mac", help="Single MAC address to upload (e.g. 00:11:22:33:44:55)")
    input_group.add_argument("--csv", help="Path to 2-field CSV file (mac_address,description) to upload via /upload")
    input_group.add_argument("--delete", help="MAC address(es) to delete via /delete (e.g. '00:11:22:33:44:55' or '00:11:22:33:44:55,22:11:22:33:44:55')")

    parser.add_argument("--description", default="Added via ZTB CLI", help="Description for single MAC addition")
    parser.add_argument("--validate", action="store_true", help="Call /validate endpoint before uploading")
    parser.add_argument("--batch-size", type=int, default=500, help="Batch size for bulk JSON uploads (default: 500)")
    parser.add_argument("--url", default=os.getenv("ZTB_BASE_URL"), help="ZTB API Base URL")
    parser.add_argument("--api-key", default=os.getenv("ZTB_API_KEY"), help="ZTB API Key")
    parser.add_argument("--dry-run", action="store_true", help="Validate input locally without executing API calls")
    args = parser.parse_args()

    if not args.url or not args.api_key:
        logger.error("Missing tenant URL or API Key. Set ZTB_BASE_URL & ZTB_API_KEY in .env or pass --url and --api-key.")
        sys.exit(1)

    client = ZTBClient(args.url, args.api_key)

    # 1. Action: List current trusted MACs via /api/v3/nac-lite/get
    if args.list:
        client.authenticate()
        logger.info("Retrieving current trusted MACs from /api/v3/nac-lite/get...")
        macs = client.get_trusted_macs()
        display_trusted_macs(macs)
        return

    # 2. Action: Delete MAC(s) via /api/v3/nac-lite/delete
    if args.delete:
        client.authenticate()
        raw_items = [m.strip() for m in args.delete.split(",") if m.strip()]
        normalized_items = [normalize_mac(m) or m for m in raw_items]
        logger.info(f"Submitting deletion for MAC(s): {','.join(normalized_items)} via DELETE /api/v3/nac-lite/delete...")
        res = client.delete_trusted_mac(normalized_items)
        logger.info(f"Delete response: {res}")
        return

    # 3. Action: Collect & normalize entries for Upload/Validate
    entries: List[Dict[str, str]] = []
    if args.mac:
        norm = normalize_mac(args.mac)
        if not norm:
            logger.error(f"Invalid MAC format: '{args.mac}'. Expected 12 hexadecimal characters.")
            sys.exit(1)
        entries.append({
            "mac_address": norm,
            "description": args.description
        })
        logger.info(f"Target MAC: {norm} | Description: {args.description}")
    elif args.csv:
        logger.info(f"Reading CSV file: {args.csv}")
        parsed, invalid_cnt = parse_macs_from_csv(args.csv)
        logger.info(f"Parsed {len(parsed)} valid MAC(s) ({invalid_cnt} invalid entries skipped).")
        entries = parsed

    if not entries:
        logger.error("No valid MAC entries to process. Exiting.")
        sys.exit(1)

    if args.dry_run:
        logger.info("[DRY-RUN] Prepared JSON payload preview:")
        for e in entries[:5]:
            print(f"  - mac_address: {e['mac_address']}, description: {e['description']}")
        if len(entries) > 5:
            print(f"  ... and {len(entries) - 5} more entries.")
        logger.info(f"[DRY-RUN] Total {len(entries)} entries ready. Exiting without network calls.")
        return

    client.authenticate()

    # Optional pre-validation pass via /api/v3/nac-lite/validate
    if args.validate:
        logger.info(f"Validating {len(entries)} entry/entries via /api/v3/nac-lite/validate...")
        val_res = client.validate_macs(entries)
        logger.info(f"Validation result: {val_res}")

    # 4. Upload entries as JSON array via /api/v3/nac-lite/upload
    logger.info(f"Uploading {len(entries)} entry/entries via POST /api/v3/nac-lite/upload...")
    upload_responses = client.upload_macs(entries, batch_size=args.batch_size)
    logger.info(f"Successfully processed upload: {upload_responses}")


if __name__ == "__main__":
    main()
