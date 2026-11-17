README: Zscaler Zero Trust Branch (ZTB) Trusted MAC Address Manager (update-trusted-mac.py)

Overview

update-trusted-mac.py is a Python 3 CLI automation script designed to interact directly with the Zscaler Zero Trust Branch (ZTB) NAC-Lite REST API endpoints (/api/v3/nac-lite/). It enables administrators to:

List currently configured trusted MAC addresses on a tenant.
Add single MAC addresses or perform bulk imports from a CSV file.
Validate MAC schemas and entries before committing changes.
Delete individual or comma-separated lists of trusted MAC addresses.
Run in dry-run mode to preview data locally before invoking remote API calls.

1. Prework & Prerequisites

Python Version

Python 3.8+ is recommended.

Required Python Packages

The script relies on standard Python libraries (sys, os, re, csv, argparse, logging, typing) and one third-party package:

requests

Install the dependency using pip:

pip install requests

2. Environment Variables & Configuration

The script reads connection parameters from environment variables or a local .env file in the working directory.

Required Environment Variables

Variable	Description	Example
ZTB_BASE_URL	Base URL of the ZTB tenant API	https://<tenant>-api.goairgap.com
ZTB_API_KEY	API Key used to authenticate against ZTB	abcdef1234567890...

Setting Environment Variables

Option A: Export directly in your shell

export ZTB_BASE_URL="https://<tenant>-api.goairgap.com"
export ZTB_API_KEY="your-ztb-api-key-here"

Option B: Use a .env file

Create a file named .env in the same directory as the script:

ZTB_BASE_URL=https://<tenant>-api.goairgap.com
ZTB_API_KEY=your-ztb-api-key-here

(Note: Command-line arguments --url and --api-key can also be passed directly during execution to override environment variables).

3. API Endpoints Accessed

Method	Endpoint	Description	Payload / Parameters
POST	/api/v3/api-key-auth/login	Authenticates using the API key and retrieves a Bearer delegate_token.	{"api_key": "<KEY>"}
GET	/api/v3/nac-lite/get	Retrieves all currently configured trusted MAC addresses.	None
POST	/api/v3/nac-lite/validate	Validates format and schema of MAC entries prior to upload.	Array of JSON objects: [{"mac_address": "...", "description": "..."}]
POST	/api/v3/nac-lite/upload	Uploads trusted MAC addresses in bulk/batches.	Array of JSON objects: [{"mac_address": "...", "description": "..."}]
DELETE	/api/v3/nac-lite/delete	Deletes specified trusted MAC addresses from the tenant.	Object with comma-separated string list: {"macs": ["MAC1,MAC2"]}

4. Usage & Execution Examples

1. List Current Trusted MAC Addresses

python3 update-trusted-mac.py --list

2. Add a Single MAC Address

Supported input formats include AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF, or AABBCCDDEEFF (the script normalizes input to uppercase colon-separated format):

python3 update-trusted-mac.py --mac 00:11:22:33:44:55 --description "Finance Printer"

3. Bulk Upload via CSV

The CSV file can be provided with or without headers. If headers are used, the script recognizes mac, mac_address, mac address, hardware_address, or address, along with description or desc.

Example CSV (devices.csv):

mac_address,description
00:11:22:33:44:55,Executive Boardroom TV
AABB.CCDD.EEFF,Warehouse Scanner 10
11-22-33-44-55-66,Reception IP Phone

Run bulk upload:

python3 update-trusted-mac.py --csv devices.csv

4. Upload with Server-Side Pre-Validation

Validates entries via /api/v3/nac-lite/validate before committing the upload:

python3 update-trusted-mac.py --csv devices.csv --validate

5. Dry-Run Mode

Parses and normalizes local data and displays a payload preview without making network calls:

python3 update-trusted-mac.py --csv devices.csv --dry-run

6. Delete Trusted MAC Addresses

Delete a single MAC address or a comma-separated list:

python3 update-trusted-mac.py --delete 00:11:22:33:44:55
# Or multiple:
python3 update-trusted-mac.py --delete "00:11:22:33:44:55, AA:BB:CC:DD:EE:FF"

7. Custom Batch Size

For large CSV uploads (e.g., thousands of MAC addresses), override the default batch size (default: 500):

python3 update-trusted-mac.py --csv large_inventory.csv --batch-size 250

Would you like to explore generating a sample CSV template generator script or adding error-handling documentation for specific API status codes?