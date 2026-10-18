import json
import urllib.request
from pathlib import Path

def run_advise(args) -> int:
    p = Path(args.manifest)
    if not p.is_file():
        print(f"Error: file not found: {args.manifest}")
        return 1

    payload = json.dumps({"manifest": p.read_text()}).encode("utf-8")
    url = f"{args.host.rstrip('/')}/advise"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
            print(f"=== KubeAudit AI Advisory Report: {args.manifest} ===")
            print(f"AI Engine Active: {data.get('available', False)}")
            print("\nViolations Detected:")
            for v in data.get("violations", []):
                print(f"   22 {v}")
            print("\nRemediation Strategy:")
            print(f"  {data.get('advice', 'No advice returned')}")
            return 0
    except Exception as e:
        print(f"Failed to query advisor endpoint: {str(e)}")
        return 1
