import argparse
import sys
import httpx

def audit_file(file_path: str, api_url: str):
    with open(file_path, "r") as f:
        manifest_content = f.read()

    response = httpx.post(f"{api_url}/audit", json={"manifest": manifest_content})
    if response.status_code != 200:
        print(f"Error ({response.status_code}): {response.text}")
        sys.exit(1)

    result = response.json()
    if result["valid"]:
        print(f"PASS: {file_path} is compliant with security standards.")
        sys.exit(0)
    else:
        print(f"FAIL: {file_path} has {len(result['issues'])} security issues:")
        for issue in result["issues"]:
            print(f"  [{issue['severity'].upper()}] {issue['rule']}: {issue['message']}")
            if issue.get("remediation"):
                print(f"    --> Fix: {issue['remediation']}")
        sys.exit(1)

def fix_file(file_path: str, output_path: str, api_url: str):
    with open(file_path, "r") as f:
        manifest_content = f.read()

    response = httpx.post(f"{api_url}/fix", json={"manifest": manifest_content})
    if response.status_code != 200:
        print(f"Error ({response.status_code}): {response.text}")
        sys.exit(1)

    result = response.json()
    out = output_path or file_path
    with open(out, "w") as f:
        f.write(result["remediated_manifest"])

    print(f"Successfully remediated {file_path} -> {out}")
    print(f"Applied {len(result['applied_fixes'])} fixes:")
    for fix in result["applied_fixes"]:
        print(f"  - {fix}")

def main():
    parser = argparse.ArgumentParser(description="KubeAudit AI Command-Line Interface")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of KubeAudit AI service")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_cmd = subparsers.add_parser("audit", help="Audit a manifest file for security violations")
    audit_cmd.add_argument("file", help="Path to Kubernetes YAML manifest")

    fix_cmd = subparsers.add_parser("fix", help="Automatically remediate security violations in a manifest")
    fix_cmd.add_argument("file", help="Path to Kubernetes YAML manifest to fix")
    fix_cmd.add_argument("-o", "--output", help="Output path for fixed manifest (defaults to overwriting input)")

    args = parser.parse_args()

    if args.command == "audit":
        audit_file(args.file, args.url)
    elif args.command == "fix":
        fix_file(args.file, args.output, args.url)

if __name__ == "__main__":
    main()