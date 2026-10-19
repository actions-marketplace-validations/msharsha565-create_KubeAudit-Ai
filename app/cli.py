import argparse
import sys
from pathlib import Path
import yaml

from app.policy_engine import policy_engine


def load_manifests(file_path: str):
    """Load YAML manifests from a file or stdin, unwrapping List kinds."""
    if file_path == "-":
        raw = sys.stdin.read()
    else:
        p = Path(file_path)
        if not p.is_file():
            print(f"Error: File '{file_path}' not found.", file=sys.stderr)
            sys.exit(1)
        raw = p.read_text()

    docs = []
    for doc in yaml.safe_load_all(raw):
        if not doc or not isinstance(doc, dict):
            continue
        if doc.get("kind") == "List" and "items" in doc:
            docs.extend([item for item in doc["items"] if isinstance(item, dict)])
        else:
            docs.append(doc)
    return docs


def audit_file(file_path: str, exit_on_fail: bool = True):
    documents = load_manifests(file_path)
    valid_docs = [d for d in documents if isinstance(d, dict)]
    total_violations = []

    for doc in valid_docs:
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "unnamed")
        namespace = doc.get("metadata", {}).get("namespace", "default")
        issues = policy_engine.evaluate(doc)
        if issues:
            print(f"\n[FAILED] {kind}/{name} (namespace: {namespace}) in {file_path}:")
            for issue in issues:
                rule = issue.get("rule", "PolicyViolation")
                severity = issue.get("severity", "Medium")
                message = issue.get("message", "Violation detected")
                fix = issue.get("remediation")
                print(f"  - [{severity}] {rule}: {message}")
                if fix:
                    print(f"    Fix: {fix}")
            total_violations.extend(issues)
        else:
            print(f"[PASSED] {kind}/{name} (namespace: {namespace})")

    if total_violations and exit_on_fail:
        print(f"\nTotal security policy violations: {len(total_violations)}")
        sys.exit(1)
    elif not total_violations:
        print(f"\nAll manifests in {file_path} conform to security policies.")


def run_advise(args):
    import requests
    path = Path(args.manifest)
    if not path.is_file():
        print(f"Error: File '{args.manifest}' not found.", file=sys.stderr)
        sys.exit(1)

    manifest_yaml = path.read_text()
    resp = requests.post(f"{args.host}/v1/advise", json={"manifest": manifest_yaml})
    if resp.status_code == 200:
        data = resp.json()
        print(f"Advice from {data.get('source', 'engine'):}")
        print(data.get("remediation", ""))
    else:
        print(f"Error ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="kubeaudit",
        description="KubeAudit AI manifest security scanner"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Audit Kubernetes YAML manifests against security policies")
    audit_parser.add_argument("file", help="Path to Kubernetes YAML manifest or '-' for stdin")

    p_advise = subparsers.add_parser("advise", help="AI-assisted remediation advice")
    p_advise.add_argument("manifest", help="Path to Kubernetes YAML manifest file")
    p_advise.add_argument("--host", default="https://kubeaudit-ai-production.up.railway.app", help="KubeAudit API base URL")
    p_advise.set_defaults(func=run_advise)

    args = parser.parse_args()
    if hasattr(args, "func"):
        return args.func(args)
    if args.command == "audit":
        return audit_file(args.file)
    return 0


if __name__ == "__main__":
    main()
