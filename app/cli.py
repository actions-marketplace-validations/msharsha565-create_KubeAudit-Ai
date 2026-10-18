from app.advisor_cli import run_advise
import argparse
import sys
import yaml
from pathlib import Path
from app.main import analyze_manifest, remediate_document
from app.policy_engine import policy_engine

def audit_file(file_path: str, exit_on_fail: bool = True):
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(path, "r") as f:
        try:
            documents = list(yaml.safe_load_all(f.read()))
        except Exception as e:
            print(f"Error: Failed to parse YAML in '{file_path}': {e}", file=sys.stderr)
            sys.exit(1)

    valid_docs = [d for d in documents if isinstance(d, dict)]
    total_violations = []

    for doc in valid_docs:
        kind = doc.get("kind", "Unknown")
        name = doc.get("metadata", {}).get("name", "unnamed")
        
        # Static baseline analysis
        issues = analyze_manifest(doc)
        
        # Rego policy evaluation
        rego_issues = policy_engine.evaluate(doc)
        for r in rego_issues:
            if not any(i.rule == r["rule"] for i in issues):
                from app.main import Issue
                issues.append(Issue(severity=r["severity"], rule=r["rule"], message=r["message"]))

        if issues:
            print(f"\n[FAILED] {kind}/{name} in {file_path}:")
            for issue in issues:
                print(f"  - [{issue.severity}] {issue.rule}: {issue.message}")
                if issue.remediation:
                    print(f"    Fix: {issue.remediation}")
            total_violations.extend(issues)
        else:
            print(f"[PASSED] {kind}/{name} in {file_path}")

    if total_violations and exit_on_fail:
        print(f"\nTotal security policy violations: {len(total_violations)}")
        sys.exit(1)
    elif not total_violations:
        print(f"\nAll manifests in {file_path} conform to security policies.")

def fix_file(file_path: str):
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(path, "r") as f:
        documents = list(yaml.safe_load_all(f.read()))

    valid_docs = [d for d in documents if isinstance(d, dict)]
    all_fixes = []

    for doc in valid_docs:
        remediate_document(doc, all_fixes)

    with open(path, "w") as f:
        yaml.dump_all(valid_docs, f, sort_keys=False)

    print(f"Successfully remediated {file_path}:")
    for fix in all_fixes:
        print(f"  - {fix}")

def main():
    parser = argparse.ArgumentParser(prog="kubeaudit", description="KubeAudit AI manifest security scanner and auto-fixer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Audit Kubernetes YAML manifests against security policies")
    audit_parser.add_argument("file", help="Path to Kubernetes YAML manifest")

    fix_parser = subparsers.add_parser("fix", help="Auto-remediate Kubernetes YAML manifests in place")
    fix_parser.add_argument("file", help="Path to Kubernetes YAML manifest")

        # advise subcommand
    p_advise = subparsers.add_parser("advise", help="AI-assisted remediation advice")
    p_advise.add_argument("manifest", help="Path to Kubernetes YAML manifest file")
    p_advise.add_argument("--host", default="https://kubeaudit-ai-production.up.railway.app", help="KubeAudit API base URL")
    p_advise.set_defaults(func=run_advise)

    args = parser.parse_args()
    if args.command == "audit":
        audit_file(args.file)
    elif args.command == "fix":
        fix_file(args.file)

if __name__ == "__main__":
    main()
