#!/usr/bin/env python3
"""Allow a self-hosted domain in the Proton Pass browser extension manifests.

The extension's manifests only let *.proton.me (and Proton's internal
domains) talk to the extension (`externally_connectable`) and run the
account-page content scripts there. This adds `*.<your domain>` next to
every proton.me pattern. Usage:

    patch-extension-manifests.py <WebClients checkout> <domain>
"""
import json
import pathlib
import sys


def patch_patterns(patterns, domain):
    out = list(patterns)
    for p in patterns:
        if "proton.me" in p:
            candidate = p.replace("proton.me", domain)
            if candidate not in out:
                out.append(candidate)
    return out


def walk(node, domain):
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("matches", "exclude_matches") and isinstance(value, list):
                node[key] = patch_patterns(value, domain)
            else:
                walk(value, domain)
    elif isinstance(node, list):
        for v in node:
            walk(v, domain)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    root = pathlib.Path(sys.argv[1]) / "applications" / "pass-extension"
    domain = sys.argv[2].strip().lstrip("*.")
    manifests = sorted(root.glob("manifest*.json"))
    if not manifests:
        sys.exit(f"no manifest*.json found under {root}")
    for path in manifests:
        data = json.loads(path.read_text())
        walk(data, domain)
        path.write_text(json.dumps(data, indent=4) + "\n")
        print(f"patched {path}")


if __name__ == "__main__":
    main()
