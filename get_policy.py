#!/usr/bin/env python3
"""Read the actual access policy from a Check Point Management Server.

The script uses the CheckPointAPI client from checkpoint_api.py, logs in with
the details from credentials.py (or command line arguments), discovers the
policy packages/access layers and prints the rules of every layer.

Examples:
    python get_policy.py
    python get_policy.py --package "Standard"
    python get_policy.py --layer "Standard Network" --output policy.json
"""

import argparse
import json
import sys
import warnings

from checkpoint_api import CheckPointAPI, CheckPointAPIError
import credentials

PAGE_SIZE = 500


def credential(name, default=None):
    """Read an optional value from credentials.py."""
    return getattr(credentials, name, default)


def fetch_packages(api):
    """Return all policy packages."""
    packages = []
    offset = 0
    while True:
        response = api.api_call(
            "show-packages",
            {"limit": PAGE_SIZE, "offset": offset, "details-level": "standard"},
        )
        chunk = response.get("packages") or response.get("objects") or []
        packages.extend(chunk)

        total = response.get("total")
        last = response.get("to")
        if not chunk:
            break
        if isinstance(total, int) and isinstance(last, int):
            if last >= total:
                break
            offset = last
        else:
            offset += len(chunk)
            if len(chunk) < PAGE_SIZE:
                break
    return packages


def fetch_access_layers(api):
    """Return all access layers known to the management server."""
    layers = []
    offset = 0
    while True:
        response = api.api_call(
            "show-access-layers",
            {"limit": PAGE_SIZE, "offset": offset, "details-level": "standard"},
        )
        chunk = response.get("access-layers") or []
        layers.extend(chunk)

        total = response.get("total")
        last = response.get("to")
        if not chunk:
            break
        if isinstance(total, int) and isinstance(last, int):
            if last >= total:
                break
            offset = last
        else:
            offset += len(chunk)
            if len(chunk) < PAGE_SIZE:
                break
    return layers


def fetch_rulebase(api, layer, details_level="standard", show_hits=False):
    """Return the complete (paginated) rulebase of one access layer."""
    entries = []
    offset = 0
    while True:
        payload = {
            "name": layer["name"],
            "details-level": details_level,
            "use-object-dictionary": False,
            "show-hits": show_hits,
            "limit": PAGE_SIZE,
            "offset": offset,
        }
        if not layer.get("name") and layer.get("uid"):
            payload.pop("name", None)
            payload["uid"] = layer["uid"]

        response = api.api_call("show-access-rulebase", payload)
        chunk = response.get("rulebase") or []
        if not chunk:
            break
        entries.extend(chunk)

        total = response.get("total")
        last = response.get("to")
        if isinstance(total, int) and isinstance(last, int):
            if last >= total:
                break
            offset = last
        else:
            offset += len(chunk)
            if len(chunk) < PAGE_SIZE:
                break
    return entries


def flatten_rulebase(entries, section_path=()):
    """Yield rules in order, including rules nested inside sections."""
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "access-section" or "rulebase" in entry:
            section_name = entry.get("name") or "(unnamed section)"
            yield from flatten_rulebase(
                entry.get("rulebase") or [], section_path + (section_name,)
            )
        else:
            rule = dict(entry)
            rule["section"] = " / ".join(section_path)
            yield rule


def display(value):
    """Turn an API field (string/list/object) into readable text."""
    if isinstance(value, dict):
        if value.get("name"):
            return value["name"]
        track_type = value.get("type")
        if isinstance(track_type, dict) and track_type.get("name"):
            return track_type["name"]
        if isinstance(track_type, str):
            return track_type
        return value.get("uid") or str(value)
    if isinstance(value, list):
        return ", ".join(display(item) for item in value) if value else "Any"
    if value is None or value == "":
        return "Any"
    return str(value)


def package_layers(package):
    """Extract the access layers of a policy package."""
    layers = []
    for layer in package.get("access-layers") or []:
        if isinstance(layer, dict):
            if layer.get("name") or layer.get("uid"):
                layers.append(
                    {"name": layer.get("name"), "uid": layer.get("uid")}
                )
        elif layer:
            layers.append({"name": str(layer), "uid": None})
    return layers


def unique_layers(layers):
    """Remove duplicate layers (same name or uid), preserving order."""
    result = []
    seen = set()
    for layer in layers:
        key = layer.get("name") or layer.get("uid")
        if key and key not in seen:
            seen.add(key)
            result.append(layer)
    return result


def print_rule(number, rule):
    """Print one rule in a compact, readable format."""
    section = rule.get("section")
    name = rule.get("name") or "(unnamed rule)"
    print(f"{number:4d}. {name}")
    if section:
        print(f"      section:     {section}")
    print(f"      enabled:     {rule.get('enabled', True)}")
    print(f"      action:      {display(rule.get('action'))}")
    print(f"      source:      {display(rule.get('source'))}")
    print(f"      destination: {display(rule.get('destination'))}")
    print(f"      service:     {display(rule.get('service'))}")
    print(f"      track:       {display(rule.get('track'))}")
    if rule.get("comments"):
        print(f"      comments:    {rule['comments']}")


def main():
    parser = argparse.ArgumentParser(
        description="Read the actual access policy from a Check Point management server."
    )
    parser.add_argument("--server", help="Management server (default: credentials.ipaddr)")
    parser.add_argument("--username", help="User name (default: credentials.username)")
    parser.add_argument("--password", help="Password (default: credentials.password)")
    parser.add_argument("--api-key", help="API key instead of user/password")
    parser.add_argument("--domain", help="Management domain (default: credentials.domain)")
    parser.add_argument("--port", type=int, default=443, help="API port (default: 443)")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify the server TLS certificate",
    )
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="NAME",
        help="Only read this policy package (can be repeated)",
    )
    parser.add_argument(
        "--layer",
        action="append",
        default=[],
        metavar="NAME",
        help="Only read this access layer (can be repeated)",
    )
    parser.add_argument(
        "--details-level",
        choices=("standard", "full"),
        default="standard",
        help="Detail level for the rulebase (default: standard)",
    )
    parser.add_argument(
        "--show-hits",
        action="store_true",
        help="Request hit counters for the rules",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Save the complete policy as JSON to FILE",
    )
    args = parser.parse_args()

    if not args.verify:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    server = args.server or credential("ipaddr") or credential("ip")
    if not server:
        parser.error("no management server given and credentials.ipaddr is missing")

    username = args.username if args.username is not None else credential("username")
    password = args.password if args.password is not None else credential("password")
    api_key = args.api_key if args.api_key is not None else credential("api_key")
    domain = args.domain if args.domain is not None else credential("domain")

    # CheckPointAPI accepts either user/password or an API key, never both.
    if args.username is not None or args.password is not None:
        api_key = None
    elif api_key:
        username = password = None

    if not api_key and (not username or not password):
        parser.error("username and password (or an API key) are required")

    try:
        with CheckPointAPI(
            server=server,
            username=username,
            password=password,
            api_key=api_key,
            domain=domain,
            port=args.port,
            verify=args.verify,
        ) as api:
            packages = fetch_packages(api)

            if args.package:
                packages = [
                    package
                    for package in packages
                    if package.get("name") in args.package
                ]
                missing = set(args.package) - {
                    package.get("name") for package in packages
                }
                for name in sorted(missing):
                    print(f"Warning: package '{name}' not found.", file=sys.stderr)

            if args.layer:
                layers = [{"name": name, "uid": None} for name in args.layer]
            else:
                layers = []
                for package in packages:
                    layers.extend(package_layers(package))
                if not layers:
                    # No package information available: read every access layer.
                    layers = fetch_access_layers(api)

            layers = unique_layers(layers)
            if not layers:
                print("No access layers found.", file=sys.stderr)
                return 1

            print(f"Management server: {server}")
            if packages and not args.layer:
                print("Policy packages:   " + ", ".join(
                    package.get("name", "?") for package in packages
                ))

            policy = {"server": server, "layers": []}
            errors = 0

            for layer in layers:
                layer_name = layer.get("name") or layer.get("uid")
                print()
                print("=" * 70)
                print(f"Access layer: {layer_name}")
                print("=" * 70)

                try:
                    entries = fetch_rulebase(
                        api,
                        layer,
                        details_level=args.details_level,
                        show_hits=args.show_hits,
                    )
                except CheckPointAPIError as exc:
                    print(f"Error reading layer '{layer_name}': {exc}", file=sys.stderr)
                    errors += 1
                    continue

                rules = list(flatten_rulebase(entries))
                print(f"Rules: {len(rules)}")
                print()
                for number, rule in enumerate(rules, start=1):
                    print_rule(number, rule)

                policy["layers"].append(
                    {
                        "name": layer.get("name"),
                        "uid": layer.get("uid"),
                        "total-rules": len(rules),
                        "rules": rules,
                        "rulebase": entries,
                    }
                )

            if args.output:
                with open(args.output, "w", encoding="utf-8") as handle:
                    json.dump(policy, handle, ensure_ascii=False, indent=2)
                print(f"\nPolicy saved to {args.output}")

            return 1 if errors else 0

    except CheckPointAPIError as exc:
        print(f"Check Point API error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
