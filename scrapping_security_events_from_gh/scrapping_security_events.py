import requests
import csv
import os
import datetime

REPOS = [
    {"owner": "multiversx", "repo": "mx-chain-go", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-chain-vm-go", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-chain-proxy-go", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-multi-factor-auth-go-service", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-sdk-js-core", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-sdk-py-cli", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-sdk-py", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-api-service", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
    {"owner": "multiversx", "repo": "mx-wallet-dapp", "endpoints": {"dependabot": True, "advisories": True, "code_scanning": True, "policy": True}},
]

GITHUB_API = "https://api.github.com"


def get_github_token():
    token = os.getenv("GITHUB_TOKEN_SECURITY_EVENTS", "")
    print(f"DEBUG: Token from env: {token[:6]}...{'(set)' if token else '(not set)'}")
    return token


def get_dependabot_alerts(token, owner, repo):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/dependabot/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    params = {"per_page": 100, "state": "open"}
    results = []
    while url:
        r = requests.get(url, headers=headers, params=params)
        if r.status_code == 200:
            for alert in r.json():
                package_name = alert.get("dependency", {}).get("package", {}).get("name", "")
                results.append({
                    "type": "dependabot",
                    "link": alert.get("html_url"),
                    "severity": alert.get("security_vulnerability", {}).get("severity", "unknown"),
                    "package": package_name
                })
            if 'next' in r.links:
                url = r.links['next']['url']
                params = None
            else:
                url = None
        else:
            url = None
    return results


def get_security_advisories(token, owner, repo):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/security-advisories"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    results = []
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        for adv in r.json():
            results.append({
                "type": "advisory",
                "link": f"https://github.com/{owner}/{repo}/security/advisories/{adv.get('ghsa_id')}",
                "severity": adv.get("severity", "unknown")
            })
    return results


def get_code_scanning_alerts(token, owner, repo):
    url = f"{GITHUB_API}/repos/{owner}/{repo}/code-scanning/alerts"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    params = {"state": "open"}
    results = []
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        for alert in r.json():
            if alert.get("state") == "open":
                results.append({
                    "type": "code_scanning",
                    "link": alert.get("html_url"),
                    "severity": alert.get("rule", {}).get("security_severity_level", "unknown")
                })
    return results


def get_security_policy(owner, repo):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/main/SECURITY.md"
    r = requests.get(url)
    if r.status_code == 200:
        return [{
            "type": "policy",
            "link": f"https://github.com/{owner}/{repo}/security/policy",
            "severity": "info"
        }]
    return []


def main():
    token = get_github_token()
    all_results = []
    for repo_info in REPOS:
        owner = repo_info["owner"]
        repo = repo_info["repo"]
        print(f"\n--- {owner}/{repo} ---")
        endpoints = repo_info["endpoints"]
        if endpoints.get("dependabot"):
            dep = get_dependabot_alerts(token, owner, repo)
            print(f"  Dependabot alerts: {len(dep)}")
            for d in dep:
                d["repo"] = f"{owner}/{repo}"
                d["package"] = d.get("package", "")
            all_results.extend(dep)
        if endpoints.get("advisories"):
            adv = get_security_advisories(token, owner, repo)
            print(f"  Security advisories: {len(adv)}")
            for a in adv:
                a["repo"] = f"{owner}/{repo}"
                a["package"] = ""
            all_results.extend(adv)
        if endpoints.get("code_scanning"):
            cs = get_code_scanning_alerts(token, owner, repo)
            print(f"  Code scanning alerts: {len(cs)}")
            for c in cs:
                c["repo"] = f"{owner}/{repo}"
                c["package"] = ""
            all_results.extend(cs)
        if endpoints.get("policy"):
            pol = get_security_policy(owner, repo)
            print(f"  Security policy: {len(pol)}")
            for p in pol:
                p["repo"] = f"{owner}/{repo}"
                p["package"] = ""
            all_results.extend(pol)
    # Save to CSV
    if all_results:
        today = datetime.datetime.now().strftime("%Y%m%d")
        filename = f"all_security_events_{today}.csv"
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["repo", "type", "link", "package", "severity"])
            writer.writeheader()
            writer.writerows(all_results)
        print(f"\nSaved all results to {filename}")
    else:
        print("\nNo security events found.")

if __name__ == "__main__":
    main() 