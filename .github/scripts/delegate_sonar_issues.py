#!/usr/bin/env python3
"""
Query SonarQube for open issues and create one Devin session per issue.
Each session gets a prompt to fix the issue, run tests, and open a PR.
"""

import json
import os
import asyncio
import aiohttp

DEVIN_SERVICE_USER_TOKEN = os.environ["DEVIN_SERVICE_USER_TOKEN"]
DEVIN_ORG_ID = os.environ["DEVIN_ORG_ID"]
SONAR_TOKEN = os.environ["SONAR_TOKEN"]
SONAR_HOST_URL = os.environ["SONAR_HOST_URL"].rstrip("/")
SONAR_PROJECT_KEY = os.environ.get("SONAR_PROJECT_KEY", "mbatchelor81_vuln-bank")

DEVIN_API_URL = f"https://api.devin.ai/v3beta1/organizations/{DEVIN_ORG_ID}/sessions"
SONAR_ISSUES_URL = f"{SONAR_HOST_URL}/api/issues/search"

CREATE_AS_USER_ID = "email|68c322be31ab500694e66453"
REPO = "mbatchelor81/vuln-bank"

MAX_CONCURRENT_SESSIONS = 20

DEVIN_HEADERS = {
    "Authorization": f"Bearer {DEVIN_SERVICE_USER_TOKEN}",
    "Content-Type": "application/json",
}


def fetch_sonar_issues_by_filter(types, severities):
    """Fetch all open issues from SonarQube API with pagination for a given filter."""
    import urllib.request
    import base64

    credentials = base64.b64encode(f"{SONAR_TOKEN}:".encode()).decode()
    all_issues = []
    page = 1
    page_size = 100

    while True:
        params = (
            f"?componentKeys={SONAR_PROJECT_KEY}"
            f"&statuses=OPEN,CONFIRMED,REOPENED"
            f"&types={types}"
            f"&severities={severities}"
            f"&ps={page_size}"
            f"&p={page}"
        )
        req = urllib.request.Request(
            SONAR_ISSUES_URL + params,
            headers={"Authorization": f"Basic {credentials}"},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            raise SystemExit(
                f"SonarQube API error (HTTP {e.code}): {body}"
            )

        issues = data.get("issues", [])
        all_issues.extend(issues)

        total = data.get("total", 0)
        if len(all_issues) >= total or not issues:
            break
        page += 1

    return all_issues


def fetch_all_issues():
    """Fetch security vulnerabilities and code smells from SonarQube."""
    vulns = fetch_sonar_issues_by_filter("VULNERABILITY", "CRITICAL,BLOCKER")
    smells = fetch_sonar_issues_by_filter("CODE_SMELL", "MAJOR")
    return vulns + smells


def group_issues(issues):
    """Group issues by file + rule. Returns a list of issue groups."""
    from collections import defaultdict
    groups = defaultdict(list)
    for issue in issues:
        component = issue.get("component", "").replace(f"{SONAR_PROJECT_KEY}:", "")
        rule = issue.get("rule", "unknown")
        groups[(component, rule)].append(issue)
    return list(groups.values())


def build_session_payload(issue_group):
    """Build a Devin session payload from a group of related issues."""
    first = issue_group[0]
    rule = first.get("rule", "unknown")
    severity = first.get("severity", "MAJOR")
    message = first.get("message", "No description")
    component = first.get("component", "").replace(f"{SONAR_PROJECT_KEY}:", "")
    issue_type = first.get("type", "CODE_SMELL")
    issue_keys = [i.get("key", "unknown") for i in issue_group]

    if len(issue_group) == 1:
        line = first.get("line", "unknown")
        prompt = (
            f"SonarQube Issue Remediation\n\n"
            f"Rule: {rule}\n"
            f"Type: {issue_type}\n"
            f"Severity: {severity}\n"
            f"File: {component}\n"
            f"Line: {line}\n"
            f"Message: {message}\n\n"
            f"Instructions:\n"
            f"1. Open `{component}` and fix the issue at/near line {line}\n"
            f"2. Follow the SonarQube rule guidance for {rule}\n"
            f"3. Run `python -m pytest` and `python -m flake8` to verify nothing breaks\n"
            f"4. If tests fail, fix any regressions caused by the change\n"
            f"5. Create a PR with the title: 'fix({issue_type.lower()}): resolve {severity.lower()} issue in {component}'\n"
        )
    else:
        lines = [str(i.get("line", "?")) for i in issue_group]
        prompt = (
            f"SonarQube Issue Remediation — {len(issue_group)} occurrences\n\n"
            f"Rule: {rule}\n"
            f"Type: {issue_type}\n"
            f"Severity: {severity}\n"
            f"File: {component}\n"
            f"Lines: {', '.join(lines)}\n"
            f"Message: {message}\n\n"
            f"Instructions:\n"
            f"1. Open `{component}` and fix ALL {len(issue_group)} occurrences at lines {', '.join(lines)}\n"
            f"2. Follow the SonarQube rule guidance for {rule}\n"
            f"3. Run `python -m pytest` and `python -m flake8` to verify nothing breaks\n"
            f"4. If tests fail, fix any regressions caused by the change\n"
            f"5. Create a PR with the title: 'fix({issue_type.lower()}): resolve {len(issue_group)} {severity.lower()} issues in {component}'\n"
        )

    short_message = message[:80] + ("..." if len(message) > 80 else "")
    count_label = f" ({len(issue_group)}x)" if len(issue_group) > 1 else ""
    title = f"{severity}: {short_message}{count_label}"

    return {
        "prompt": prompt,
        "create_as_user_id": CREATE_AS_USER_ID,
        "repos": [REPO],
        "title": title,
        "tags": ["sonarqube"] + issue_keys,
    }, component, len(issue_group)


async def create_devin_session(http_session, semaphore, payload, label, count):
    """Create a Devin session from a pre-built payload."""
    async with semaphore:
        async with http_session.post(DEVIN_API_URL, headers=DEVIN_HEADERS, json=payload) as resp:
            result = await resp.json()
            status = "created" if resp.status in (200, 201) else "failed"
            print(f"[{status}] {label} ({count} issue(s)): {result.get('session_id', 'N/A')}")
            return result


async def main():
    print(f"Querying SonarQube at {SONAR_HOST_URL} for project {SONAR_PROJECT_KEY}...")
    all_issues = fetch_all_issues()

    if not all_issues:
        print("No issues found. Exiting.")
        return

    groups = group_issues(all_issues)
    print(f"Found {len(all_issues)} issues in {len(groups)} groups. Creating Devin sessions...")

    payloads = [build_session_payload(g) for g in groups]

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS)
    async with aiohttp.ClientSession() as http_session:
        tasks = [
            create_devin_session(http_session, semaphore, payload, label, count)
            for payload, label, count in payloads
        ]
        await asyncio.gather(*tasks)

    print("All sessions created.")


if __name__ == "__main__":
    asyncio.run(main())
