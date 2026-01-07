#!/usr/bin/env python3
"""
Dependabot to Jira Sync Script
Syncs Dependabot security alerts from GitHub to Jira tickets
"""

import os
import sys
import requests
from typing import List, Dict, Optional
import json
from dotenv import load_dotenv


class DependabotJiraSync:
    def __init__(self, github_token: str, jira_email: str, jira_token: str, jira_base_url: str = "https://sagebionetworks.atlassian.net", dry_run: bool = False, limit: Optional[int] = None):
        """
        Initialize the sync tool
        
        Args:
            github_token: GitHub personal access token with repo and security_events scopes
            jira_email: Jira account email
            jira_token: Jira API token
            jira_base_url: Base URL for Jira instance (e.g., https://yourcompany.atlassian.net)
            dry_run: If True, report what would be created without actually creating tickets
            limit: If set, process only this many alerts total (useful for testing)
        """
        self.github_token = github_token
        self.jira_email = jira_email
        self.jira_token = jira_token
        self.dry_run = dry_run
        self.limit = limit
        self.github_api = "https://api.github.com"
        self.jira_api = f"{jira_base_url.rstrip('/')}/rest/api/3"
        
        # Repository to Jira project mappings
        self.repo_mappings = [
            {
                "owner": "Sage-Bionetworks",
                "repo": "SynapseWebClient",
                "jira_project": "SWC"
            },
            {
                "owner": "Sage-Bionetworks",
                "repo": "synapse-web-monorepo",
                "jira_project": "PORTALS"
            }
        ]
        
    def get_github_headers(self) -> Dict[str, str]:
        """Get headers for GitHub API requests"""
        return {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def get_jira_auth(self):
        """Get authentication tuple for Jira API requests"""
        return (self.jira_email, self.jira_token)
    
    def test_jira_auth(self) -> bool:
        """Test basic Jira authentication"""
        url = f"{self.jira_api}/myself"
        
        response = requests.get(
            url,
            auth=self.get_jira_auth(),
            headers={"Accept": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            user_info = response.json()
            print(f"✓ Authenticated as: {user_info.get('displayName', 'Unknown')}")
            return True
        else:
            print(f"✗ Authentication failed (Status: {response.status_code})")
            print(f"  Please check JIRA_EMAIL and JIRA_API_TOKEN in your .env file")
            print(f"  Create a new API token at: https://id.atlassian.com/manage-profile/security/api-tokens")
            return False
    
    def validate_jira_connection(self, jira_project: str) -> Dict:
        """Validate Jira connection and get project metadata"""
        url = f"{self.jira_api}/project/{jira_project}"
        
        response = requests.get(
            url,
            auth=self.get_jira_auth(),
            headers={"Accept": "application/json"}
        )
        
        if response.status_code != 200:
            print(f"✗ Failed to connect to Jira project {jira_project}")
            return {"valid": False}
        
        project_info = response.json()
        
        # Get issue types for this project
        meta_url = f"{self.jira_api}/issue/createmeta/{jira_project}/issuetypes"
        meta_response = requests.get(
            meta_url,
            auth=self.get_jira_auth(),
            headers={"Accept": "application/json"}
        )
        
        issue_types = []
        if meta_response.status_code == 200:
            issue_types = [it["name"] for it in meta_response.json().get("issueTypes", [])]
        
        # Get available priorities
        priority_url = f"{self.jira_api}/priority"
        priority_response = requests.get(
            priority_url,
            auth=self.get_jira_auth(),
            headers={"Accept": "application/json"}
        )
        
        priorities = []
        if priority_response.status_code == 200:
            priorities = [p["name"] for p in priority_response.json()]
        
        return {
            "valid": True,
            "key": project_info.get("key"),
            "name": project_info.get("name"),
            "issue_types": issue_types,
            "priorities": priorities
        }
    
    def get_dependabot_alerts(self, repo_owner: str, repo_name: str) -> List[Dict]:
        """
        Fetch all open Dependabot alerts from GitHub
        
        Args:
            repo_owner: GitHub repository owner
            repo_name: GitHub repository name
        
        Returns:
            List of alert dictionaries
        """
        url = f"{self.github_api}/repos/{repo_owner}/{repo_name}/dependabot/alerts"
        params = {
            "state": "open",
            "per_page": 100
        }
        
        all_alerts = []
        
        while url:
            response = requests.get(
                url, 
                headers=self.get_github_headers(),
                params=params
            )
            
            if response.status_code != 200:
                print(f"Error fetching alerts: {response.status_code}")
                print(f"Response: {response.text}")
                break
            
            alerts = response.json()
            if not alerts:
                break
                
            all_alerts.extend(alerts)
            
            # GitHub uses Link header for pagination
            # Extract next page URL from Link header if it exists
            link_header = response.headers.get("Link", "")
            url = None
            params = {}  # Clear params for subsequent requests (URL will be complete)
            
            if link_header:
                # Parse Link header to find 'next' relation
                links = link_header.split(",")
                for link in links:
                    if 'rel="next"' in link:
                        # Extract URL from <URL>
                        url = link[link.find("<")+1:link.find(">")]
                        break
        
        print(f"Found {len(all_alerts)} open Dependabot alerts")
        return all_alerts
    
    def search_jira_ticket(self, alert_number: int, repo_name: str, jira_project: str) -> Optional[str]:
        """
        Search for existing Jira ticket for a Dependabot alert
        
        Args:
            alert_number: The Dependabot alert number
            repo_name: GitHub repository name (to distinguish alerts from different repos)
            jira_project: Jira project key
            
        Returns:
            Jira ticket key if found, None otherwise
        """
        url = f"{self.jira_api}/search/jql"
        
        # Create labels to search for
        alert_label = f"alert-{alert_number}"
        repo_label = f"repo-{repo_name.lower().replace('-', '_')}"
        
        # Search for tickets with both labels
        jql = f'project = {jira_project} AND labels = "{alert_label}" AND labels = "{repo_label}"'
        
        params = {
            "jql": jql,
            "maxResults": 1,
            "fields": "key,summary,labels"
        }
        
        response = requests.get(
            url,
            auth=self.get_jira_auth(),
            params=params
        )
        
        if response.status_code == 200:
            results = response.json()
            if results.get("issues"):
                ticket = results["issues"][0]
                return ticket["key"]
        else:
            # Debug: print why search failed
            print(f"  Search failed (Status {response.status_code}): {response.text[:200]}")
        
        return None
    
    def _get_patched_version(self, vulnerability: Dict) -> str:
        """
        Safely extract patched version from vulnerability data
        
        Args:
            vulnerability: Vulnerability dictionary from GitHub API
            
        Returns:
            Patched version string or 'N/A'
        """
        first_patched = vulnerability.get('first_patched_version')
        
        if first_patched is None:
            return 'N/A'
        
        # If it's a dict with identifier key
        if isinstance(first_patched, dict):
            return first_patched.get('identifier', 'N/A')
        
        # If it's already a string
        if isinstance(first_patched, str):
            return first_patched
        
        return 'N/A'
    
    def create_jira_ticket(self, alert: Dict, repo_owner: str, repo_name: str, jira_project: str, jira_priorities: List[str] = None) -> Optional[str]:
        """
        Create a Jira ticket for a Dependabot alert
        
        Args:
            alert: Dependabot alert dictionary
            repo_owner: GitHub repository owner
            repo_name: GitHub repository name
            jira_project: Jira project key
            
        Returns:
            Created ticket key or None if failed (or simulated key in dry run mode)
        """
        alert_number = alert["number"]
        security_advisory = alert.get("security_advisory", {})
        vulnerability = alert.get("security_vulnerability", {})
        
        package = vulnerability.get("package", {}).get("name", "Unknown")
        severity = security_advisory.get("severity", "unknown").upper()
        summary = security_advisory.get("summary", "No summary available")
        description = security_advisory.get("description", "No description available")
        cvss_score = security_advisory.get("cvss", {}).get("score", "N/A")
        
        # Determine priority based on severity and available priorities
        priority_map = {
            "CRITICAL": ["Highest", "Critical", "High"],
            "HIGH": ["High", "Highest", "Critical", "Medium"],
            "MODERATE": ["Medium", "High", "Low"],
            "LOW": ["Low", "Lowest", "Medium"]
        }
        
        # Find first matching priority from available priorities
        priority = None
        if jira_priorities:
            for preferred in priority_map.get(severity, ["Medium"]):
                if preferred in jira_priorities:
                    priority = preferred
                    break
        
        # Build ticket description - keep it simple and direct to GitHub for full details
        github_url = alert.get('html_url')
        
        ticket_description = f"""DEPENDABOT SECURITY ALERT

Package: {package}
Severity: {severity} (CVSS Score: {cvss_score})
Vulnerable Version: {vulnerability.get('vulnerable_version_range', 'N/A')}
Patched Version: {self._get_patched_version(vulnerability)}

SUMMARY
{summary}

FULL DETAILS
For the complete vulnerability description, proof of concept, impact analysis, and remediation steps, please view the full security advisory on GitHub:
{github_url}

REFERENCES
"""
        
        # Add CVE identifiers
        for identifier in security_advisory.get("identifiers", []):
            ticket_description += f"{identifier.get('type')}: {identifier.get('value')}\n"
        
        # In dry run mode, print what would be created and return a simulated ticket key
        if self.dry_run:
            print(f"[DRY RUN] Would create ticket for alert #{alert_number}:")
            print(f"  Project: {jira_project}")
            print(f"  Summary: Dependabot - {package}: {summary[:60]}")
            print(f"  Package: {package}")
            print(f"  Severity: {severity} (CVSS: {cvss_score})")
            print(f"  Priority: {priority if priority else 'Not set'}")
            print(f"  Alert URL: {alert.get('html_url')}")
            return f"{jira_project}-DRYRUN"
        
        url = f"{self.jira_api}/issue"
        
        payload = {
            "fields": {
                "project": {
                    "key": jira_project
                },
                "summary": f"Dependabot - {package}: {summary[:60]}",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": ticket_description
                                }
                            ]
                        }
                    ]
                },
                "issuetype": {
                    "name": "Task"
                },
                "labels": [
                    "dependabot",
                    "security",
                    f"severity-{severity.lower()}",
                    f"alert-{alert_number}",
                    f"repo-{repo_name.lower().replace('-', '_')}"
                ]
            }
        }
        
        # Add priority only if available
        if priority:
            payload["fields"]["priority"] = {"name": priority}
        
        response = requests.post(
            url,
            auth=self.get_jira_auth(),
            headers={"Content-Type": "application/json"},
            json=payload
        )
        
        if response.status_code == 201:
            ticket_key = response.json().get("key")
            print(f"✓ Created ticket {ticket_key} for alert #{alert_number}")
            return ticket_key
        else:
            print(f"✗ Failed to create ticket for alert #{alert_number}")
            print(f"  Status: {response.status_code}")
            # Try to parse JSON error, otherwise show raw text
            try:
                error_data = response.json()
                print(f"  Error: {json.dumps(error_data, indent=2)}")
            except:
                # Show first 500 chars of HTML/text response
                print(f"  Response: {response.text[:500]}")
            return None
    
    def sync_alerts(self):
        """Main sync function - syncs alerts for all configured repositories"""
        print("="*60)
        print("Dependabot to Jira Sync")
        if self.dry_run:
            print("*** DRY RUN MODE - No tickets will be created ***")
        if self.limit:
            print(f"*** LIMIT MODE - Processing only {self.limit} alert(s) ***")
        print(f"Syncing {len(self.repo_mappings)} repositories")
        print("="*60)
        print()
        
        # Test Jira authentication once before processing
        if not self.test_jira_auth():
            print("\n⚠ Jira authentication failed. Please check your credentials.")
            return
        print()
        
        total_created = 0
        total_skipped = 0
        total_alerts = 0
        total_processed = 0
        
        for mapping in self.repo_mappings:
            repo_owner = mapping["owner"]
            repo_name = mapping["repo"]
            jira_project = mapping["jira_project"]
            
            print(f"\n{'='*60}")
            print(f"Repository: {repo_owner}/{repo_name}")
            print(f"Jira Project: {jira_project}")
            print(f"{'='*60}")
            
            # Validate Jira connection first
            jira_info = self.validate_jira_connection(jira_project)
            
            if not jira_info.get("valid"):
                print(f"⚠ Skipping {repo_name} - Jira connection failed")
                continue
            
            print(f"✓ Connected to Jira project: {jira_info.get('name', jira_project)}")
            print()
            
            # Fetch all open alerts for this repo
            alerts = self.get_dependabot_alerts(repo_owner, repo_name)
            
            if not alerts:
                print("No open Dependabot alerts found.")
                continue
            
            print(f"Found {len(alerts)} open alerts\n")
            total_alerts += len(alerts)
            
            created_count = 0
            skipped_count = 0
            
            for alert in alerts:
                # Check if we've reached the limit
                if self.limit and total_processed >= self.limit:
                    print(f"\n⚠ Reached limit of {self.limit} alert(s). Stopping.")
                    break
                
                alert_number = alert["number"]
                package = alert.get("security_vulnerability", {}).get("package", {}).get("name", "Unknown")
                
                # Check if ticket already exists
                existing_ticket = self.search_jira_ticket(alert_number, repo_name, jira_project)
                
                if existing_ticket:
                    print(f"○ Alert #{alert_number} ({package}) - Ticket exists: {existing_ticket}")
                    skipped_count += 1
                else:
                    # Create new ticket
                    ticket_key = self.create_jira_ticket(
                        alert, 
                        repo_owner, 
                        repo_name, 
                        jira_project,
                        jira_priorities=jira_info.get("priorities")
                    )
                    if ticket_key:
                        created_count += 1
                
                total_processed += 1
            
            total_created += created_count
            total_skipped += skipped_count
            
            # Break out of repo loop if limit reached
            if self.limit and total_processed >= self.limit:
                break
            
            print(f"\n{repo_name} Summary:")
            print(f"  Tickets created: {created_count}")
            print(f"  Tickets skipped: {skipped_count}")
        
        print(f"\n\n{'='*60}")
        print(f"Overall Summary:")
        print(f"  Total alerts across all repos: {total_alerts}")
        print(f"  Total tickets created: {total_created}")
        print(f"  Total tickets skipped (already exist): {total_skipped}")
        print("="*60)


def main():
    """Main entry point"""
    # Load environment variables from .env file if present
    load_dotenv()
    
    # Check for command line flags
    dry_run = "--dry-run" in sys.argv or "-n" in sys.argv
    
    # Check for limit flag (e.g., --limit=1 or --limit 1)
    limit = None
    for arg in sys.argv:
        if arg.startswith("--limit="):
            limit = int(arg.split("=")[1])
        elif arg == "--limit" and sys.argv.index(arg) + 1 < len(sys.argv):
            limit = int(sys.argv[sys.argv.index(arg) + 1])
    
    # Get credentials from environment variables
    github_token = os.environ.get("GITHUB_TOKEN")
    jira_email = os.environ.get("JIRA_EMAIL")
    jira_token = os.environ.get("JIRA_API_TOKEN")
    jira_base_url = os.environ.get("JIRA_BASE_URL", "https://sagebionetworks.jira.com")
    
    if not github_token:
        print("Error: GITHUB_TOKEN environment variable not set")
        print("Create a token at: https://github.com/settings/tokens")
        print("Required scopes: repo, security_events")
        sys.exit(1)
    
    if not jira_email:
        print("Error: JIRA_EMAIL environment variable not set")
        sys.exit(1)
    
    if not jira_token:
        print("Error: JIRA_API_TOKEN environment variable not set")
        print("Create a token at: https://id.atlassian.com/manage-profile/security/api-tokens")
        sys.exit(1)
    
    # Run sync
    sync = DependabotJiraSync(
        github_token, 
        jira_email, 
        jira_token, 
        jira_base_url=jira_base_url,
        dry_run=dry_run, 
        limit=limit
    )
    sync.sync_alerts()


if __name__ == "__main__":
    main()
