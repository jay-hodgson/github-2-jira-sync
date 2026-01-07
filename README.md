# Dependabot to Jira Sync

This script automatically syncs Dependabot security alerts from GitHub to Jira tickets.

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables

#### GitHub Token
Create a personal access token at: https://github.com/settings/tokens

Required scopes:
- `repo` (Full control of private repositories)
- `security_events` (Read and write security events)

```bash
export GITHUB_TOKEN="your_github_token_here"
```

#### Jira Credentials
Create an API token at: https://id.atlassian.com/manage-profile/security/api-tokens

```bash
export JIRA_EMAIL="your_email@sagebase.org"
export JIRA_API_TOKEN="your_jira_api_token_here"
export JIRA_BASE_URL="https://sagebionetworks.jira.com"  # Optional, defaults to https://sagebionetworks.jira.com
```

**Note:** Set `JIRA_BASE_URL` to your actual Jira instance URL if it differs from the default.

### 3. Run the Script

```bash
python main.py
```

## Command Line Options

- `--dry-run` or `-n`: Preview what tickets would be created without actually creating them
- `--limit=N`: Process only N alerts (useful for testing)

**Examples:**
```bash
# Test with dry run mode
python main.py --dry-run

# Test with just 1 alert
python main.py --limit=1

# Combine options
python main.py --dry-run --limit=5
```

## What It Does

1. Fetches all open Dependabot alerts from multiple GitHub repositories:
   - `Sage-Bionetworks/SynapseWebClient` → SWC project
   - `Sage-Bionetworks/synapse-web-monorepo` → PORTALS project
2. For each alert:
   - Checks if a Jira ticket already exists (to avoid duplicates)
   - Creates a new ticket in the appropriate Jira project if needed
3. Sets appropriate priority based on severity:
   - CRITICAL → Highest
   - HIGH → High
   - MODERATE → Medium
   - LOW → Low

## Jira Ticket Format

Each ticket includes:
- Repository name, package name and vulnerability summary in the title
- Detailed description with:
  - Repository information
  - Severity and CVSS score
  - Vulnerability description
  - Vulnerable version range
  - Patched version
  - CVE identifiers
  - Link to GitHub alert
- Labels: `dependabot`, `security`, `severity-*`, `alert-*`, `repo-*`

## Example Output

```
============================================================
Dependabot to Jira Sync
Syncing 2 repositories
============================================================


============================================================
Repository: Sage-Bionetworks/SynapseWebClient
Jira Project: SWC
============================================================
Found 5 open alerts

✓ Created ticket SWC-123 for alert #1
○ Alert #2 (lodash) - Ticket exists: SWC-124
✓ Created ticket SWC-125 for alert #3

SynapseWebClient Summary:
  Tickets created: 2
  Tickets skipped: 3

============================================================
Repository: Sage-Bionetworks/synapse-web-monorepo
Jira Project: PORTALS
============================================================
Found 3 open alerts

✓ Created ticket PORTALS-456 for alert #1
✓ Created ticket PORTALS-457 for alert #2
○ Alert #3 (axios) - Ticket exists: PORTALS-458

synapse-web-monorepo Summary:
  Tickets created: 2
  Tickets skipped: 1


============================================================
Overall Summary:
  Total alerts across all repos: 8
  Total tickets created: 4
  Total tickets skipped (already exist): 4
============================================================
```

## Scheduling

To run this automatically, you can set up a cron job or use GitHub Actions.

### Example Cron Job (daily at 9 AM)

```bash
0 9 * * * cd /Users/jhodgson/Dependabot\ Jira\ sync && /usr/bin/python3 main.py >> sync.log 2>&1
```
