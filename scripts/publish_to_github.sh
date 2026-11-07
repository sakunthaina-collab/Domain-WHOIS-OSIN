#!/usr/bin/env bash
# Trustworthy Agent — GitHub Publishing Script
# Developer: NAKARIN SAKULTHAI
# License: MIT License

set -euo pipefail

REPO=""
CREATE_REPO=false
DRY_RUN=false
VISIBILITY="private"

print_usage() {
  cat <<EOF
Usage: $0 --repo OWNER/REPOSITORY [--create] [--public] [--dry-run]

Options:
  --repo OWNER/REPO   Target GitHub repository in OWNER/REPOSITORY format
  --create            Create the repository on GitHub if it doesn't exist
  --public            Set repository visibility to public (default: private)
  --dry-run           Simulate the publishing process without modifying GitHub
  -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO="$2"
      shift 2
      ;;
    --create)
      CREATE_REPO=true
      shift
      ;;
    --public)
      VISIBILITY="public"
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      print_usage
      exit 1
      ;;
  esac
done

if [[ -z "$REPO" ]]; then
  echo "Error: --repo OWNER/REPOSITORY is required."
  print_usage
  exit 1
fi

echo "=========================================================="
echo "🛡️  Trustworthy Agent — Safe GitHub Publisher"
echo "Target Repo : $REPO ($VISIBILITY)"
echo "Create Mode : $CREATE_REPO"
echo "Dry Run     : $DRY_RUN"
echo "=========================================================="

# 1. Scan for obvious secrets
echo "==> Scanning for potential hardcoded secrets..."
SECRET_PATTERNS='(BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY|ghp_[A-Za-z0-9_]{36}|AIza[0-9A-Za-z-_]{35}|api_key[ \t]*=[ \t]*["\x27][A-Za-z0-9-_]{16,}["\x27])'

if git grep -E -I -n "$SECRET_PATTERNS" -- ':!*.lock' ':!*.example' ':!*.log' > /dev/null 2>&1; then
  echo "Error: Potential secrets detected in repository! Publishing aborted."
  git grep -E -I -n "$SECRET_PATTERNS" -- ':!*.lock' ':!*.example' ':!*.log'
  exit 1
fi
echo "✓ Secret scan passed."

if [[ "$DRY_RUN" == "true" ]]; then
  echo "==> [DRY-RUN] Would configure remote 'origin' -> git@github.com:$REPO.git"
  if [[ "$CREATE_REPO" == "true" ]]; then
    echo "==> [DRY-RUN] Would run: gh repo create $REPO --$VISIBILITY --source=. --remote=origin"
  fi
  echo "==> [DRY-RUN] Would push branch 'main' to GitHub origin"
  echo "✓ Dry-run completed successfully. No changes were made."
  exit 0
fi

# 2. Check / Create Repository
if [[ "$CREATE_REPO" == "true" ]]; then
  echo "==> Ensuring GitHub repository exists ($REPO)..."
  if ! gh repo view "$REPO" > /dev/null 2>&1; then
    echo "Creating $VISIBILITY repository: $REPO..."
    gh repo create "$REPO" "--$VISIBILITY" --source=. --remote=origin || true
  else
    echo "Repository already exists on GitHub."
  fi
fi

# 3. Configure Remote & Push
if ! git remote get-url origin > /dev/null 2>&1; then
  git remote add origin "git@github.com:$REPO.git"
else
  git remote set-url origin "git@github.com:$REPO.git"
fi

echo "==> Pushing branch main..."
git push -u origin HEAD:main

echo "=========================================================="
echo "✓ Successfully published to https://github.com/$REPO"
echo "=========================================================="
