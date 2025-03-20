#!/bin/bash
# Dependency Maintenance Script
# This script audits, updates, and validates dependencies
# It can be scheduled via cron to run regularly

# Exit on error
set -e

# Configuration
REQUIREMENTS_FILE="requirements.txt"
BACKUP_FILE="requirements.txt.bak"
LOG_FILE="dependency_maintenance.log"
REPORTS_DIR="reports/dependency-scan"
GIT_BRANCH="dependency-updates"
CREATE_PR=true  # Whether to create a PR for updates
SLACK_WEBHOOK=${SLACK_WEBHOOK:-""}  # Use environment variable if available

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to send notifications
notify() {
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"Dependency Maintenance: $1\"}" \
            "$SLACK_WEBHOOK" || true
    fi
}

# Create log directory
mkdir -p "$REPORTS_DIR"
touch "$LOG_FILE"

log "=== Starting Dependency Maintenance ==="

# Make sure we have the latest dependencies
log "Updating pip..."
pip install --upgrade pip

log "Installing dependency maintenance tools..."
pip install safety pip-audit pip-licenses

# Create a backup of the requirements file
cp "$REQUIREMENTS_FILE" "$BACKUP_FILE"
log "Created backup of $REQUIREMENTS_FILE at $BACKUP_FILE"

# Scan dependencies for vulnerabilities
log "Scanning dependencies for vulnerabilities..."
mkdir -p "$REPORTS_DIR"

# Run Safety Check
log "Running Safety scan..."
SAFETY_OUTPUT=$(safety check -r "$REQUIREMENTS_FILE" --output text)
echo "$SAFETY_OUTPUT" > "$REPORTS_DIR/safety-report.txt"
safety check -r "$REQUIREMENTS_FILE" --json > "$REPORTS_DIR/safety-report.json"

# Count vulnerabilities
VULN_COUNT=$(echo "$SAFETY_OUTPUT" | grep -c "vulnerability" || echo "0")
log "Found $VULN_COUNT vulnerabilities using Safety"

# Run pip-audit
log "Running pip-audit scan..."
PIP_AUDIT_OUTPUT=$(pip-audit -r "$REQUIREMENTS_FILE")
echo "$PIP_AUDIT_OUTPUT" > "$REPORTS_DIR/pip-audit-report.txt"
pip-audit -r "$REQUIREMENTS_FILE" -f json > "$REPORTS_DIR/pip-audit-report.json"

# Check for outdated packages
log "Checking for outdated packages..."
pip list --outdated --format=json > "$REPORTS_DIR/outdated-packages.json"
OUTDATED_COUNT=$(jq length "$REPORTS_DIR/outdated-packages.json")
log "Found $OUTDATED_COUNT outdated packages"

# Generate license report
log "Generating license report..."
pip-licenses --format=json > "$REPORTS_DIR/dependency-licenses.json"
pip-licenses --format=markdown > "$REPORTS_DIR/dependency-licenses.md"

# If vulnerabilities were found, update dependencies
if [ "$VULN_COUNT" -gt 0 ] || [ "$OUTDATED_COUNT" -gt 0 ]; then
    log "Vulnerabilities or outdated packages found, updating dependencies..."
    
    # Create a branch for dependency updates if requested
    if [ "$CREATE_PR" = true ]; then
        # Check if git is available and we're in a git repo
        if command -v git &> /dev/null && git rev-parse --is-inside-work-tree &> /dev/null; then
            log "Creating git branch for dependency updates..."
            # Get current branch so we can return to it
            CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
            
            # Create a new branch or switch to it if it exists
            BRANCH_DATE=$(date '+%Y%m%d')
            BRANCH_NAME="$GIT_BRANCH-$BRANCH_DATE"
            
            # Check if branch exists
            if git show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
                git checkout "$BRANCH_NAME"
            else
                git checkout -b "$BRANCH_NAME"
            fi
        else
            log "Not in a git repository or git command not available"
            CREATE_PR=false
        fi
    fi
    
    # Run dependency updater script
    log "Running dependency updater..."
    python scripts/update_dependencies.py --apply --report
    
    # Generate a lockfile
    log "Generating lockfile..."
    python scripts/generate_lockfile.py --json
    
    # Verify updates with pip check
    log "Verifying dependencies..."
    pip check
    
    # If we're creating a PR, commit and push changes
    if [ "$CREATE_PR" = true ]; then
        log "Committing dependency updates..."
        git add "$REQUIREMENTS_FILE" "requirements.lock" "requirements.json" "$REPORTS_DIR"
        
        # Create commit message with summary of updates
        COMMIT_MSG="Update dependencies\n\n"
        
        # Add vulnerability fixes to commit message
        if [ "$VULN_COUNT" -gt 0 ]; then
            COMMIT_MSG+="Fixed $VULN_COUNT security vulnerabilities\n"
        fi
        
        # Add outdated package updates to commit message
        if [ "$OUTDATED_COUNT" -gt 0 ]; then
            COMMIT_MSG+="Updated $OUTDATED_COUNT outdated packages\n"
        fi
        
        # Commit changes
        git commit -m "$(echo -e "$COMMIT_MSG")"
        
        # Try to push changes
        if git push origin "$BRANCH_NAME"; then
            log "Pushed dependency updates to $BRANCH_NAME"
            
            # If GitHub CLI is available, create a PR
            if command -v gh &> /dev/null; then
                log "Creating pull request..."
                PR_URL=$(gh pr create --title "Dependency Updates $BRANCH_DATE" \
                    --body "This PR updates dependencies to fix security vulnerabilities and update outdated packages." \
                    --base "$CURRENT_BRANCH" \
                    --head "$BRANCH_NAME" || echo "Failed to create PR")
                
                if [[ "$PR_URL" != "Failed to create PR" ]]; then
                    log "Created PR: $PR_URL"
                    notify "Created PR for dependency updates: $PR_URL"
                else
                    log "Failed to create PR"
                    notify "Failed to create PR for dependency updates"
                fi
            else
                log "GitHub CLI not available, skipping PR creation"
                notify "Pushed dependency updates to branch $BRANCH_NAME"
            fi
        else
            log "Failed to push changes"
            notify "Failed to push dependency updates"
        fi
        
        # Switch back to original branch
        git checkout "$CURRENT_BRANCH"
    fi
    
    # Send notification about updates
    notify "Updated dependencies: Fixed $VULN_COUNT vulnerabilities and updated $OUTDATED_COUNT packages"
else
    log "No vulnerabilities or outdated packages found, no updates needed"
    notify "Dependency check completed: No updates needed"
fi

# Generate HTML report
log "Generating HTML report..."
python scripts/generate_dependency_report.py

log "=== Dependency Maintenance Completed ===" 