#!/bin/bash
# Sync knowledge base to AI service and docs folder
# Run from ipmi-monitor root directory

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
AI_REPO="${REPO_ROOT}/../ipmi-monitor-ai"

echo "=== Syncing Knowledge Base ==="
echo "Source: ${REPO_ROOT}/knowledge/"

# 1. Sync to AI service repo
if [ -d "$AI_REPO" ]; then
    echo ""
    echo ">>> Syncing to AI service: ${AI_REPO}/knowledge/"
    cp -r "${REPO_ROOT}/knowledge/"* "${AI_REPO}/knowledge/"
    echo "✅ AI service knowledge updated"
else
    echo "⚠️  AI service repo not found at: $AI_REPO"
fi

# 2. Sync to docs folder (with Jekyll frontmatter)
echo ""
echo ">>> Syncing to docs folder: ${REPO_ROOT}/docs/"

for f in "${REPO_ROOT}/knowledge/"*.md; do
    filename=$(basename "$f")
    target="${REPO_ROOT}/docs/${filename}"
    
    # Check if file already has frontmatter
    if head -1 "$f" | grep -q "^---"; then
        # Already has frontmatter, just copy
        cp "$f" "$target"
    else
        # Add Jekyll frontmatter
        title=$(grep "^# " "$f" | head -1 | sed 's/^# //')
        {
            echo "---"
            echo "layout: default"
            echo "title: ${title}"
            echo "---"
            echo ""
            cat "$f"
        } > "$target"
    fi
    
    # Convert .md links to .html for GitHub Pages
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/\.md)/.html)/g' "$target"
    else
        sed -i 's/\.md)/.html)/g' "$target"
    fi
    
    echo "  ✓ ${filename}"
done

echo ""
echo "✅ Knowledge base sync complete"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit ipmi-monitor: git add -A && git commit -m 'docs: Update knowledge base'"
echo "  3. Commit ipmi-monitor-ai: cd ../ipmi-monitor-ai && git add -A && git commit -m 'sync: Update knowledge base'"

