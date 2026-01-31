#!/bin/bash

echo "🔍 Verifying .gitignore protection..."
echo ""

# Test function
test_ignored() {
    local file="$1"
    local should_ignore="$2"
    
    if git check-ignore -q "$file"; then
        if [ "$should_ignore" = "yes" ]; then
            echo "✅ $file - correctly ignored"
        else
            echo "⚠️  $file - ignored but shouldn't be"
        fi
    else
        if [ "$should_ignore" = "no" ]; then
            echo "✅ $file - correctly tracked"
        else
            echo "❌ $file - NOT ignored but should be!"
        fi
    fi
}

echo "Files that SHOULD be ignored:"
test_ignored "config.toml" "yes"
test_ignored ".scurl/config.toml" "yes"
test_ignored ".env" "yes"
test_ignored "test.log" "yes"
test_ignored "target/debug/scurl" "yes"
test_ignored ".DS_Store" "yes"
test_ignored "test-script.sh" "yes"

echo ""
echo "Files that should NOT be ignored:"
test_ignored "README.md" "no"
test_ignored "src/main.rs" "no"
test_ignored "Cargo.toml" "no"
test_ignored ".env.example" "no"
test_ignored "examples/safe-example.sh" "no"

echo ""
echo "✨ Verification complete!"
