#!/bin/bash
# Development tooling setup and test script

echo "🔧 Testing development tooling setup..."
echo

echo "📋 Available scripts:"
echo "  ./scripts/lint.sh          - Run ESLint"
echo "  ./scripts/lint-fix.sh      - Run ESLint with --fix"
echo "  ./scripts/format.sh        - Format code with Prettier"
echo "  ./scripts/format-check.sh  - Check code formatting"
echo

echo "🧪 Testing tools..."

echo "✨ Prettier version:"
npx prettier --version

echo "🔍 ESLint version:"
npx eslint --version

echo "🔗 lint-staged version:"
npx lint-staged --version

echo
echo "✅ All tools are installed and ready to use!"
echo "📝 Use 'npx lint-staged' to run pre-commit checks manually"