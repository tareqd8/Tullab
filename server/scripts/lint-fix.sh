#!/bin/bash
# ESLint fix script for the project
ESLINT_USE_FLAT_CONFIG=false npx eslint . --ext .ts,.tsx,.js,.jsx --config .eslintrc.cjs --fix "$@"