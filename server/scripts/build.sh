#!/bin/bash

# Build script for all applications
# This script builds API, Admin web app, and mobile apps for production

echo "Building Tollab applications..."

# Build API
echo "Building API..."
cd apps/api
pnpm build
if [ $? -ne 0 ]; then
    echo "API build failed!"
    exit 1
fi
cd ../..

# Build Admin app
echo "Building Admin web app..."
cd apps/admin
pnpm build
if [ $? -ne 0 ]; then
    echo "Admin build failed!"
    exit 1
fi
cd ../..

echo "Web applications built successfully!"
echo "API build: apps/api/dist/"
echo "Admin build: apps/admin/dist/"
echo ""
echo "To build mobile apps, run:"
echo "  cd apps/student && eas build --platform all"
echo "  cd apps/merchant && eas build --platform all"