# Package Scripts Configuration

Since the main package.json cannot be directly edited in this environment, here are the scripts you should add manually:

## Root Package.json Scripts

Add these scripts to your main `package.json` file:

```json
{
  "scripts": {
    "dev": "concurrently \"npm run dev:api\" \"npm run dev:admin\" \"npm run dev:student\" \"npm run dev:merchant\"",
    "dev:api": "NODE_ENV=development tsx server/index.ts",
    "dev:admin": "cd apps/admin && npm run dev",
    "dev:student": "cd apps/student && npx expo start --dev-client --port 8081",
    "dev:merchant": "cd apps/merchant && npx expo start --dev-client --port 8082",
    "build": "npm run build:api && npm run build:admin",
    "build:api": "vite build && esbuild server/index.ts --platform=node --packages=external --bundle --format=esm --outdir=dist",
    "build:admin": "cd apps/admin && npm run build",
    "build:student": "cd apps/student && eas build --platform all",
    "build:merchant": "cd apps/merchant && eas build --platform all",
    "start": "NODE_ENV=production node dist/index.js",
    "check": "tsc",
    "db:push": "drizzle-kit push"
  }
}
```

## Alternative: Use Shell Scripts

If you prefer not to modify package.json, you can use the provided shell scripts:

### Development
```bash
./scripts/dev.sh
```

### Production Build
```bash
./scripts/build.sh
```

## Expo Build Commands for Mobile Apps

### Student App
```bash
cd apps/student

# Development build
npx expo start --dev-client

# Production build
eas build --platform all --profile production

# Submit to stores
eas submit --platform all
```

### Merchant App  
```bash
cd apps/merchant

# Development build
npx expo start --dev-client

# Production build  
eas build --platform all --profile production

# Submit to stores
eas submit --platform all
```

## PNPM Workspace Commands

Since this is a pnpm workspace, you can also use:

```bash
# Install dependencies for all apps
pnpm install

# Run a command in a specific app
pnpm --filter @tullab/api dev
pnpm --filter @tullab/admin build

# Run script in all apps
pnpm -r build

# Development with pnpm
pnpm --filter @tullab/api dev &
pnpm --filter @tullab/admin dev &
```

## Dependencies Required

Make sure you have these installed:

```bash
npm install -g concurrently @expo/cli eas-cli pnpm
```