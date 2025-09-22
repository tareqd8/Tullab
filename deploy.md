# Tollab Deployment Guide

This guide covers deployment strategies for all Tollab applications: API, Admin web portal, and mobile apps.

## Prerequisites

- Docker and Docker Compose installed
- Node.js 18+ and pnpm
- Expo CLI and EAS CLI for mobile apps
- Domain name and SSL certificate
- VPS or cloud server access

## Quick Start

### Development Environment

1. **Install dependencies:**
   ```bash
   pnpm install
   ```

2. **Set up environment variables:**
   ```bash
   cp apps/api/.env.example apps/api/.env
   cp apps/admin/.env.example apps/admin/.env
   cp apps/student/.env.example apps/student/.env
   cp apps/merchant/.env.example apps/merchant/.env
   ```

3. **Start all services:**
   ```bash
   ./scripts/dev.sh
   ```

### Production Build

```bash
./scripts/build.sh
```

---

## API Deployment (Backend)

### Option 1: Docker Deployment to VPS

#### 1. Prepare Server

```bash
# Install Docker and Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### 2. Create Docker Compose Configuration

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: apps/api/Dockerfile
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
      - JWT_SECRET=${JWT_SECRET}
      - JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
      - SESSION_SECRET=${SESSION_SECRET}
      - PORT=3000
    ports:
      - "3000:3000"
    restart: unless-stopped
    depends_on:
      - postgres
    networks:
      - tollab-network

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=${DB_NAME}
      - POSTGRES_USER=${DB_USER}
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    # SECURITY: DO NOT expose database ports in production
    # Use SSH tunnel or internal network access only
    restart: unless-stopped
    networks:
      - tollab-network

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - api
    restart: unless-stopped
    networks:
      - tollab-network

volumes:
  postgres_data:

networks:
  tollab-network:
    driver: bridge
```

#### 3. Nginx Configuration

Create `nginx/nginx.conf`:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream api {
        server api:3000;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    server {
        listen 80;
        server_name your-api-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-api-domain.com;

        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

        # Security headers
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location / {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://api;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        location /health {
            access_log off;
            proxy_pass http://api;
        }
    }
}
```

#### 4. Deploy

```bash
# Create production environment file
cp apps/api/.env.example .env.production

# Edit with production values
# DATABASE_URL, JWT secrets, etc.

# Deploy
docker-compose -f docker-compose.prod.yml up -d

# Check logs
docker-compose -f docker-compose.prod.yml logs -f
```

### Option 2: Platform as a Service (Heroku, Railway, etc.)

#### Heroku Deployment

1. **Install Heroku CLI and login:**
   ```bash
   heroku login
   ```

2. **Create application:**
   ```bash
   heroku create tollab-api
   heroku addons:create heroku-postgresql:mini
   ```

3. **Set environment variables:**
   ```bash
   heroku config:set NODE_ENV=production
   heroku config:set JWT_SECRET=your-jwt-secret
   heroku config:set JWT_REFRESH_SECRET=your-refresh-secret
   heroku config:set SESSION_SECRET=your-session-secret
   ```

4. **Deploy:**
   ```bash
   # Note: Use container deployment for Docker-based apps
   heroku container:push web --app tollab-api
   heroku container:release web --app tollab-api
   ```

---

## Admin App Deployment (Frontend)

### Option 1: Static Hosting (Netlify, Vercel, etc.)

#### Netlify Deployment

1. **Build the application:**
   ```bash
   cd apps/admin
   pnpm build
   ```

2. **Create `_redirects` file:**
   ```bash
   echo "/* /index.html 200" > dist/_redirects
   ```

3. **Deploy via Netlify CLI:**
   ```bash
   npx netlify-cli deploy --prod --dir=dist
   ```

4. **Environment Variables:**
   Set in Netlify dashboard:
   - `VITE_API_URL=https://your-api-domain.com/api`
   - Other environment variables from `.env.example`

#### Vercel Deployment

1. **Install Vercel CLI:**
   ```bash
   npm i -g vercel
   ```

2. **Deploy:**
   ```bash
   cd apps/admin
   vercel --prod
   ```

3. **Configure vercel.json:**
   ```json
   {
     "rewrites": [{ "source": "/(.*)", "destination": "/index.html" }],
     "headers": [
       {
         "source": "/(.*)",
         "headers": [
           {
             "key": "X-Frame-Options",
             "value": "DENY"
           },
           {
             "key": "X-Content-Type-Options",
             "value": "nosniff"
           }
         ]
       }
     ]
   }
   ```

### Option 2: Docker Behind Nginx

#### Docker Deployment

1. **Build and deploy with Docker Compose:**
   
   Add to your `docker-compose.prod.yml`:

   ```yaml
   admin:
     build:
       context: .
       dockerfile: apps/admin/Dockerfile
     ports:
       - "8080:8080"
     environment:
       - NODE_ENV=production
     restart: unless-stopped
     networks:
       - tollab-network
   ```

2. **Update Nginx to serve admin:**
   
   Add to your nginx configuration:

   ```nginx
   server {
       listen 443 ssl http2;
       server_name your-admin-domain.com;

       ssl_certificate /etc/nginx/ssl/cert.pem;
       ssl_certificate_key /etc/nginx/ssl/key.pem;

       location / {
           proxy_pass http://admin:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

---

## Mobile Apps Deployment

### Prerequisites

1. **Install EAS CLI:**
   ```bash
   npm install -g @expo/cli eas-cli
   ```

2. **Login to Expo:**
   ```bash
   eas login
   ```

3. **Configure EAS Build:**
   
   In each mobile app directory (`apps/student` and `apps/merchant`), create `eas.json`:

   ```json
   {
     "cli": {
       "version": ">= 5.2.0"
     },
     "build": {
       "development": {
         "developmentClient": true,
         "distribution": "internal"
       },
       "preview": {
         "distribution": "internal",
         "ios": {
           "resourceClass": "m-medium"
         }
       },
       "production": {
         "ios": {
           "resourceClass": "m-medium"
         }
       }
     },
     "submit": {
       "production": {}
     }
   }
   ```

### Student App Deployment

1. **Configure app.json:**
   ```json
   {
     "expo": {
       "name": "Tollab Student",
       "slug": "tollab-student",
       "version": "1.0.0",
       "scheme": "tollab-student",
       "platforms": ["ios", "android"],
       "ios": {
         "bundleIdentifier": "com.tollab.student"
       },
       "android": {
         "package": "com.tollab.student"
       },
       "extra": {
         "eas": {
           "projectId": "your-student-project-id"
         }
       }
     }
   }
   ```

2. **Build for production:**
   ```bash
   cd apps/student
   
   # Build for iOS
   eas build --platform ios --profile production
   
   # Build for Android
   eas build --platform android --profile production
   
   # Build for both platforms
   eas build --platform all --profile production
   ```

3. **Submit to App Stores:**
   ```bash
   # Submit to App Store
   eas submit --platform ios
   
   # Submit to Google Play
   eas submit --platform android
   ```

### Merchant App Deployment

Follow the same process as Student app, but with merchant-specific configuration:

1. **Configure app.json:**
   ```json
   {
     "expo": {
       "name": "Tollab Merchant",
       "slug": "tollab-merchant",
       "ios": {
         "bundleIdentifier": "com.tollab.merchant"
       },
       "android": {
         "package": "com.tollab.merchant"
       }
     }
   }
   ```

2. **Build and submit:**
   ```bash
   cd apps/merchant
   eas build --platform all --profile production
   eas submit --platform all
   ```

---

## Environment Configuration

### Production Environment Variables

#### API (.env)
```bash
# Database
DATABASE_URL="postgresql://user:pass@localhost:5432/tollab_prod"

# Security (Generate strong secrets!)
JWT_SECRET="super-secure-jwt-secret-min-32-chars"
JWT_REFRESH_SECRET="super-secure-refresh-secret-min-32-chars"  
SESSION_SECRET="super-secure-session-secret-min-32-chars"

# Server
NODE_ENV="production"
PORT="3000"

# CORS (Add your domains)
CORS_ORIGINS="https://admin.tollab.com,https://tollab.com"

# Rate Limiting
RATE_LIMIT_WINDOW_MS="900000"
RATE_LIMIT_MAX_REQUESTS="100"

# Logging
LOG_LEVEL="info"
```

#### Admin (.env)
```bash
# API Configuration
VITE_API_URL="https://api.tollab.com/api"

# App Configuration
VITE_APP_TITLE="Tollab Admin Portal"
NODE_ENV="production"
```

#### Mobile Apps (.env)
```bash
# API Configuration
EXPO_PUBLIC_API_URL="https://api.tollab.com/api"

# App Configuration
EXPO_PUBLIC_APP_VERSION="1.0.0"
NODE_ENV="production"

# Feature Flags
EXPO_PUBLIC_ENABLE_SCREEN_CAPTURE_PROTECTION="true"
EXPO_PUBLIC_ENABLE_ANALYTICS="true"

# External Services
EXPO_PUBLIC_SENTRY_DSN="your-sentry-dsn"
```

---

## SSL/HTTPS Setup

### Let's Encrypt with Certbot

1. **Install Certbot:**
   ```bash
   sudo apt-get update
   sudo apt-get install certbot python3-certbot-nginx
   ```

2. **Generate certificates:**
   ```bash
   sudo certbot --nginx -d your-api-domain.com -d your-admin-domain.com
   ```

3. **Auto-renewal:**
   ```bash
   sudo crontab -e
   # Add: 0 12 * * * /usr/bin/certbot renew --quiet
   ```

### Manual SSL Certificate

1. **Place certificates in `nginx/ssl/`:**
   - `cert.pem` (certificate)
   - `key.pem` (private key)

2. **Update nginx configuration with SSL settings**

---

## Monitoring and Logging

### Health Checks

API includes health check endpoints:
- `GET /health` - Basic health check
- `GET /api/health/detailed` - Detailed system status (if implemented)

**Important**: Verify your API has a `/health` endpoint or update the Docker health check accordingly.

### Logging

Configure log aggregation:
```yaml
# Add to docker-compose.prod.yml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Monitoring Setup

1. **Application Performance Monitoring (APM):**
   - Add Sentry DSN to environment variables
   - Configure error tracking in applications

2. **Infrastructure Monitoring:**
   - Set up server monitoring (CPU, memory, disk)
   - Database performance monitoring
   - SSL certificate expiry monitoring

---

## Troubleshooting

### Common Issues

1. **Database Connection Issues:**
   ```bash
   # Check database connectivity
   docker-compose exec api npm run db:push
   ```

2. **SSL Certificate Problems:**
   ```bash
   # Test SSL configuration
   openssl s_client -connect your-domain.com:443 -servername your-domain.com
   ```

3. **Mobile App Build Failures:**
   ```bash
   # Clear Expo cache
   npx expo install --fix
   npx expo r -c
   ```

4. **CORS Issues:**
   - Verify `CORS_ORIGINS` environment variable
   - Check frontend `VITE_API_URL` configuration

### Logs Access

```bash
# API logs
docker-compose logs -f api

# Admin logs
docker-compose logs -f admin

# Nginx logs
docker-compose logs -f nginx

# Database logs  
docker-compose logs -f postgres
```

---

## Security Checklist

- [ ] Strong JWT secrets (min 32 characters)
- [ ] Database credentials secured
- [ ] **Database ports NOT exposed publicly** (remove port mappings in production)
- [ ] **API/Admin services NOT exposed publicly** (only Nginx on ports 80/443)
- [ ] HTTPS enabled with valid certificates
- [ ] CORS properly configured
- [ ] Rate limiting enabled
- [ ] Security headers configured
- [ ] Regular security updates
- [ ] Database backups configured
- [ ] Error logging without sensitive data
- [ ] Input validation on all endpoints
- [ ] Database access via SSH tunnel or internal network only
- [ ] Host firewall/security groups allow only ports 80/443

---

## Backup Strategy

### Database Backups

```bash
# Automated backup script
#!/bin/bash
docker-compose exec -T postgres pg_dump -U $DB_USER $DB_NAME | gzip > "backup-$(date +%Y%m%d-%H%M%S).sql.gz"

# Restore from backup
gunzip -c backup-20240101-120000.sql.gz | docker-compose exec -T postgres psql -U $DB_USER $DB_NAME

# SSH Tunnel for secure database access (if needed)
ssh -L 5432:localhost:5432 user@your-server.com
# Then connect locally: postgresql://user:pass@localhost:5432/dbname
```

### Application Backups

- Code: Git repository with tags for releases
- Configuration: Environment files backup
- SSL certificates: Regular backup of certificate files
- Application data: Regular database dumps

---

For additional support or questions, refer to the individual application documentation in each `apps/` directory.