# Tollab - TypeScript Monorepo Platform

> Complete monorepo solution with API backend, React Native mobile apps, web admin dashboard, and shared packages. Built with modern TypeScript, TurboRepo, and industry best practices.

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ 
- **pnpm** 8+
- **PostgreSQL** or Neon Database

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/tollab.git
cd tollab

# Install dependencies
pnpm install

# Set up environment variables
cp apps/api/.env.example apps/api/.env
# Edit apps/api/.env with your database credentials

# Initialize database
cd apps/api && npm run db:push

# Start all applications
pnpm dev
```

## 🗄️ Database Setup

### Prerequisites

- **PostgreSQL** database running locally or **Neon Database** account
- **DATABASE_URL** environment variable configured in your `.env` file

### Database Migration Commands

```bash
# Apply schema changes to database (recommended for development)
cd apps/api && npm run db:push

# Generate and run migrations (for production)
cd apps/api && npm run db:migrate
```

### Database Seeding

Populate your database with comprehensive sample data:

```bash
# Seed database with sample data
cd apps/api && npm run db:seed
```

#### Sample Data Created

The seeding process creates:

- **3 Universities**: UC Berkeley, Stanford University, UCLA
- **5 Discount Categories**: Food & Dining, Retail & Shopping, Entertainment, Technology, Health & Fitness  
- **4 Businesses**: Campus Cafe, TechHub Electronics, FitZone Gym, BookNook
- **4 Students**: Emily Thompson (UCB), Michael Park (Stanford), Sophia Garcia (UCLA), Alex Kim (UCB)
- **5 Discounts**: Various percentage and flat-amount offers from different businesses
- **9 Accounts**: 4 student accounts, 4 merchant accounts, 1 admin account
- **3 QR Tokens**: Active tokens for student verification
- **3 Sample Redemptions**: Approved discount redemptions for testing

#### Test Account Credentials

Use these credentials for development and testing:

**Student Account:**
- Email: `emily.thompson@berkeley.edu`
- Password: `password123`

**Merchant Account:**
- Email: `maria@campuscafe.com`  
- Password: `merchant123`

**Admin Account:**
- Email: `admin@tullab.com`
- Password: `admin123`

### Database Reset

To completely reset your database:

```bash
# Reset schema and apply fresh migrations
cd apps/api && npm run db:push --force

# Re-seed with sample data  
cd apps/api && npm run db:seed
```

### Environment Variables

Ensure your `.env` file contains:

```env
DATABASE_URL="postgresql://username:password@localhost:5432/tollab_dev"
NODE_ENV="development"
JWT_SECRET="your-jwt-secret-key"
```

For **Neon Database**, use the connection string format:
```env
DATABASE_URL="postgresql://username:password@ep-example-123456.us-east-1.aws.neon.tech/neondb?sslmode=require"
```

### Troubleshooting

**Database Connection Issues:**
- Ensure PostgreSQL is running locally or your Neon Database is accessible
- Verify DATABASE_URL format is correct
- Check firewall settings for database connections

**Migration Errors:**
- Use `cd apps/api && npm run db:push --force` to force schema changes (data loss warning)
- Ensure no active connections to the database during migration

**Seeding Failures:**
- Verify database schema is up to date: `cd apps/api && npm run db:push`
- Check for existing data conflicts before re-seeding
