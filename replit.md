# Overview

Tullab is a comprehensive TypeScript monorepo platform that provides a complete full-stack development solution. The project includes an Express.js API backend, React Native mobile applications for students and merchants, a React-based web admin dashboard, and a client web application. All applications share common code through a centralized shared package, enabling consistent type safety and business logic across the entire ecosystem.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Monorepo Structure
The project uses TurboRepo for efficient build orchestration and dependency management. The architecture follows a modular approach with clear separation of concerns across different application domains while maintaining code reusability through shared packages.

## Frontend Architecture
- **Web Applications**: Built with React and Vite for fast development and optimized builds
- **Mobile Applications**: React Native with Expo for cross-platform mobile development
- **Admin Dashboard**: Dedicated React application with routing and component-based architecture
- **UI Framework**: Utilizes Radix UI components with Tailwind CSS for consistent styling
- **State Management**: TanStack React Query for server state management

## Backend Architecture
- **API Server**: Express.js with TypeScript providing RESTful endpoints
- **Database Layer**: Drizzle ORM with PostgreSQL for type-safe database operations
- **Authentication**: Planned JWT-based authentication with bcrypt for password hashing
- **Error Handling**: Centralized error handling with structured API responses
- **Middleware**: CORS, rate limiting, logging, and security headers

## Data Layer
- **Database**: PostgreSQL with Neon Database as the cloud provider
- **ORM**: Drizzle ORM providing type-safe database queries and migrations
- **Schema Management**: Centralized database schemas in the shared package
- **Migrations**: Automated database migrations with Drizzle Kit

## Code Sharing Strategy
- **Shared Package**: Central package containing database schemas, types, validation schemas, and utility functions
- **Type Safety**: End-to-end TypeScript with Zod for runtime validation
- **Common Utilities**: Shared business logic, date formatting, and string manipulation functions

## Development Tooling
- **Build System**: TurboRepo for optimized builds and caching
- **Type Checking**: TypeScript across all applications with shared configuration
- **Code Quality**: ESLint with TypeScript rules and Prettier for formatting
- **Development Server**: Vite for web applications with hot module replacement

# External Dependencies

## Database Services
- **Neon Database**: Serverless PostgreSQL database hosting
- **WebSocket Support**: For real-time database connections

## UI and Styling
- **Radix UI**: Headless UI components for accessibility and customization
- **Tailwind CSS**: Utility-first CSS framework for styling
- **Lucide React**: Icon library for consistent iconography

## Mobile Development
- **Expo**: React Native development platform and build service
- **React Navigation**: Navigation library for mobile apps
- **React Native Paper**: Material Design components for React Native

## Authentication and Security
- **bcryptjs**: Password hashing library
- **jsonwebtoken**: JWT token generation and verification
- **express-rate-limit**: API rate limiting middleware

## Development and Build Tools
- **Vite**: Fast build tool and development server
- **TurboRepo**: Monorepo build system and task runner
- **Drizzle Kit**: Database migration and introspection tool
- **TypeScript**: Type safety across the entire stack

## API and Data Management
- **TanStack React Query**: Server state management and caching
- **Zod**: Schema validation and type inference
- **Axios**: HTTP client for API requests

## Deployment and DevOps
- **Replit Integration**: Development environment setup with specialized Vite plugins
- **Environment Management**: Centralized environment variable validation
- **Build Optimization**: Production-ready build configurations for all applications