# Security Documentation

## Overview

This document outlines the comprehensive security measures implemented in the Tollab student discount verification platform to protect user data, prevent unauthorized access, and ensure GDPR compliance.

## Authentication & Authorization

### JWT-based Authentication
- **Access Tokens**: 15-minute expiry for short-lived access
- **Refresh Tokens**: 30-day expiry stored as httpOnly cookies
- **Argon2id Password Hashing**: OWASP 2024 recommended settings
  - Memory cost: 19 MiB
  - Time cost: 2 iterations
  - Parallelism: 1 thread

### Role-Based Access Control (RBAC)
- **Admin**: Full system access and management
- **University**: Limited to own university's student data
- **Student**: Self-service profile updates (email/phone only)
- **Merchant**: Student verification and discount redemption

### Protected Data Fields
Students **cannot** modify via any client call:
- `full_name`
- `student_id` 
- `university_id`/`university_name`
- `expires_at`
- `is_active`

Only university/admin endpoints can modify these fields.

## Data Protection & Privacy

### GDPR Compliance
- **Data Minimization**: Merchants only receive essential verification data
- **PII Masking**: Student names, emails, and phone numbers masked in merchant views
- **Right to Erasure**: Data deletion capabilities for user accounts
- **Data Portability**: Export capabilities for user data

### Student Data Masking for Merchants
- **Names**: `Ahmed Hassan` → `A. H.`
- **Emails**: `student@university.edu` → `s*****@university.edu`
- **Phone**: `+971501234567` → `***-***-4567`
- **Student ID**: `STU12345` → `***45`

### Sensitive Data Redaction
All logs automatically redact:
- Passwords and password hashes
- JWT tokens and refresh tokens
- Student PII (names, emails, phones)
- Database credentials
- API keys and secrets

## Rate Limiting

### Endpoint-Specific Limits
- **Authentication** (`/auth/login`): 5 attempts per 15 minutes
- **QR Verification** (`/students/verify`): 20 attempts per 5 minutes
- **Discount Redemption** (`/students/redeem`): 10 attempts per hour
- **General API**: 100 requests per 15 minutes
- **Admin Endpoints**: 200 requests per 15 minutes

### Rate Limiting Strategy
- User-based limiting when authenticated
- IP-based limiting for anonymous requests
- Progressive backoff on repeated violations

## Network Security

### CORS Configuration
Strict origin control allowing only:
- Admin web application origins
- Expo development servers (development only)
- Configured production domains

### Environment Variables
All sensitive configuration validated with Zod:
```typescript
JWT_SECRET: minimum 32 characters (64+ in production)
JWT_REFRESH_SECRET: minimum 32 characters (64+ in production)
SESSION_SECRET: minimum 32 characters
DATABASE_URL: validated URL format
```

## Validation & Eligibility

### Student Eligibility Validation
Every verify/redeem operation validates:
- Student account is active (`is_active: true`)
- Student ID has not expired (`expires_at > now`)
- Student record exists in database
- University affiliation is valid

### Request Validation
- Zod schema validation for all API endpoints
- Input sanitization and type checking
- SQL injection prevention through parameterized queries
- XSS protection through content type validation

## Logging & Monitoring

### Security Logging with Pino
- **Structured Logging**: JSON format for easy parsing
- **PII Redaction**: Automatic removal of sensitive data
- **Audit Trails**: Complete record of authentication and authorization events
- **Error Tracking**: Security incidents and failed access attempts

### Audit Events
- User authentication (success/failure)
- Authorization violations
- Data access patterns
- Administrative actions
- QR verification and redemption activities

## Database Security

### Connection Security
- TLS-encrypted connections to Neon PostgreSQL
- Connection pooling with secure credential management
- Environment-based configuration isolation

### Data Storage
- Passwords hashed with Argon2id (never stored in plaintext)
- Refresh tokens hashed before database storage
- Automatic cleanup of expired tokens
- Foreign key constraints for data integrity

## Mobile Application Security

### QR Code Security
- Time-limited QR tokens (5-minute expiry)
- Cryptographic signatures to prevent tampering
- Rotation IDs to prevent replay attacks
- Student-specific nonces for uniqueness

### API Communication
- HTTPS-only communication in production
- JWT tokens for authenticated requests
- Request/response validation
- Error message sanitization

## Incident Response

### Security Monitoring
- Failed authentication attempt tracking
- Unusual access pattern detection
- Rate limit violation alerts
- Database connection monitoring

### Automated Responses
- Account lockout after repeated failed attempts
- IP-based blocking for abuse patterns
- Token revocation on suspicious activity
- Audit log generation for security events

## Compliance & Standards

### Industry Standards
- **OWASP Top 10**: Protection against common vulnerabilities
- **GDPR**: European data protection compliance
- **ISO 27001**: Information security management practices
- **JWT Best Practices**: RFC 7519 and security recommendations

### Regular Security Practices
- Dependency vulnerability scanning
- Code security reviews
- Penetration testing recommendations
- Security training for development team

## Configuration Security

### Environment Management
```bash
# Required environment variables
JWT_SECRET=<64+ character random string>
JWT_REFRESH_SECRET=<64+ character random string>
SESSION_SECRET=<32+ character random string>
DATABASE_URL=<encrypted connection string>
CORS_ORIGINS=<comma-separated allowed origins>
```

### Production Hardening
- Minimum 64-character JWT secrets
- HTTPS-only cookie settings
- Secure headers configuration
- Database connection encryption

## Data Retention

### Automatic Cleanup
- Expired refresh tokens removed daily
- QR verification records expire after 24 hours
- Audit logs retained for 90 days
- Student data retention follows university policies

### Manual Data Management
- Admin tools for data export
- Secure data deletion procedures
- Backup encryption requirements
- Recovery process documentation

## Security Testing

### Recommended Tests
- Authentication bypass attempts
- Authorization escalation testing
- SQL injection vulnerability scanning
- XSS and CSRF protection validation
- Rate limiting effectiveness testing

### Penetration Testing Checklist
- [ ] API endpoint authentication
- [ ] Role-based access controls
- [ ] Data masking effectiveness
- [ ] Rate limiting bypasses
- [ ] JWT token security
- [ ] QR code tampering
- [ ] Database injection attacks
- [ ] Cross-origin request validation

## Contact & Reporting

For security concerns or vulnerability reports:
- **Internal**: Security team via internal channels
- **External**: Responsible disclosure process
- **Emergency**: Immediate escalation procedures

---

**Document Version**: 1.0  
**Last Updated**: September 2025  
**Next Review**: December 2025

This security documentation should be reviewed and updated regularly as the system evolves and new security requirements emerge.