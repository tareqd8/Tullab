import { envSchema, type Env } from '../../packages/shared/src/env';

/**
 * Validated environment variables - throws on startup if invalid
 */
export const env: Env = envSchema.parse(process.env);

// Validate critical security requirements
if (process.env.NODE_ENV === 'production') {
  if (env.JWT_SECRET.length < 64) {
    throw new Error('JWT_SECRET must be at least 64 characters in production');
  }
  if (env.JWT_REFRESH_SECRET.length < 64) {
    throw new Error('JWT_REFRESH_SECRET must be at least 64 characters in production');
  }
}

export default env;