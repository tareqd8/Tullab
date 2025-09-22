import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { logger } from './logging';
import env from '../config/env';

/**
 * Rate limiting configuration
 */
const createRateLimit = (options: {
  windowMs: number;
  max: number;
  message: string;
  skipSuccessfulRequests?: boolean;
  standardHeaders?: boolean;
  legacyHeaders?: boolean;
}) => {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: { error: options.message },
    standardHeaders: options.standardHeaders ?? true,
    legacyHeaders: options.legacyHeaders ?? false,
    skipSuccessfulRequests: options.skipSuccessfulRequests ?? false,
    handler: (req: Request, res: Response) => {
      logger.warn({
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.path,
        method: req.method
      }, 'Rate limit exceeded');
      
      res.status(429).json({
        error: options.message,
        retryAfter: Math.round(options.windowMs / 1000)
      });
    },
    keyGenerator: (req: Request) => {
      // Use account ID if authenticated, otherwise use the default IP key generator
      if ((req as any).user?.id) {
        return (req as any).user.id; // This is actually accountId from JWT payload
      }
      // Use the default IP key generator to handle IPv6 properly
      return undefined; // Let express-rate-limit use its default IP-based key
    },
    skip: (req: Request) => {
      // Don't skip any requests - apply rate limiting to all
      return false;
    }
  });
};

/**
 * Strict rate limiting for authentication endpoints
 * 5 attempts per 15 minutes per IP/user
 */
export const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many authentication attempts. Please try again later.',
  skipSuccessfulRequests: true
});

/**
 * Rate limiting for QR code verification - very restrictive for security (QR tokens expire in 45s)
 * 10 verifications per 2 minutes per user
 */
export const verifyRateLimit = createRateLimit({
  windowMs: 2 * 60 * 1000, // 2 minutes
  max: 10, // Reduced limit since QR tokens are very short-lived
  message: 'Too many verification attempts. Please wait before trying again.',
  skipSuccessfulRequests: false
});

/**
 * Rate limiting for QR code generation - prevent abuse
 * 5 QR generations per minute per user
 */
export const qrGenerationRateLimit = createRateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5, // Only 5 QR generations per minute per user
  message: 'Too many QR code requests. Please wait before generating a new code.',
  skipSuccessfulRequests: false
});

/**
 * Rate limiting for discount redemption
 * 10 redemptions per hour per user
 */
export const redeemRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Too many redemption attempts. Please wait before trying again.',
  skipSuccessfulRequests: false
});

/**
 * General API rate limiting
 * 100 requests per 15 minutes per IP/user
 */
export const generalRateLimit = createRateLimit({
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  max: env.RATE_LIMIT_MAX_REQUESTS,
  message: 'Too many requests. Please slow down.',
  skipSuccessfulRequests: true
});

/**
 * Admin-specific rate limiting
 * 200 requests per 15 minutes for admin users
 */
export const adminRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: 'Admin rate limit exceeded. Please wait before continuing.',
  skipSuccessfulRequests: true
});