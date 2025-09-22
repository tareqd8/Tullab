import * as argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { storage } from './storage';
import { refresh_tokens } from '@tullab/shared/schemas';
import { eq, lt } from 'drizzle-orm';
import { db } from './db';

// JWT Configuration - following 2024 security best practices
// Require JWT secrets as environment variables - no defaults for security
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Validate required secrets on startup
if (!JWT_SECRET || !JWT_REFRESH_SECRET) {
  throw new Error('JWT_SECRET and JWT_REFRESH_SECRET environment variables are required for security');
}

// Create validated constants for TypeScript
const VALIDATED_JWT_SECRET: string = JWT_SECRET;
const VALIDATED_JWT_REFRESH_SECRET: string = JWT_REFRESH_SECRET;

if (process.env.NODE_ENV === 'production') {
  if (JWT_SECRET.length < 32 || JWT_REFRESH_SECRET.length < 32) {
    throw new Error('JWT secrets must be at least 32 characters long in production');
  }
}

// Token expiration times - Production Security Settings
const ACCESS_TOKEN_EXPIRY = '5m'; // 5 minutes - Reduced for better security
const REFRESH_TOKEN_EXPIRY = '30d'; // 30 days
const QR_TOKEN_EXPIRY = '45s'; // 45 seconds - Short-lived for security

export interface JWTPayload {
  accountId: string;
  email: string;
  role: 'student' | 'merchant' | 'admin' | 'university';
  university_id?: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  accountId: string;
  tokenId: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenVerification {
  isValid: boolean;
  tokenRecord?: any;
}

export interface QRTokenPayload {
  sub: string; // student_id
  nonce: string;
  rotation_id: string;
  iat?: number;
  exp?: number;
}

export class AuthService {
  /**
   * Hash password using Argon2id with OWASP 2024 recommended settings
   * Memory: 19 MiB, Iterations: 2, Parallelism: 1
   */
  static async hashPassword(password: string): Promise<string> {
    try {
      return await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 19456, // 19 MiB in KB
        timeCost: 2,       // 2 iterations
        parallelism: 1,    // 1 thread
      });
    } catch (error) {
      console.error('Error hashing password with Argon2:', error);
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Verify password against Argon2 hash
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      console.error('Error verifying password with Argon2:', error);
      return false;
    }
  }

  /**
   * Generate JWT access token (15 minutes)
   */
  static generateAccessToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, VALIDATED_JWT_SECRET, {
      expiresIn: ACCESS_TOKEN_EXPIRY,
      issuer: 'tullab-api',
      audience: 'tullab-app',
    });
  }

  /**
   * Generate JWT refresh token (30 days)
   */
  static generateRefreshToken(payload: Omit<RefreshTokenPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, VALIDATED_JWT_REFRESH_SECRET, {
      expiresIn: REFRESH_TOKEN_EXPIRY,
      issuer: 'tullab-api',
      audience: 'tullab-app',
    });
  }

  /**
   * Verify JWT access token
   */
  static verifyAccessToken(token: string): JWTPayload | null {
    try {
      const decoded = jwt.verify(token, VALIDATED_JWT_SECRET, {
        issuer: 'tullab-api',
        audience: 'tullab-app',
      });
      return decoded as JWTPayload;
    } catch (error) {
      console.error('Access token verification failed:', error);
      return null;
    }
  }

  /**
   * Verify JWT refresh token
   */
  static verifyRefreshToken(token: string): RefreshTokenPayload | null {
    try {
      const decoded = jwt.verify(token, VALIDATED_JWT_REFRESH_SECRET, {
        issuer: 'tullab-api',
        audience: 'tullab-app',
      });
      return decoded as RefreshTokenPayload;
    } catch (error) {
      console.error('Refresh token verification failed:', error);
      return null;
    }
  }

  /**
   * Store refresh token hash in database
   */
  static async storeRefreshToken(accountId: string, tokenId: string): Promise<void> {
    if (!db) throw new Error('Database not available');
    
    try {
      const tokenHash = await argon2.hash(tokenId);
      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + 30); // 30 days from now

      // Store refresh token hash in database for persistence and security
      await db.insert(refresh_tokens).values({
        account_id: accountId,
        token_hash: tokenHash,
        expires_at: expiresAt,
      });
      console.log('✅ [AUTH] Refresh token stored securely in database');
    } catch (error) {
      console.error('Error storing refresh token:', error);
      throw new Error('Failed to store refresh token');
    }
  }

  /**
   * Verify refresh token exists in database and is valid
   * Returns the token record if valid for rotation purposes
   */
  static async verifyRefreshTokenInDB(accountId: string, tokenId: string): Promise<{ isValid: boolean; tokenRecord?: any }> {
    if (!db) throw new Error('Database not available');
    
    try {
      const now = new Date();
      // Only query non-expired tokens to optimize performance
      const tokens = await db
        .select()
        .from(refresh_tokens)
        .where(eq(refresh_tokens.account_id, accountId));

      for (const token of tokens) {
        // Check if token is not expired (double-check since DB might have expired tokens)
        if (now > token.expires_at) {
          continue;
        }

        // Verify token hash
        const isValid = await argon2.verify(token.token_hash, tokenId);
        if (isValid) {
          return { isValid: true, tokenRecord: token };
        }
      }

      return { isValid: false };
    } catch (error) {
      console.error('Error verifying refresh token in DB:', error);
      return { isValid: false };
    }
  }

  /**
   * Revoke all refresh tokens for an account (logout)
   */
  static async revokeRefreshTokens(accountId: string): Promise<void> {
    if (!db) throw new Error('Database not available');
    
    try {
      await db
        .delete(refresh_tokens)
        .where(eq(refresh_tokens.account_id, accountId));
    } catch (error) {
      console.error('Error revoking refresh tokens:', error);
      throw new Error('Failed to revoke refresh tokens');
    }
  }

  /**
   * Clean up expired refresh tokens
   */
  static async cleanupExpiredTokens(): Promise<void> {
    if (!db) throw new Error('Database not available');
    
    try {
      const now = new Date();
      const deletedCount = await db
        .delete(refresh_tokens)
        .where(lt(refresh_tokens.expires_at, now));
      console.log(`Cleaned up ${deletedCount} expired refresh tokens`);
    } catch (error) {
      console.error('Error cleaning up expired tokens:', error);
    }
  }

  /**
   * Delete a specific refresh token (for rotation)
   */
  static async deleteRefreshToken(accountId: string, tokenId: string): Promise<void> {
    if (!db) throw new Error('Database not available');
    
    try {
      const tokens = await db
        .select()
        .from(refresh_tokens)
        .where(eq(refresh_tokens.account_id, accountId));

      for (const token of tokens) {
        const isMatch = await argon2.verify(token.token_hash, tokenId);
        if (isMatch) {
          await db
            .delete(refresh_tokens)
            .where(eq(refresh_tokens.id, token.id));
          break;
        }
      }
    } catch (error) {
      console.error('Error deleting refresh token:', error);
      throw new Error('Failed to delete refresh token');
    }
  }

  /**
   * Rotate refresh token - delete old and create new
   * Implements proper token rotation for security
   */
  static async rotateRefreshToken(accountId: string, oldTokenId: string): Promise<{ tokenId: string; refreshToken: string }> {
    if (!db) throw new Error('Database not available');
    
    try {
      // First, delete the old token
      await this.deleteRefreshToken(accountId, oldTokenId);
      
      // Generate new token
      const newTokenId = this.generateTokenId();
      const newRefreshToken = this.generateRefreshToken({
        accountId,
        tokenId: newTokenId,
      });

      // Store new token
      await this.storeRefreshToken(accountId, newTokenId);

      return { tokenId: newTokenId, refreshToken: newRefreshToken };
    } catch (error) {
      console.error('Error rotating refresh token:', error);
      throw new Error('Failed to rotate refresh token');
    }
  }

  /**
   * Detect refresh token reuse - revoke all tokens if reuse detected
   * Critical security feature to prevent token replay attacks
   */
  static async detectTokenReuse(accountId: string, tokenId: string): Promise<boolean> {
    if (!db) throw new Error('Database not available');
    
    try {
      const verification = await this.verifyRefreshTokenInDB(accountId, tokenId);
      
      // If token is not valid but account has tokens, it might be reuse
      if (!verification.isValid) {
        const accountTokens = await db
          .select()
          .from(refresh_tokens)
          .where(eq(refresh_tokens.account_id, accountId));
        
        // If account has tokens but none match, it's likely reuse
        if (accountTokens.length > 0) {
          console.warn(`Potential token reuse detected for account ${accountId}`);
          // Revoke all tokens as security measure
          await this.revokeRefreshTokens(accountId);
          return true;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Error detecting token reuse:', error);
      return false;
    }
  }

  /**
   * Generate a cryptographically secure token ID
   */
  static generateTokenId(): string {
    return randomBytes(32).toString('hex');
  }

  /**
   * Generate QR token with short expiry for security
   */
  static generateQRToken(studentId: string): string {
    const nonce = randomBytes(16).toString('hex');
    const rotation_id = randomBytes(8).toString('hex');
    
    const payload: Omit<QRTokenPayload, 'iat' | 'exp'> = {
      sub: studentId,
      nonce,
      rotation_id,
    };

    return jwt.sign(payload, VALIDATED_JWT_SECRET, {
      expiresIn: QR_TOKEN_EXPIRY, // 45 seconds - Short for security
      issuer: 'tullab-api',
      audience: 'tullab-qr',
    });
  }

  /**
   * Verify QR token
   */
  static verifyQRToken(token: string): QRTokenPayload | null {
    try {
      const decoded = jwt.verify(token, VALIDATED_JWT_SECRET, {
        issuer: 'tullab-api',
        audience: 'tullab-qr',
      });
      return decoded as QRTokenPayload;
    } catch (error) {
      console.error('QR token verification failed:', error);
      return null;
    }
  }
}

/**
 * Express middleware to require authentication
 */
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Access token required',
      timestamp: new Date().toISOString(),
    });
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix
  const payload = AuthService.verifyAccessToken(token);

  if (!payload) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or expired access token',
      timestamp: new Date().toISOString(),
    });
  }

  // Attach user info to request object
  (req as any).user = payload;
  next();
}

/**
 * Express middleware to require specific role
 */
export function requireRole(...roles: ('student' | 'merchant' | 'admin' | 'university')[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user as JWTPayload;
    
    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required',
        timestamp: new Date().toISOString(),
      });
    }

    if (!roles.includes(user.role)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Access denied. Required role: ${roles.join(' or ')}`,
        timestamp: new Date().toISOString(),
      });
    }

    next();
  };
}

/**
 * Utility function to set httpOnly cookie for refresh token
 */
export function setRefreshTokenCookie(res: Response, refreshToken: string) {
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Only send over HTTPS in production
    sameSite: 'strict',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
    path: '/api/auth', // Only send cookie to auth endpoints
  });
}

/**
 * Utility function to clear refresh token cookie
 */
export function clearRefreshTokenCookie(res: Response) {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth',
  });
}