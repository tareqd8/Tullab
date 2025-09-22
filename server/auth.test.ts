import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import { createServer } from 'http';
import express from 'express';
import { registerRoutes } from './routes';
import { storage } from './storage';
import { AuthService } from './auth';
import { db } from './db';
import { refresh_tokens, accounts } from '@tullab/shared/schemas';
import { eq } from 'drizzle-orm';

let app: express.Express;
let server: any;
let testAccount: any;

describe('Authentication System Tests', () => {
  beforeAll(async () => {
    // Set up test app
    app = express();
    app.use(express.json());
    server = await registerRoutes(app);
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  beforeEach(async () => {
    // Clean up test data
    if (db) {
      await db.delete(refresh_tokens);
      await db.delete(accounts).where(eq(accounts.email, 'test@example.com'));
    }
    
    // Create test account
    testAccount = await storage.createAccount({
      email: 'test@example.com',
      password_hash: 'password123',
      role: 'student',
      student_id: null,
      business_id: null,
    });
  });

  describe('POST /api/auth/login', () => {
    it('should login with valid credentials and return JWT + refresh token cookie', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        })
        .expect(200);

      expect(response.body).toMatchObject({
        data: {
          account: {
            id: testAccount.id,
            email: 'test@example.com',
            role: 'student',
          },
          accessToken: expect.any(String),
          expiresIn: '15m',
        },
        message: 'Login successful',
        timestamp: expect.any(String),
      });

      // Verify password_hash is not in response
      expect(response.body.data.account.password_hash).toBeUndefined();

      // Verify JWT access token can be decoded
      const payload = AuthService.verifyAccessToken(response.body.data.accessToken);
      expect(payload).toMatchObject({
        accountId: testAccount.id,
        email: 'test@example.com',
        role: 'student',
      });

      // Verify refresh token cookie is set
      const cookies = response.headers['set-cookie'] as string[];
      const refreshTokenCookie = cookies?.find(cookie => cookie.startsWith('refreshToken='));
      expect(refreshTokenCookie).toBeDefined();
      expect(refreshTokenCookie).toContain('HttpOnly');
      expect(refreshTokenCookie).toContain('SameSite=Strict');
      expect(refreshTokenCookie).toContain('Path=/api/auth');
    });

    it('should reject invalid email', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'password123',
        })
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Unauthorized',
        message: 'Invalid email or password',
        timestamp: expect.any(String),
      });
    });

    it('should reject invalid password', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'wrongpassword',
        })
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Unauthorized',
        message: 'Invalid email or password',
        timestamp: expect.any(String),
      });
    });

    it('should validate request body format', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'invalid-email',
          password: '',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        error: 'Validation Error',
        message: 'Invalid input data',
        details: expect.any(Array),
        timestamp: expect.any(String),
      });
    });
  });

  describe('POST /api/auth/refresh', () => {
    let refreshTokenCookie: string;
    let accessToken: string;

    beforeEach(async () => {
      // Login to get refresh token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      accessToken = loginResponse.body.data.accessToken;
      const cookies = loginResponse.headers['set-cookie'] as string[];
      refreshTokenCookie = cookies?.find(cookie => cookie.startsWith('refreshToken='))?.split(';')[0] || '';
    });

    it('should refresh access token with valid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', refreshTokenCookie)
        .expect(200);

      expect(response.body).toMatchObject({
        data: {
          accessToken: expect.any(String),
          expiresIn: '15m',
        },
        message: 'Token refreshed and rotated successfully',
        timestamp: expect.any(String),
      });

      // Verify new access token is different from old one
      expect(response.body.data.accessToken).not.toBe(accessToken);

      // Verify new access token can be decoded
      const payload = AuthService.verifyAccessToken(response.body.data.accessToken);
      expect(payload).toMatchObject({
        accountId: testAccount.id,
        email: 'test@example.com',
        role: 'student',
      });

      // Verify new refresh token cookie is set (token rotation)
      const cookies = response.headers['set-cookie'] as string[];
      const newRefreshTokenCookie = cookies?.find(cookie => cookie.startsWith('refreshToken='));
      expect(newRefreshTokenCookie).toBeDefined();
    });

    it('should reject request without refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Unauthorized',
        message: 'Refresh token required',
        timestamp: expect.any(String),
      });
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', 'refreshToken=invalid-token')
        .expect(401);

      expect(response.body).toMatchObject({
        error: 'Unauthorized',
        message: 'Invalid refresh token',
        timestamp: expect.any(String),
      });

      // Verify refresh token cookie is cleared
      const cookies = response.headers['set-cookie'] as string[];
      const clearedCookie = cookies?.find(cookie => cookie.includes('refreshToken=;'));
      expect(clearedCookie).toBeDefined();
    });

    it('should reject already used refresh token (token reuse detection)', async () => {
      // First refresh should work
      const firstRefresh = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', refreshTokenCookie)
        .expect(200);

      // Second refresh with old token should fail and revoke all tokens
      const secondRefresh = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', refreshTokenCookie)
        .expect(401);

      expect(secondRefresh.body).toMatchObject({
        error: 'Unauthorized',
        message: 'Token reuse detected - all tokens revoked for security',
        timestamp: expect.any(String),
      });

      // Verify all refresh tokens for account are revoked
      if (db) {
        const remainingTokens = await db
          .select()
          .from(refresh_tokens)
          .where(eq(refresh_tokens.account_id, testAccount.id));
        expect(remainingTokens).toHaveLength(0);
      }
    });
  });

  describe('POST /api/auth/logout', () => {
    let refreshTokenCookie: string;

    beforeEach(async () => {
      // Login to get refresh token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const cookies = loginResponse.headers['set-cookie'] as string[];
      refreshTokenCookie = cookies?.find(cookie => cookie.startsWith('refreshToken='))?.split(';')[0] || '';
    });

    it('should logout and revoke refresh tokens', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Cookie', refreshTokenCookie)
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'Logout successful',
        timestamp: expect.any(String),
      });

      // Verify refresh token cookie is cleared
      const cookies = response.headers['set-cookie'] as string[];
      const clearedCookie = cookies?.find(cookie => cookie.includes('refreshToken=;'));
      expect(clearedCookie).toBeDefined();

      // Verify refresh tokens are revoked in database
      if (db) {
        const remainingTokens = await db
          .select()
          .from(refresh_tokens)
          .where(eq(refresh_tokens.account_id, testAccount.id));
        expect(remainingTokens).toHaveLength(0);
      }
    });

    it('should succeed even without refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'Logout successful',
        timestamp: expect.any(String),
      });
    });

    it('should succeed even with invalid refresh token', async () => {
      const response = await request(app)
        .post('/api/auth/logout')
        .set('Cookie', 'refreshToken=invalid-token')
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'Logout successful',
        timestamp: expect.any(String),
      });
    });
  });

  describe('AuthService', () => {
    describe('Password Hashing', () => {
      it('should hash password with Argon2', async () => {
        const password = 'testpassword123';
        const hash = await AuthService.hashPassword(password);

        expect(hash).toBeDefined();
        expect(hash).not.toBe(password);
        expect(hash.startsWith('$argon2id$')).toBe(true);
      });

      it('should verify password against Argon2 hash', async () => {
        const password = 'testpassword123';
        const hash = await AuthService.hashPassword(password);

        const isValid = await AuthService.verifyPassword(password, hash);
        expect(isValid).toBe(true);

        const isInvalid = await AuthService.verifyPassword('wrongpassword', hash);
        expect(isInvalid).toBe(false);
      });
    });

    describe('JWT Tokens', () => {
      it('should generate and verify access tokens', () => {
        const payload = {
          accountId: 'test-account-id',
          email: 'test@example.com',
          role: 'student' as const,
        };

        const token = AuthService.generateAccessToken(payload);
        expect(token).toBeDefined();

        const decoded = AuthService.verifyAccessToken(token);
        expect(decoded).toMatchObject(payload);
      });

      it('should generate and verify refresh tokens', () => {
        const payload = {
          accountId: 'test-account-id',
          tokenId: 'test-token-id',
        };

        const token = AuthService.generateRefreshToken(payload);
        expect(token).toBeDefined();

        const decoded = AuthService.verifyRefreshToken(token);
        expect(decoded).toMatchObject(payload);
      });

      it('should reject invalid tokens', () => {
        const invalidToken = 'invalid.jwt.token';
        
        const accessPayload = AuthService.verifyAccessToken(invalidToken);
        expect(accessPayload).toBeNull();

        const refreshPayload = AuthService.verifyRefreshToken(invalidToken);
        expect(refreshPayload).toBeNull();
      });
    });

    describe('Token ID Generation', () => {
      it('should generate cryptographically secure token IDs', () => {
        const tokenId1 = AuthService.generateTokenId();
        const tokenId2 = AuthService.generateTokenId();

        expect(tokenId1).toBeDefined();
        expect(tokenId2).toBeDefined();
        expect(tokenId1).not.toBe(tokenId2);
        expect(tokenId1.length).toBe(64); // 32 bytes as hex = 64 chars
        expect(/^[a-f0-9]+$/.test(tokenId1)).toBe(true);
      });
    });
  });

  describe('Middleware Tests', () => {
    let accessToken: string;

    beforeEach(async () => {
      // Login to get access token
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      accessToken = loginResponse.body.data.accessToken;
    });

    describe('requireAuth middleware', () => {
      it('should allow access with valid token', async () => {
        // Test with protected accounts endpoint
        const response = await request(app)
          .get('/api/accounts')
          .set('Authorization', `Bearer ${accessToken}`)
          .expect(200);

        expect(response.body.data).toBeDefined();
      });

      it('should reject request without token', async () => {
        const response = await request(app)
          .get('/api/accounts')
          .expect(401);

        expect(response.body).toMatchObject({
          error: 'Unauthorized',
          message: 'Access token required',
          timestamp: expect.any(String),
        });
      });

      it('should reject request with invalid token', async () => {
        const response = await request(app)
          .get('/api/accounts')
          .set('Authorization', 'Bearer invalid-token')
          .expect(401);

        expect(response.body).toMatchObject({
          error: 'Unauthorized',
          message: 'Invalid or expired access token',
          timestamp: expect.any(String),
        });
      });

      it('should reject request with malformed authorization header', async () => {
        const response = await request(app)
          .get('/api/accounts')
          .set('Authorization', 'InvalidFormat token')
          .expect(401);

        expect(response.body).toMatchObject({
          error: 'Unauthorized',
          message: 'Access token required',
          timestamp: expect.any(String),
        });
      });
    });
  });

  describe('Security Tests', () => {
    it('should not expose password hashes in any response', async () => {
      const loginResponse = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      expect(loginResponse.body.data.account.password_hash).toBeUndefined();

      const accountsResponse = await request(app)
        .get('/api/accounts')
        .set('Authorization', `Bearer ${loginResponse.body.data.accessToken}`);

      accountsResponse.body.data.forEach((account: any) => {
        expect(account.password_hash).toBeUndefined();
      });
    });

    it('should set secure cookie attributes for refresh tokens', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'test@example.com',
          password: 'password123',
        });

      const cookies = response.headers['set-cookie'] as string[];
      const refreshTokenCookie = cookies?.find(cookie => cookie.startsWith('refreshToken='));

      expect(refreshTokenCookie).toBeDefined();
      expect(refreshTokenCookie).toContain('HttpOnly');
      expect(refreshTokenCookie).toContain('SameSite=Strict');
      expect(refreshTokenCookie).toContain('Path=/api/auth');
      
      // In development, secure flag should not be set
      if (process.env.NODE_ENV === 'production') {
        expect(refreshTokenCookie).toContain('Secure');
      }
    });
  });
});