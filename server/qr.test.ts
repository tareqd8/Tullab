import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { registerRoutes } from './routes';
import { storage } from './storage';
import { AuthService } from './auth';
import { db } from './db';
import { qr_tokens, accounts } from '../packages/shared/src/schemas';
import { eq } from 'drizzle-orm';
import crypto from 'crypto';

let app: express.Express;
let server: any;
let testStudentAccount: any;
let testMerchantAccount: any;

// Mock student ID for testing (since we can't create full student records easily)
const mockStudentId = 'test-student-id';
const mockBusinessId = 'test-business-id';

describe('QR Token System Tests', () => {
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
      await db.delete(qr_tokens);
      await db.delete(accounts).where(eq(accounts.email, 'student@test.com'));
      await db.delete(accounts).where(eq(accounts.email, 'merchant@test.com'));
    }
    
    // Create test accounts (without foreign key references for testing)
    testStudentAccount = await storage.createAccount({
      student_id: null, // No FK constraint
      business_id: null,
      role: 'student',
      email: 'student@test.com',
      password_hash: 'password123'
    });

    testMerchantAccount = await storage.createAccount({
      student_id: null,
      business_id: null, // No FK constraint
      role: 'merchant',
      email: 'merchant@test.com',
      password_hash: 'password123'
    });
  });

  describe('QR Token Generation', () => {
    it('should generate a valid JWT token', () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      
      expect(qrToken).toBeDefined();
      expect(typeof qrToken).toBe('string');
      
      // Verify token can be decoded
      const payload = AuthService.verifyQRToken(qrToken);
      expect(payload).toBeDefined();
      expect(payload).not.toBeNull();
      if (payload) {
        expect(payload).toMatchObject({
          sub: mockStudentId,
          type: 'qr_access'
        });
      }
    });

    it('should generate unique tokens for each call', () => {
      const token1 = AuthService.generateQRToken(mockStudentId);
      const token2 = AuthService.generateQRToken(mockStudentId);
      
      expect(token1).not.toBe(token2);
    });

    it('should create tokens with proper expiration', () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      const payload = AuthService.verifyQRToken(qrToken);
      
      expect(payload).not.toBeNull();
      if (payload) {
        expect(payload.exp).toBeDefined();
        expect(payload.iat).toBeDefined();
        
        if (payload.exp && payload.iat) {
          // Token should expire in approximately 2 minutes (120 seconds)
          const tokenLifetime = payload.exp - payload.iat;
          expect(tokenLifetime).toBe(120);
        }
      }
    });
  });

  describe('Token Hashing Function', () => {
    it('should hash tokens consistently', () => {
      const token = 'test-token';
      const hash1 = crypto.createHash('sha256').update(token).digest('hex');
      const hash2 = crypto.createHash('sha256').update(token).digest('hex');
      
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 produces 64-character hex string
    });

    it('should produce different hashes for different tokens', () => {
      const token1 = 'test-token-1';
      const token2 = 'test-token-2';
      const hash1 = crypto.createHash('sha256').update(token1).digest('hex');
      const hash2 = crypto.createHash('sha256').update(token2).digest('hex');
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Storage Operations', () => {
    it('should store QR token in database', async () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);
      
      await storage.storeQRToken(mockStudentId, qrToken, expiresAt);
      
      if (db) {
        const storedTokens = await db
          .select()
          .from(qr_tokens)
          .where(eq(qr_tokens.student_id, mockStudentId));
        
        expect(storedTokens).toHaveLength(1);
        expect(storedTokens[0].active).toBe(true);
        expect(storedTokens[0].consumed_at).toBeNull();
      }
    });

    it('should handle atomic token consumption correctly', async () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);
      
      await storage.storeQRToken(mockStudentId, qrToken, expiresAt);
      
      // First consumption should succeed
      const result1 = await storage.atomicConsumeQRToken(qrToken);
      expect(result1.consumed).toBe(true);
      expect(result1.consumedAt).toBeInstanceOf(Date);
      
      // Second consumption should show as already consumed
      const result2 = await storage.atomicConsumeQRToken(qrToken);
      expect(result2.consumed).toBe(true);
      expect(result2.withinIdempotencyWindow).toBe(true);
    });

    it('should handle non-existent token correctly', async () => {
      const nonExistentToken = AuthService.generateQRToken(mockStudentId);
      
      const result = await storage.atomicConsumeQRToken(nonExistentToken);
      expect(result.consumed).toBe(false);
      // Note: atomicConsumeQRToken doesn't return error property, 
      // so we just check the consumed status
    });
  });

  describe('GET /api/qr/issue - Basic Functionality', () => {
    it('should return QR code for authenticated student', async () => {
      const token = AuthService.generateAccessToken(testStudentAccount);
      
      const response = await request(app)
        .get('/api/qr/issue')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(response.headers['content-type']).toBe('image/png');
      expect(response.body).toBeInstanceOf(Buffer);
    });

    it('should reject non-student requests', async () => {
      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      const response = await request(app)
        .get('/api/qr/issue')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);

      expect(response.body.error).toBe('Forbidden');
    });

    it('should reject unauthenticated requests', async () => {
      const response = await request(app)
        .get('/api/qr/issue')
        .expect(401);

      expect(response.body.error).toBe('Unauthorized');
    });
  });

  describe('POST /api/qr/verify - Basic Functionality', () => {
    let validQRToken: string;
    
    beforeEach(async () => {
      validQRToken = AuthService.generateQRToken(mockStudentId);
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);
      await storage.storeQRToken(mockStudentId, validQRToken, expiresAt);
    });

    it('should reject non-merchant requests', async () => {
      const token = AuthService.generateAccessToken(testStudentAccount);
      
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: validQRToken })
        .expect(403);

      expect(response.body.error).toBe('Forbidden');
    });

    it('should reject unauthenticated requests', async () => {
      const response = await request(app)
        .post('/api/qr/verify')
        .send({ token: validQRToken })
        .expect(401);

      expect(response.body.error).toBe('Unauthorized');
    });

    it('should reject invalid token format', async () => {
      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: 'invalid-token' })
        .expect(401);

      expect(response.body.error).toBe('Unauthorized');
      expect(response.body.message).toContain('Invalid token');
    });

    it('should reject missing token', async () => {
      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({})
        .expect(400);

      expect(response.body.error).toBe('Bad Request');
    });

    it('should handle expired tokens correctly', async () => {
      // Create an expired token
      const expiredToken = AuthService.generateQRToken(mockStudentId);
      const pastDate = new Date(Date.now() - 5 * 60 * 1000); // 5 minutes ago
      await storage.storeQRToken(mockStudentId, expiredToken, pastDate);

      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: expiredToken })
        .expect(410);

      expect(response.body.error).toBe('Gone');
      expect(response.body.message).toBe('QR token has expired');
    });

    it('should handle token not found in database', async () => {
      const validJWT = AuthService.generateQRToken(mockStudentId);
      // Don't store this token in database
      
      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: validJWT })
        .expect(404);

      expect(response.body.error).toBe('Not Found');
      expect(response.body.message).toBe('QR token not found');
    });
  });

  describe('Security Tests', () => {
    it('should prevent token reuse outside idempotency window', async () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);
      await storage.storeQRToken(mockStudentId, qrToken, expiresAt);

      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      // First verification
      await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: qrToken })
        .expect(200);

      // Simulate time passing beyond idempotency window
      if (db) {
        const tokenHash = crypto.createHash('sha256').update(qrToken).digest('hex');
        const oldTime = new Date(Date.now() - 15 * 1000); // 15 seconds ago
        await db
          .update(qr_tokens)
          .set({ consumed_at: oldTime })
          .where(eq(qr_tokens.token_hash, tokenHash));
      }

      // Second verification outside window - should still verify but not create new redemptions
      const response = await request(app)
        .post('/api/qr/verify')
        .set('Authorization', `Bearer ${token}`)
        .send({ token: qrToken })
        .expect(200);

      expect(response.body.data.consumed).toBe(true);
      expect(response.body.data.within_idempotency_window).toBe(false);
    });

    it('should handle concurrent verification attempts', async () => {
      const qrToken = AuthService.generateQRToken(mockStudentId);
      const expiresAt = new Date(Date.now() + 2 * 60 * 1000);
      await storage.storeQRToken(mockStudentId, qrToken, expiresAt);

      const token = AuthService.generateAccessToken(testMerchantAccount);
      
      // Make multiple concurrent requests
      const promises = Array(3).fill(null).map(() => 
        request(app)
          .post('/api/qr/verify')
          .set('Authorization', `Bearer ${token}`)
          .send({ token: qrToken })
      );

      const responses = await Promise.all(promises);
      
      // All should succeed with 200 status
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });

      // Verify token is properly consumed
      if (db) {
        const tokenHash = crypto.createHash('sha256').update(qrToken).digest('hex');
        const storedTokens = await db
          .select()
          .from(qr_tokens)
          .where(eq(qr_tokens.token_hash, tokenHash));
        
        expect(storedTokens).toHaveLength(1);
        expect(storedTokens[0].active).toBe(false);
        expect(storedTokens[0].consumed_at).not.toBeNull();
      }
    });
  });
});