import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { loginSchema, registerStudentSchema, registerBusinessSchema, insertAccountSchema, paginationSchema, securityEventRequestSchema, InsertDiscountCategory, updateDiscountSchema, insertUniversitySchema } from "@tullab/shared/schemas";
import { ZodError } from "zod";
import { AuthService, requireAuth, requireRole, setRefreshTokenCookie, clearRefreshTokenCookie } from "./auth";
import cookieParser from "cookie-parser";
import swaggerUi from "swagger-ui-express";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import multer from "multer";
import csv from "csv-parser";
import { Readable } from "stream";
import QRCode from "qrcode";
import * as argon2 from "argon2";

// Student validation helper functions
interface StudentValidationResult {
  isActive: boolean;
  reason?: 'expired' | 'invalid_status';
  message?: string;
}

function validateStudentStatus(student: any): StudentValidationResult {
  // Check if student status is active
  if (student.status !== 'active') {
    return {
      isActive: false,
      reason: 'invalid_status',
      message: `Student status is '${student.status}' - only active students can use discounts`
    };
  }

  // Check if student is not expired (valid_until >= current date)
  const currentDate = new Date();
  currentDate.setHours(0, 0, 0, 0); // Start of today in UTC
  
  const validUntilDate = new Date(student.valid_until);
  validUntilDate.setHours(0, 0, 0, 0); // Start of valid_until date
  
  if (validUntilDate < currentDate) {
    return {
      isActive: false,
      reason: 'expired',
      message: `Student access expired on ${student.valid_until} - contact your university to renew`
    };
  }

  return {
    isActive: true
  };
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Add cookie parser middleware for refresh tokens
  app.use(cookieParser());

  // Load OpenAPI specification
  const openApiPath = path.join(process.cwd(), 'apps/api/openapi.yaml');
  let swaggerDocument: any;
  
  try {
    const file = fs.readFileSync(openApiPath, 'utf8');
    swaggerDocument = yaml.load(file);
  } catch (error) {
    console.error('Failed to load OpenAPI specification:', error);
    swaggerDocument = {
      openapi: '3.0.3',
      info: {
        title: 'Tullab API',
        version: '1.0.0',
        description: 'Student discount platform API (OpenAPI spec failed to load)'
      },
      paths: {}
    };
  }

  // Swagger UI setup
  const swaggerOptions = {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Tullab API Documentation',
    customfavIcon: '/favicon.ico',
    swaggerOptions: {
      persistAuthorization: true,
      displayRequestDuration: true,
      filter: true,
      showExtensions: true,
      showCommonExtensions: true,
    }
  };

  // Serve OpenAPI documentation at /docs
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, swaggerOptions));

  // Serve raw OpenAPI spec at /openapi.yaml
  app.get('/openapi.yaml', (req, res) => {
    res.setHeader('Content-Type', 'application/x-yaml');
    try {
      const file = fs.readFileSync(openApiPath, 'utf8');
      res.send(file);
    } catch (error) {
      res.status(404).json({ 
        error: 'OpenAPI specification not found',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Serve OpenAPI spec as JSON at /openapi.json
  app.get('/openapi.json', (req, res) => {
    res.json(swaggerDocument);
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '1.0.0'
    });
  });

  // API info endpoint
  app.get('/api/', (req, res) => {
    res.json({
      name: 'Student Discount Platform API',
      version: '1.0.0',
      description: 'Student discount platform for universities and businesses',
      endpoints: {
        health: '/health',
        auth: '/api/auth',
        accounts: '/api/accounts',
      },
      documentation: 'https://docs.studentdiscount.platform',
      timestamp: new Date().toISOString(),
    });
  });

  // Debugging middleware to catch ALL requests to auth endpoints
  app.use('/api/auth/*', (req, res, next) => {
    console.log(`🔍 [DEBUG] ${req.method} ${req.originalUrl} - Content-Type: ${req.headers['content-type']} - User-Agent: ${req.headers['user-agent']?.substring(0, 50)}`);
    next();
  });

  // Auth endpoints - Register new student
  app.post('/api/auth/register/student', async (req, res) => {
    console.log('🔥 [AUTH] POST /api/auth/register/student - Student registration attempt');
    try {
      // Validate request body
      const validatedData = registerStudentSchema.parse(req.body);
      
      // Check if account already exists
      const existingAccount = await storage.getAccountByEmail(validatedData.email);
      if (existingAccount) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'Account with this email already exists',
          timestamp: new Date().toISOString()
        });
      }

      // Create new account (password will be hashed in storage layer)
      const { confirmPassword, ...accountData } = validatedData;
      const accountInput = {
        email: accountData.email,
        password_hash: accountData.password, // Will be hashed in storage
        role: 'student' as const,
        student_id: null, // Will be set after creating student record
        business_id: null,
      };
      
      const newAccount = await storage.createAccount(accountInput);
      
      // Return account data without password
      const { password_hash, ...accountResponse } = newAccount;
      res.status(201).json({
        data: accountResponse,
        message: 'Student account registered successfully',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Student registration error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to register student account',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Auth endpoints - Register new business
  app.post('/api/auth/register/business', async (req, res) => {
    console.log('🔥 [AUTH] POST /api/auth/register/business - Business registration attempt');
    try {
      // Validate request body
      const validatedData = registerBusinessSchema.parse(req.body);
      
      // Check if account already exists
      const existingAccount = await storage.getAccountByEmail(validatedData.email);
      if (existingAccount) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'Account with this email already exists',
          timestamp: new Date().toISOString()
        });
      }

      // Create new account (password will be hashed in storage layer)
      const { confirmPassword, ...accountData } = validatedData;
      const accountInput = {
        email: accountData.email,
        password_hash: accountData.password, // Will be hashed in storage
        role: 'merchant' as const,
        student_id: null,
        business_id: null, // Will be set after creating business record
      };
      
      const newAccount = await storage.createAccount(accountInput);
      
      // Return account data without password
      const { password_hash, ...accountResponse } = newAccount;
      res.status(201).json({
        data: accountResponse,
        message: 'Business account registered successfully',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Business registration error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to register business account',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Auth endpoints - Login with JWT
  app.post('/api/auth/login', async (req, res) => {
    console.log('🔥 [AUTH] POST /api/auth/login - Login attempt');
    try {
      // Validate request body
      const validatedData = loginSchema.parse(req.body);
      console.log('🔍 [AUTH] Email:', validatedData.email);
      console.log('🔍 [AUTH] Password length:', validatedData.password?.length);
      
      // Find account by email
      const account = await storage.getAccountByEmail(validatedData.email);
      console.log('🔍 [AUTH] Account found:', !!account);
      if (!account) {
        console.log('🚨 [AUTH] No account found for email:', validatedData.email);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid email or password',
          timestamp: new Date().toISOString()
        });
      }
      console.log('🔍 [AUTH] Account role:', account.role);
      console.log('🔍 [AUTH] Password hash starts with:', account.password_hash.substring(0, 20));

      // Verify password with Argon2
      console.log('🔒 [AUTH] About to verify password...');
      const isPasswordValid = await storage.verifyPassword(validatedData.password, account.password_hash);
      console.log('🔒 [AUTH] Password valid:', isPasswordValid);
      if (!isPasswordValid) {
        console.log('🚨 [AUTH] Password verification failed');
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid email or password',
          timestamp: new Date().toISOString()
        });
      }
      console.log('✅ [AUTH] Password verification successful!');

      // Generate JWT access token (15 minutes)
      const accessToken = AuthService.generateAccessToken({
        accountId: account.id as unknown as string,
        email: account.email,
        role: account.role,
      });

      // Generate refresh token (30 days)
      const tokenId = AuthService.generateTokenId();
      const refreshToken = AuthService.generateRefreshToken({
        accountId: account.id as unknown as string,
        tokenId,
      });

      // Store refresh token hash in database
      await AuthService.storeRefreshToken(account.id as unknown as string, tokenId);

      // Set refresh token as httpOnly cookie
      setRefreshTokenCookie(res, refreshToken);
      
      // Return account data with access token
      const { password_hash, ...accountResponse } = account;
      res.status(200).json({
        data: {
          account: accountResponse,
          accessToken,
          expiresIn: '15m',
        },
        message: 'Login successful',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Login error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to login',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Auth endpoints - Refresh access token
  app.post('/api/auth/refresh', async (req, res) => {
    console.log('🔄 [AUTH] POST /api/auth/refresh - Token refresh attempt');
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Refresh token required',
          timestamp: new Date().toISOString()
        });
      }

      // Verify refresh token JWT
      const payload = AuthService.verifyRefreshToken(refreshToken);
      if (!payload) {
        clearRefreshTokenCookie(res);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid refresh token',
          timestamp: new Date().toISOString()
        });
      }

      // Check for token reuse - critical security feature
      const tokenReuseDetected = await AuthService.detectTokenReuse(payload.accountId, payload.tokenId);
      if (tokenReuseDetected) {
        clearRefreshTokenCookie(res);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Token reuse detected - all tokens revoked for security',
          timestamp: new Date().toISOString()
        });
      }

      // Verify refresh token exists in database and get token record
      const verification = await AuthService.verifyRefreshTokenInDB(payload.accountId, payload.tokenId);
      if (!verification.isValid) {
        clearRefreshTokenCookie(res);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Refresh token not found or expired',
          timestamp: new Date().toISOString()
        });
      }

      // Get current account info
      const account = await storage.getAccount(payload.accountId);
      if (!account) {
        clearRefreshTokenCookie(res);
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Account not found',
          timestamp: new Date().toISOString()
        });
      }

      // Implement token rotation - delete old token and create new one
      const { tokenId: newTokenId, refreshToken: newRefreshToken } = await AuthService.rotateRefreshToken(
        payload.accountId, 
        payload.tokenId
      );

      // Generate new access token
      const newAccessToken = AuthService.generateAccessToken({
        accountId: account.id as unknown as string,
        email: account.email,
        role: account.role,
      });

      // Set new rotated refresh token as httpOnly cookie
      setRefreshTokenCookie(res, newRefreshToken);

      res.status(200).json({
        data: {
          accessToken: newAccessToken,
          expiresIn: '15m',
        },
        message: 'Token refreshed and rotated successfully',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Token refresh error:', error);
      clearRefreshTokenCookie(res);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to refresh token',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Auth endpoints - Logout
  app.post('/api/auth/logout', async (req, res) => {
    console.log('👋 [AUTH] POST /api/auth/logout - Logout attempt');
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (refreshToken) {
        // Verify refresh token to get account ID
        const payload = AuthService.verifyRefreshToken(refreshToken);
        if (payload) {
          // Revoke all refresh tokens for this account
          await AuthService.revokeRefreshTokens(payload.accountId);
        }
      }

      // Clear refresh token cookie
      clearRefreshTokenCookie(res);

      res.status(200).json({
        message: 'Logout successful',
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Logout error:', error);
      // Still clear cookie and return success for better UX
      clearRefreshTokenCookie(res);
      res.status(200).json({
        message: 'Logout successful',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Auth endpoints - Get current user profile
  app.get('/api/auth/me', requireAuth, async (req, res) => {
    console.log('👤 [AUTH] GET /api/auth/me - Get current user profile');
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required',
          timestamp: new Date().toISOString()
        });
      }

      // Get full account details from storage
      const account = await storage.getAccount(user.accountId);
      
      if (!account) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Account not found',
          timestamp: new Date().toISOString()
        });
      }

      // Return account data without password
      const { password_hash, ...accountResponse } = account;
      
      res.status(200).json({
        success: true,
        data: {
          user: {
            id: accountResponse.id,
            email: accountResponse.email,
            role: accountResponse.role,
            student_id: accountResponse.student_id,
            business_id: accountResponse.business_id
          }
        },
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Get user profile error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get user profile',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Catch any other auth requests that shouldn't be there
  app.all('/api/auth/*', (req, res) => {
    console.log(`⚠️ [DEBUG] Unexpected ${req.method} ${req.originalUrl} - This should not happen!`);
    res.status(404).json({ error: 'Auth endpoint not found', method: req.method, url: req.originalUrl });
  });

  // Database health check endpoint
  app.get('/api/db/health', async (req, res) => {
    console.log('🏥 [HEALTH] GET /api/db/health - Database health check');
    try {
      // Test basic database operations
      const testResults = {
        connection: false,
        accountOperations: false,
        timestamp: new Date().toISOString()
      };

      // Test database connection by trying to get accounts
      try {
        const accounts = await storage.getAllAccounts();
        testResults.connection = true;
        testResults.accountOperations = true;
        
        res.status(200).json({
          status: 'healthy',
          database: 'connected',
          storage: storage.constructor.name,
          tests: testResults,
          accountCount: accounts.length,
          timestamp: new Date().toISOString()
        });
      } catch (dbError) {
        console.error('Database health check failed:', dbError);
        res.status(503).json({
          status: 'unhealthy',
          database: 'disconnected',
          storage: storage.constructor.name,
          tests: testResults,
          error: 'Database operations failed',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Health check error:', error);
      res.status(500).json({
        status: 'error',
        message: 'Health check failed',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Account CRUD endpoints - Protected routes
  app.get('/api/accounts', requireAuth, async (req, res) => {
    console.log('👥 [ACCOUNTS] GET /api/accounts - Get all accounts');
    try {
      const accounts = await storage.getAllAccounts();
      
      // Remove passwords from response
      const accountsResponse = accounts.map(({ password_hash, ...account }) => account);
      
      res.status(200).json({
        data: accountsResponse,
        count: accountsResponse.length,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Get accounts error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve accounts',
        timestamp: new Date().toISOString()
      });
    }
  });

  app.get('/api/accounts/:id', async (req, res) => {
    console.log(`👤 [ACCOUNTS] GET /api/accounts/${req.params.id} - Get account by ID`);
    try {
      const { id } = req.params;
      
      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Account ID is required',
          timestamp: new Date().toISOString()
        });
      }

      const account = await storage.getAccount(id);
      
      if (!account) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Account not found',
          timestamp: new Date().toISOString()
        });
      }

      // Remove password from response
      const { password_hash, ...accountResponse } = account;
      
      res.status(200).json({
        data: accountResponse,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Get account error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve account',
        timestamp: new Date().toISOString()
      });
    }
  });

  app.put('/api/accounts/:id', async (req, res) => {
    console.log(`✏️ [ACCOUNTS] PUT /api/accounts/${req.params.id} - Update account`);
    try {
      const { id } = req.params;
      
      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Account ID is required',
          timestamp: new Date().toISOString()
        });
      }

      // Validate request body (allow partial updates)
      const validatedData = insertAccountSchema.partial().parse(req.body);
      
      const updatedAccount = await storage.updateAccount(id, validatedData);
      
      if (!updatedAccount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Account not found',
          timestamp: new Date().toISOString()
        });
      }

      // Remove password from response
      const { password_hash, ...accountResponse } = updatedAccount;
      
      res.status(200).json({
        data: accountResponse,
        message: 'Account updated successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Update account error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update account',
        timestamp: new Date().toISOString()
      });
    }
  });

  app.delete('/api/accounts/:id', async (req, res) => {
    console.log(`🗑️ [ACCOUNTS] DELETE /api/accounts/${req.params.id} - Delete account`);
    try {
      const { id } = req.params;
      
      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Account ID is required',
          timestamp: new Date().toISOString()
        });
      }

      const deleted = await storage.deleteAccount(id);
      
      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Account not found',
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(200).json({
        message: 'Account deleted successfully',
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Delete account error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete account',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Configure multer for CSV file uploads (memory storage)
  const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
      if (file.mimetype === 'text/csv' || file.originalname.endsWith('.csv')) {
        cb(null, true);
      } else {
        cb(new Error('Only CSV files are allowed'));
      }
    }
  });

  // Multer error handling middleware
  const handleMulterError = (err: any, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'File too large. Maximum size is 5MB.',
          timestamp: new Date().toISOString()
        });
      }
      return res.status(400).json({
        error: 'Bad Request',
        message: err.message,
        timestamp: new Date().toISOString()
      });
    }
    
    if (err && err.message === 'Only CSV files are allowed') {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Only CSV files are allowed',
        timestamp: new Date().toISOString()
      });
    }
    
    next(err);
  };

  // Admin CSV import endpoint for students
  app.post('/api/admin/import-students', 
    requireAuth, 
    requireRole('admin'), 
    upload.single('csv'),
    handleMulterError,
    async (req: Request, res: Response) => {
    console.log(`📥 [IMPORT] POST /api/admin/import-students - Import students from CSV`);
    
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'CSV file is required',
          timestamp: new Date().toISOString()
        });
      }

      const csvBuffer = req.file.buffer;
      let csvString = csvBuffer.toString('utf-8');
      
      // Remove BOM (Byte Order Mark) if present
      if (csvString.charCodeAt(0) === 0xFEFF) {
        csvString = csvString.slice(1);
      }
      
      // Parse CSV data
      const students: any[] = [];
      const stream = Readable.from(csvString);
      
      await new Promise((resolve, reject) => {
        stream
          .pipe(csv())
          .on('data', (row) => {
            students.push(row);
          })
          .on('end', resolve)
          .on('error', reject);
      });

      if (students.length === 0) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'CSV file is empty or has no valid data',
          timestamp: new Date().toISOString()
        });
      }

      // Validate CSV headers with flexible matching
      const requiredHeaders = ['first_name', 'last_name', 'student_id', 'email', 'phone', 'university', 'valid_from', 'valid_until'];
      const csvHeaders = Object.keys(students[0]).map(h => h.trim().toLowerCase());
      
      console.log('CSV Headers received:', csvHeaders);
      console.log('Required headers:', requiredHeaders);
      
      // Create mapping for flexible header matching
      const headerMap: Record<string, string> = {};
      const normalizedRequired = requiredHeaders.map(h => h.toLowerCase());
      
      // Check for exact matches and common variations
      const missingHeaders: string[] = [];
      for (const required of requiredHeaders) {
        const normalized = required.toLowerCase();
        let found = false;
        
        // Check for exact match
        if (csvHeaders.includes(normalized)) {
          const originalHeader = Object.keys(students[0]).find(h => h.trim().toLowerCase() === normalized);
          if (originalHeader) {
            headerMap[required] = originalHeader.trim();
            found = true;
          }
        }
        
        // Check for common variations
        if (!found) {
          const variations = [
            normalized.replace(/_/g, ' '), // underscore to space
            normalized.replace(/_/g, '-'), // underscore to dash
            normalized.replace(/ /g, '_'), // space to underscore
            normalized.replace(/ /g, '-'), // space to dash
            normalized.replace(/-/g, '_'), // dash to underscore
            normalized.replace(/-/g, ' ')  // dash to space
          ];
          
          for (const variation of variations) {
            if (csvHeaders.includes(variation)) {
              const originalHeader = Object.keys(students[0]).find(h => h.trim().toLowerCase() === variation);
              if (originalHeader) {
                headerMap[required] = originalHeader.trim();
                found = true;
                break;
              }
            }
          }
        }
        
        if (!found) {
          missingHeaders.push(required);
        }
      }
      
      if (missingHeaders.length > 0) {
        console.error('Missing CSV headers:', missingHeaders);
        console.error('Available headers:', Object.keys(students[0]));
        
        return res.status(400).json({
          error: 'Bad Request',
          message: `Missing required CSV headers: ${missingHeaders.join(', ')}`,
          details: `Expected headers: ${requiredHeaders.join(', ')}`,
          received: Object.keys(students[0]),
          timestamp: new Date().toISOString()
        });
      }
      
      // Normalize the data using the header mapping
      const normalizedStudents = students.map(row => {
        const normalizedRow: any = {};
        for (const [required, original] of Object.entries(headerMap)) {
          normalizedRow[required] = row[original];
        }
        return normalizedRow;
      });
      
      console.log('CSV import - processed', normalizedStudents.length, 'student records');

      // Process students and get summary
      const importResult = await storage.importStudents(normalizedStudents, (req as any).user);
      
      res.status(200).json({
        message: 'Students imported successfully',
        summary: importResult,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Import students error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to import students',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Configure multer for image uploads (disk storage)
  const imageUpload = multer({
    storage: multer.diskStorage({
      destination: (req, file, cb) => {
        const uploadDir = 'uploads';
        const subDir = file.fieldname === 'business-logo' ? 'logos' : 'discount-images';
        const fullPath = path.join(process.cwd(), uploadDir, subDir);
        
        // Create directory if it doesn't exist
        fs.mkdirSync(fullPath, { recursive: true });
        cb(null, fullPath);
      },
      filename: (req, file, cb) => {
        // Generate unique filename
        const ext = path.extname(file.originalname);
        const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`;
        cb(null, filename);
      }
    }),
    limits: {
      fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
      // Check if file is an image
      if (file.mimetype.startsWith('image/')) {
        // Allow common image formats
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
          cb(null, true);
        } else {
          cb(new Error('Only JPEG, PNG, GIF, and WebP images are allowed'));
        }
      } else {
        cb(new Error('Only image files are allowed'));
      }
    }
  });

  // Image upload error handling middleware
  const handleImageUploadError = (err: any, req: Request, res: Response, next: NextFunction) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Image file too large. Maximum size is 5MB.',
          timestamp: new Date().toISOString()
        });
      }
      return res.status(400).json({
        error: 'Bad Request',
        message: err.message,
        timestamp: new Date().toISOString()
      });
    }
    
    if (err && (err.message.includes('Only image files are allowed') || err.message.includes('Only JPEG, PNG, GIF'))) {
      return res.status(400).json({
        error: 'Bad Request',
        message: err.message,
        timestamp: new Date().toISOString()
      });
    }
    
    next(err);
  };

  // Business logo upload endpoint
  app.post('/api/upload/business-logo',
    requireAuth,
    requireRole('admin'),
    imageUpload.single('business-logo'),
    handleImageUploadError,
    async (req: Request, res: Response) => {
      console.log('🖼️ [UPLOAD] POST /api/upload/business-logo - Upload business logo');
      
      try {
        if (!req.file) {
          return res.status(400).json({
            error: 'Bad Request',
            message: 'Logo image file is required',
            timestamp: new Date().toISOString()
          });
        }

        // Generate URL for the uploaded image
        const imageUrl = `/uploads/logos/${req.file.filename}`;
        
        res.status(200).json({
          message: 'Business logo uploaded successfully',
          data: {
            filename: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype,
            url: imageUrl
          },
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        console.error('Business logo upload error:', error);
        
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to upload business logo',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  // Discount image upload endpoint
  app.post('/api/upload/discount-image',
    requireAuth,
    requireRole('admin'),
    imageUpload.single('discount-image'),
    handleImageUploadError,
    async (req: Request, res: Response) => {
      console.log('🖼️ [UPLOAD] POST /api/upload/discount-image - Upload discount image');
      
      try {
        if (!req.file) {
          return res.status(400).json({
            error: 'Bad Request',
            message: 'Discount image file is required',
            timestamp: new Date().toISOString()
          });
        }

        // Generate URL for the uploaded image
        const imageUrl = `/uploads/discount-images/${req.file.filename}`;
        
        res.status(200).json({
          message: 'Discount image uploaded successfully',
          data: {
            filename: req.file.filename,
            originalName: req.file.originalname,
            size: req.file.size,
            mimetype: req.file.mimetype,
            url: imageUrl
          },
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        console.error('Discount image upload error:', error);
        
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to upload discount image',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  // Serve uploaded images statically
  app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

  // Students Management endpoints
  app.get('/api/students', 
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log('👥 [STUDENTS] GET /api/students - Get all students');
      
      try {
        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 20;
        const search = req.query.search as string;
        const university_id = req.query.university_id as string;
        const status = req.query.status as string;
        
        const students = await storage.getStudents({
          page,
          limit,
          search,
          university_id,
          status
        });
        
        res.status(200).json({
          message: 'Students retrieved successfully',
          data: students.data,
          pagination: students.pagination,
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('Get students error:', error);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to retrieve students',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  // Export students to CSV
  app.get('/api/students/export-csv',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log('📥 [STUDENTS] GET /api/students/export-csv - Export all students to CSV');
      
      try {
        // Get all students without pagination
        const students = await storage.getStudents({
          page: 1,
          limit: 10000, // Large limit to get all students
        });
        
        // If no students, return empty CSV with headers
        if (students.data.length === 0) {
          const headers = ['first_name', 'last_name', 'student_id', 'email', 'phone', 'university', 'valid_from', 'valid_until', 'status', 'created_at'].join(',');
          res.setHeader('Content-Type', 'text/csv');
          res.setHeader('Content-Disposition', `attachment; filename="students-export-${new Date().toISOString().split('T')[0]}.csv"`);
          return res.status(200).send(headers + '\n');
        }

        // Get universities to map IDs to names
        const universitiesResult = await storage.getUniversities({ page: 1, limit: 1000 });
        const universityMap = new Map(universitiesResult.data.map(u => [u.id, u.name]));

        // Create CSV content
        const headers = ['first_name', 'last_name', 'student_id', 'email', 'phone', 'university', 'valid_from', 'valid_until', 'status', 'created_at'] as const;
        
        const csvRows = students.data.map(student => {
          const universityName = universityMap.get(student.university_id) || 'Unknown';
          return [
            student.first_name || '',
            student.last_name || '',
            student.student_id || '',
            student.email || '',
            student.phone || '',
            universityName,
            student.valid_from || '',
            student.valid_until || '',
            student.status || '',
            student.created_at ? new Date(student.created_at).toISOString().split('T')[0] : ''
          ].map(field => `"${String(field).replace(/"/g, '""')}"`).join(',');
        });

        const csvContent = [headers.join(','), ...csvRows].join('\n');

        // Set response headers for CSV download
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="students-export-${new Date().toISOString().split('T')[0]}.csv"`);
        
        res.status(200).send(csvContent);
        
      } catch (error) {
        console.error('Export students CSV error:', error);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to export students data',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  app.get('/api/students/:id',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log(`👤 [STUDENTS] GET /api/students/${req.params.id} - Get student by ID`);
      
      try {
        const student = await storage.getStudentById(req.params.id);
        
        if (!student) {
          return res.status(404).json({
            error: 'Not Found',
            message: 'Student not found',
            timestamp: new Date().toISOString()
          });
        }
        
        res.status(200).json({
          message: 'Student retrieved successfully',
          data: student,
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('Get student error:', error);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to retrieve student',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  app.patch('/api/students/:id',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log(`✏️ [STUDENTS] PATCH /api/students/${req.params.id} - Update student`);
      
      try {
        const student = await storage.updateStudent(req.params.id, req.body);
        
        res.status(200).json({
          message: 'Student updated successfully',
          data: student,
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('Update student error:', error);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to update student',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  app.patch('/api/students/:id/status',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log(`🔄 [STUDENTS] PATCH /api/students/${req.params.id}/status - Update student status`);
      
      try {
        const { status } = req.body;
        const student = await storage.updateStudentStatus(req.params.id, status);
        
        res.status(200).json({
          message: 'Student status updated successfully',
          data: student,
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('Update student status error:', error);
        res.status(500).json({
          error: 'Internal Server Error', 
          message: 'Failed to update student status',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  // Bulk delete students
  app.delete('/api/students/bulk',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
      console.log('🗑️ [STUDENTS] DELETE /api/students/bulk - Bulk delete students');
      
      try {
        const { studentIds } = req.body;
        
        if (!studentIds || !Array.isArray(studentIds) || studentIds.length === 0) {
          return res.status(400).json({
            error: 'Bad Request',
            message: 'Student IDs array is required and cannot be empty',
            timestamp: new Date().toISOString()
          });
        }

        // Delete students using storage method
        const results = await Promise.allSettled(
          studentIds.map((id: string) => storage.deleteStudent(id))
        );

        const successful = results.filter(result => result.status === 'fulfilled').length;
        const failed = results.filter(result => result.status === 'rejected').length;

        res.status(200).json({
          message: `Bulk delete completed: ${successful} deleted, ${failed} failed`,
          summary: {
            deleted: successful,
            failed: failed,
            total: studentIds.length
          },
          timestamp: new Date().toISOString()
        });
        
      } catch (error) {
        console.error('Bulk delete students error:', error);
        res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to bulk delete students',
          timestamp: new Date().toISOString()
        });
      }
    }
  );

  // University Management endpoints
  app.post('/api/universities', 
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log('🏫 [UNIVERSITY] POST /api/universities - Create university');
    
    try {
      // Validate request body using Zod schema
      const validatedData = insertUniversitySchema.parse(req.body);
      
      // Create university using storage method
      const university = await storage.createUniversity(validatedData);

      res.status(201).json({
        message: 'University created successfully',
        data: university,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('University creation error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }

      if (error instanceof Error && error.message.includes('already exists')) {
        return res.status(409).json({
          error: 'Conflict',
          message: error.message,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create university',
        timestamp: new Date().toISOString()
      });
    }
  });

  app.get('/api/universities', 
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log('🏫 [UNIVERSITY] GET /api/universities - List universities');
    
    try {
      // Parse query parameters
      const page = parseInt(req.query.page as string) || 1;
      const limit = Math.min(parseInt(req.query.limit as string) || 20, 100); // Max 100 per page
      const search = req.query.search as string;

      // Get universities using storage method
      const result = await storage.getUniversities({ page, limit, search });

      res.status(200).json({
        message: 'Universities retrieved successfully',
        data: result.data,
        pagination: result.pagination,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('University listing error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to list universities',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Get single university by ID
  app.get('/api/universities/:id', 
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log(`🏫 [UNIVERSITY] GET /api/universities/${req.params.id} - Get university by ID`);
    
    try {
      const university = await storage.getUniversityById(req.params.id);
      
      if (!university) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'University not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'University retrieved successfully',
        data: university,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get university error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get university',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Update university
  app.put('/api/universities/:id',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log(`🏫 [UNIVERSITY] PUT /api/universities/${req.params.id} - Update university`);
    
    try {
      // Validate request body using Zod schema (allow partial updates)
      const validatedData = insertUniversitySchema.partial().parse(req.body);
      
      // Ensure we have something to update
      if (Object.keys(validatedData).length === 0) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'No valid fields provided for update',
          timestamp: new Date().toISOString()
        });
      }

      // Update university using storage method
      const university = await storage.updateUniversity(req.params.id, validatedData);
      
      if (!university) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'University not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'University updated successfully',
        data: university,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Update university error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }

      if (error instanceof Error && error.message.includes('already exists')) {
        return res.status(409).json({
          error: 'Conflict',
          message: error.message,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update university',
        timestamp: new Date().toISOString()
      });
    }
  });

  // PATCH endpoint for university updates (same as PUT for frontend compatibility)
  app.patch('/api/universities/:id',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log(`🏫 [UNIVERSITY] PATCH /api/universities/${req.params.id} - Update university`);
    
    try {
      // Validate request body using Zod schema (allow partial updates)
      const validatedData = insertUniversitySchema.partial().parse(req.body);
      
      // Ensure we have something to update
      if (Object.keys(validatedData).length === 0) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'No valid fields provided for update',
          timestamp: new Date().toISOString()
        });
      }

      // Update university using storage method
      const university = await storage.updateUniversity(req.params.id, validatedData);
      
      if (!university) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'University not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'University updated successfully',
        data: university,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Update university error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }

      if (error instanceof Error && error.message.includes('already exists')) {
        return res.status(409).json({
          error: 'Conflict',
          message: error.message,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update university',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Delete university
  app.delete('/api/universities/:id',
    requireAuth,
    requireRole('admin'),
    async (req: Request, res: Response) => {
    console.log(`🏫 [UNIVERSITY] DELETE /api/universities/${req.params.id} - Delete university`);
    
    try {
      // Check if university exists first
      const university = await storage.getUniversityById(req.params.id);
      if (!university) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'University not found',
          timestamp: new Date().toISOString()
        });
      }

      // Delete university using storage method
      const deleted = await storage.deleteUniversity(req.params.id);
      
      if (!deleted) {
        return res.status(500).json({
          error: 'Internal Server Error',
          message: 'Failed to delete university',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'University deleted successfully',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Delete university error:', error);
      
      if (error instanceof Error && error.message.includes('associated students')) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'Cannot delete university with associated students',
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete university',
        timestamp: new Date().toISOString()
      });
    }
  });

  // QR Code Generation endpoint for students
  app.get('/api/qr/issue', 
    requireAuth, 
    requireRole('student'),
    (req, res, next) => {
      // Import the rate limit here to avoid circular dependency issues
      const { qrGenerationRateLimit } = require('./middleware/rateLimiting');
      qrGenerationRateLimit(req, res, next);
    },
    async (req: Request, res: Response) => {
    console.log(`🔗 [QR] GET /api/qr/issue - Generate QR code for student`);
    
    try {
      const user = (req as any).user;
      
      // Get the student record to verify they exist and are valid
      const account = await storage.getAccount(user.accountId);
      if (!account || !account.student_id) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Student account required',
          timestamp: new Date().toISOString()
        });
      }

      const student = await storage.getStudentById(account.student_id);
      if (!student) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Student record not found',
          timestamp: new Date().toISOString()
        });
      }

      // Check if student is eligible (not expired)
      const now = new Date();
      const validUntil = new Date(student.valid_until);
      if (validUntil < now) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Student verification has expired',
          timestamp: new Date().toISOString()
        });
      }

      // Generate JWT token for QR code
      const qrToken = AuthService.generateQRToken(student.id);
      
      // Store token for replay prevention
      const expiresAt = new Date(Date.now() + 45 * 1000); // 45 seconds - short-lived for security
      await storage.storeQRToken(student.id, qrToken, expiresAt);

      // Generate QR code URL
      const qrUrl = `tollab://verify?token=${qrToken}`;
      
      // Generate QR code as PNG
      const qrCodeImage = await QRCode.toDataURL(qrUrl, {
        type: 'image/png',
        width: 300,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      });

      res.status(200).json({
        message: 'QR code generated successfully',
        data: {
          qr_code: qrCodeImage,
          expires_at: expiresAt.toISOString(),
          url: qrUrl
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('QR generation error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to generate QR code',
        timestamp: new Date().toISOString()
      });
    }
  });

  // QR Code Verification endpoint for merchants  
  app.post('/api/qr/verify', 
    requireAuth, 
    requireRole('merchant'), 
    async (req: Request, res: Response) => {
    console.log(`🔍 [QR] POST /api/qr/verify - Verify QR code token`);
    
    try {
      const { token, discount_id } = req.body;
      
      if (!token) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Token is required',
          timestamp: new Date().toISOString()
        });
      }

      // Verify JWT token
      const payload = AuthService.verifyQRToken(token);
      if (!payload) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid or expired QR token',
          timestamp: new Date().toISOString()
        });
      }

      // Verify student and get details first
      const verificationResult = await storage.verifyQRToken(payload.sub, discount_id);
      
      if (!verificationResult.isValid) {
        return res.status(404).json({
          error: 'Not Found',
          message: verificationResult.error || 'Student verification failed',
          timestamp: new Date().toISOString()
        });
      }

      // Prepare redemption data if discount_id provided and student is eligible
      let redemptionData;
      if (discount_id && verificationResult.student?.eligibility) {
        const user = (req as any).user;
        const account = await storage.getAccount(user.accountId);
        
        if (account?.business_id) {
          redemptionData = {
            student_id: payload.sub,
            discount_id: discount_id,
            business_id: account.business_id,
            verifier_account_id: user.accountId,
            status: 'approved' as const
          };
        }
      }

      // Atomic token consumption
      const consumeResult = await storage.atomicConsumeQRToken(token);

      // Handle consumption errors
      if (!consumeResult.consumed) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'Token state conflict, please try again',
          timestamp: new Date().toISOString()
        });
      }

      // Create redemption if data provided
      let redemption;
      if (redemptionData) {
        try {
          redemption = await storage.createRedemption(redemptionData as any);
        } catch (error) {
          console.error('Error creating redemption:', error);
          // Token was already consumed, so continue with success response
        }
      }

      res.status(200).json({
        message: 'QR code verified successfully',
        data: {
          student: verificationResult.student,
          consumed: consumeResult.consumed,
          consumed_at: consumeResult.consumedAt,
          within_idempotency_window: consumeResult.withinIdempotencyWindow,
          redemption_created: !!redemption,
          redemption: redemption
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('QR verification error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to verify QR code',
        timestamp: new Date().toISOString()
      });
    }
  });

  // QR Code Generation endpoint for admin testing
  app.post('/api/qr/generate-test', 
    requireAuth, 
    requireRole('admin'), 
    async (req: Request, res: Response) => {
    console.log(`🔗 [QR] POST /api/qr/generate-test - Generate QR code for testing`);
    
    try {
      const { student_id } = req.body;
      
      if (!student_id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'student_id is required',
          timestamp: new Date().toISOString()
        });
      }

      // Get the student record to verify they exist and are valid
      const student = await storage.getStudentById(student_id);
      if (!student) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Student record not found',
          timestamp: new Date().toISOString()
        });
      }

      // Validate student status and expiry
      const validationResult = validateStudentStatus(student);
      if (!validationResult.isActive) {
        return res.status(422).json({
          error: 'Unprocessable Entity',
          message: validationResult.message,
          data: {
            reason: validationResult.reason,
            student_status: student.status,
            valid_until: student.valid_until
          },
          timestamp: new Date().toISOString()
        });
      }

      // Generate JWT token for QR code
      const qrToken = AuthService.generateQRToken(student.id);
      
      // Store token for replay prevention
      const expiresAt = new Date(Date.now() + 45 * 1000); // 45 seconds - short-lived for security
      await storage.storeQRToken(student.id, qrToken, expiresAt);

      // Generate QR code URL
      const qrUrl = `tollab://verify?token=${qrToken}`;
      
      // Generate QR code as PNG
      const qrCodeImage = await QRCode.toDataURL(qrUrl, {
        type: 'image/png',
        width: 300,
        margin: 2,
        color: {
          dark: '#000000',
          light: '#FFFFFF'
        }
      });

      res.status(200).json({
        message: 'QR code generated successfully for testing',
        data: {
          qr_code: qrCodeImage,
          expires_at: expiresAt.toISOString(),
          url: qrUrl
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('QR test generation error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to generate test QR code',
        timestamp: new Date().toISOString()
      });
    }
  });

  // QR Code Verification endpoint for admin testing (allows admin role instead of merchant)
  app.post('/api/qr/verify-test', 
    requireAuth, 
    requireRole('admin'), 
    async (req: Request, res: Response) => {
    console.log(`🔍 [QR] POST /api/qr/verify-test - Verify QR code token (admin testing)`);
    
    try {
      const { token, discount_id } = req.body;
      
      if (!token) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Token is required',
          timestamp: new Date().toISOString()
        });
      }

      // Verify JWT token
      const payload = AuthService.verifyQRToken(token);
      if (!payload) {
        return res.status(200).json({
          message: 'QR code verification failed',
          data: {
            valid: false,
            reason: 'invalid_token',
            message: 'Invalid or expired QR token'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Verify student and get details first
      const verificationResult = await storage.verifyQRToken(payload.sub, discount_id);
      
      if (!verificationResult.isValid) {
        return res.status(200).json({
          message: 'QR code verification failed',
          data: {
            valid: false,
            reason: 'not_found',
            message: verificationResult.error || 'Student verification failed'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Validate student status and expiry
      const validationResult = validateStudentStatus(verificationResult.student);
      if (!validationResult.isActive) {
        return res.status(200).json({
          message: 'QR code verification failed',
          data: {
            valid: false,
            reason: validationResult.reason,
            message: validationResult.message,
            student_status: verificationResult.student.status,
            valid_until: verificationResult.student.valid_until
          },
          timestamp: new Date().toISOString()
        });
      }

      // For testing, don't actually consume the token, just verify it
      res.status(200).json({
        message: 'QR code verified successfully (test mode)',
        data: {
          valid: true,
          student: verificationResult.student,
          test_mode: true,
          message: 'QR code is valid and student information verified'
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('QR test verification error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to verify QR code',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Discount Endpoints

  // GET /discounts - Get discounts with filters
  app.get('/api/discounts', async (req: Request, res: Response) => {
    console.log('🛍️ [DISCOUNTS] GET /api/discounts - Get discounts with filters');
    
    try {
      // Parse query parameters
      const {
        category_id,
        business_id,
        city,
        activeOnly,
        q,
        sort = 'recent',
        page = '1',
        limit = '20'
      } = req.query;

      // Validate and convert parameters
      const filters = {
        category_id: category_id as string,
        business_id: business_id as string,
        city: city as string,
        activeOnly: activeOnly === 'true' ? true : activeOnly === 'false' ? false : undefined,
        q: q as string,
        sort: (sort as string) as 'recent' | 'endingSoon' | 'popular',
        page: parseInt(page as string) || 1,
        limit: Math.min(parseInt(limit as string) || 20, 100) // Max 100 per page
      };

      const result = await storage.getDiscounts(filters);

      // Set proper headers for frontend consumption
      res.set('X-Total-Count', result.pagination.total.toString());
      res.set('X-Page-Count', result.pagination.totalPages.toString());

      res.status(200).json({
        message: 'Discounts retrieved successfully',
        data: result.discounts,
        pagination: result.pagination,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get discounts error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get discounts',
        timestamp: new Date().toISOString()
      });
    }
  });

  // GET /discounts/:id - Get single discount by ID
  app.get('/api/discounts/:id', async (req: Request, res: Response) => {
    console.log(`🛍️ [DISCOUNTS] GET /api/discounts/${req.params.id} - Get single discount`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Discount ID is required',
          timestamp: new Date().toISOString()
        });
      }

      const discount = await storage.getDiscountById(id);

      if (!discount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Discount retrieved successfully',
        data: discount,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get discount by ID error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get discount',
        timestamp: new Date().toISOString()
      });
    }
  });

  // GET /categories - Get all discount categories
  app.get('/api/categories', async (req: Request, res: Response) => {
    console.log('📂 [CATEGORIES] GET /api/categories - Get all categories');
    
    try {
      const categories = await storage.getCategories();

      res.status(200).json({
        message: 'Categories retrieved successfully',
        data: categories,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get categories error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get categories',
        timestamp: new Date().toISOString()
      });
    }
  });

  // POST /redemptions - Create redemption (merchant only)
  app.post('/api/redemptions', 
    requireAuth, 
    requireRole('merchant'), 
    async (req: Request, res: Response) => {
    console.log('🎟️ [REDEMPTIONS] POST /api/redemptions - Create redemption');
    
    try {
      const { student_token, student_id, discount_id } = req.body;
      const user = (req as any).user;

      // Validate required fields
      if (!discount_id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'discount_id is required',
          timestamp: new Date().toISOString()
        });
      }

      if (!student_token && !student_id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Either student_token or student_id is required',
          timestamp: new Date().toISOString()
        });
      }

      if (student_token && student_id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Provide either student_token or student_id, not both',
          timestamp: new Date().toISOString()
        });
      }

      // Get merchant account to get business_id
      const account = await storage.getAccount(user.accountId);
      if (!account || !account.business_id) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Merchant account with valid business required',
          timestamp: new Date().toISOString()
        });
      }

      let redemption;

      if (student_token) {
        // Create redemption from student token
        redemption = await storage.createRedemptionFromToken(
          student_token, 
          discount_id, 
          account.business_id, 
          user.accountId
        );
      } else {
        // Create redemption from student ID
        redemption = await storage.createRedemptionFromStudentId(
          student_id, 
          discount_id, 
          account.business_id, 
          user.accountId
        );
      }

      res.status(201).json({
        message: 'Redemption created successfully',
        data: redemption,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Create redemption error:', error);
      
      if (error instanceof Error && error.message.includes('verification failed')) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Invalid student token',
          timestamp: new Date().toISOString()
        });
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create redemption',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Security Events Endpoint

  // POST /security/screencap-attempt - Log security events (screen capture attempts)
  app.post('/api/security/screencap-attempt', async (req: Request, res: Response) => {
    console.log('🔒 [SECURITY] POST /api/security/screencap-attempt - Log security event');
    
    try {
      // Validate request body
      const validatedData = securityEventRequestSchema.parse(req.body);
      
      // Create security event
      const securityEvent = await storage.createSecurityEvent(validatedData as any);
      
      res.status(201).json({
        message: 'Security event logged successfully',
        data: {
          id: securityEvent.id,
          event_type: securityEvent.event_type,
          platform: securityEvent.platform,
          created_at: securityEvent.created_at
        },
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Security event logging error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Invalid request data',
          details: error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
          timestamp: new Date().toISOString()
        });
      }

      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to log security event',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Business Management Endpoints
  
  // GET /api/businesses - Get all businesses
  app.get('/api/businesses', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log('🏢 [BUSINESSES] GET /api/businesses - Get all businesses');
    
    try {
      const { page = '1', limit = '20', search, category, verified } = req.query;
      
      const filters = {
        page: parseInt(page as string),
        limit: parseInt(limit as string),
        search: search as string,
        category: category as string,
        verified: verified === 'true' ? true : verified === 'false' ? false : undefined
      };

      const businesses = await storage.getBusinesses(filters);

      res.status(200).json({
        message: 'Businesses retrieved successfully',
        data: businesses.data,
        pagination: businesses.pagination,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get businesses error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get businesses',
        timestamp: new Date().toISOString()
      });
    }
  });

  // GET /api/businesses/:id - Get single business by ID
  app.get('/api/businesses/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🏢 [BUSINESSES] GET /api/businesses/${req.params.id} - Get single business`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Business ID is required',
          timestamp: new Date().toISOString()
        });
      }

      const business = await storage.getBusinessById(id);

      if (!business) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Business not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Business retrieved successfully',
        data: business,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get business by ID error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get business',
        timestamp: new Date().toISOString()
      });
    }
  });

  // POST /api/businesses - Create new business
  app.post('/api/businesses', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log('🏢 [BUSINESSES] POST /api/businesses - Create new business');
    
    try {
      // Validate request body against business schema
      const { insertBusinessSchema } = await import("@tullab/shared/schemas");
      const validatedData = insertBusinessSchema.parse(req.body);

      // Check if business with this email already exists
      const existingBusiness = await storage.getBusinessByEmail(validatedData.contact_email);
      if (existingBusiness) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'Business with this contact email already exists',
          timestamp: new Date().toISOString()
        });
      }

      const newBusiness = await storage.createBusiness(validatedData);

      res.status(201).json({
        message: 'Business created successfully',
        data: newBusiness,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Create business error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create business',
        timestamp: new Date().toISOString()
      });
    }
  });

  // PUT /api/businesses/:id - Update business
  app.put('/api/businesses/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🏢 [BUSINESSES] PUT /api/businesses/${req.params.id} - Update business`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Business ID is required',
          timestamp: new Date().toISOString()
        });
      }

      // Check if business exists
      const existingBusiness = await storage.getBusinessById(id);
      if (!existingBusiness) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Business not found',
          timestamp: new Date().toISOString()
        });
      }

      const updatedBusiness = await storage.updateBusiness(id, req.body);

      if (!updatedBusiness) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Business not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Business updated successfully',
        data: updatedBusiness,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Update business error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update business',
        timestamp: new Date().toISOString()
      });
    }
  });

  // DELETE /api/businesses/:id - Delete business
  app.delete('/api/businesses/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🏢 [BUSINESSES] DELETE /api/businesses/${req.params.id} - Delete business`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Business ID is required',
          timestamp: new Date().toISOString()
        });
      }

      const deleted = await storage.deleteBusiness(id);

      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Business not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Business deleted successfully',
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Delete business error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete business',
        timestamp: new Date().toISOString()
      });
    }
  });

  // POST /api/discounts - Create new discount
  app.post('/api/discounts', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log('🛍️ [DISCOUNTS] POST /api/discounts - Create new discount');
    
    try {
      // Validate request body against discount schema
      const { insertDiscountSchema } = await import("@tullab/shared/schemas");
      const validatedData = insertDiscountSchema.parse(req.body);

      const newDiscount = await storage.createDiscount(validatedData);

      res.status(201).json({
        message: 'Discount created successfully',
        data: newDiscount,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Create discount error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create discount',
        timestamp: new Date().toISOString()
      });
    }
  });

  // PUT /api/discounts/:id - Update discount
  app.put('/api/discounts/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🛍️ [DISCOUNTS] PUT /api/discounts/${req.params.id} - Update discount`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Discount ID is required',
          timestamp: new Date().toISOString()
        });
      }

      // Check if discount exists
      const existingDiscount = await storage.getDiscountById(id);
      if (!existingDiscount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      // Validate request body for partial updates
      const { updateDiscountSchema } = await import("@tullab/shared/schemas");
      const validatedData = updateDiscountSchema.parse(req.body);

      // Cast to the correct type expected by storage
      const updatedDiscount = await storage.updateDiscount(id, validatedData as any);

      if (!updatedDiscount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Discount updated successfully',
        data: updatedDiscount,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Update discount error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update discount',
        timestamp: new Date().toISOString()
      });
    }
  });

  // PATCH /api/discounts/:id - Partial update discount (matches frontend expectations)
  app.patch('/api/discounts/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🛍️ [DISCOUNTS] PATCH /api/discounts/${req.params.id} - Partial update discount`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Discount ID is required',
          timestamp: new Date().toISOString()
        });
      }

      // Check if discount exists
      const existingDiscount = await storage.getDiscountById(id);
      if (!existingDiscount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      // Validate request body for partial updates
      const validatedData = updateDiscountSchema.parse(req.body);

      // Type-safe conversion for storage layer compatibility
      const updateData: any = { ...validatedData };
      
      // Update the discount
      const updatedDiscount = await storage.updateDiscount(id, updateData);

      if (!updatedDiscount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Discount updated successfully',
        data: updatedDiscount,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Partial update discount error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update discount',
        timestamp: new Date().toISOString()
      });
    }
  });

  // DELETE /api/discounts/:id - Delete discount
  app.delete('/api/discounts/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`🛍️ [DISCOUNTS] DELETE /api/discounts/${req.params.id} - Delete discount`);
    
    try {
      const { id } = req.params;

      if (!id) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'Discount ID is required',
          timestamp: new Date().toISOString()
        });
      }

      // Check if discount exists first
      const existingDiscount = await storage.getDiscountById(id);
      if (!existingDiscount) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      // Skip redemption check for now - database constraints will prevent deletion
      // if there are existing redemptions (foreign key constraint will handle this)


      const deleted = await storage.deleteDiscount(id);

      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Discount not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Discount deleted successfully',
        timestamp: new Date().toISOString()
      });

    } catch (error: any) {
      console.error('Delete discount error:', error);
      
      const errorMessage = error.message || 'Unknown error';
      
      // Handle foreign key constraint violations
      if (errorMessage.startsWith('CONSTRAINT_VIOLATION:')) {
        const message = errorMessage.replace('CONSTRAINT_VIOLATION: ', '');
        return res.status(409).json({
          error: 'Conflict',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      // Handle not found errors  
      if (errorMessage.startsWith('NOT_FOUND:')) {
        const message = errorMessage.replace('NOT_FOUND: ', '');
        return res.status(404).json({
          error: 'Not Found',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      // Handle other database errors
      if (errorMessage.startsWith('DATABASE_ERROR:')) {
        const message = errorMessage.replace('DATABASE_ERROR: ', '');
        return res.status(500).json({
          error: 'Database Error',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      // Handle generic errors
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete discount',
        details: errorMessage,
        timestamp: new Date().toISOString()
      });
    }
  });

  // GET /api/discount-categories - Get all discount categories
  app.get('/api/discount-categories', requireAuth, async (req: Request, res: Response) => {
    console.log('📂 [CATEGORIES] GET /api/discount-categories - Get all categories');
    
    try {
      const { search } = req.query;
      const searchTerm = search ? String(search).trim() : undefined;
      
      const categories = await storage.getCategories(searchTerm);

      res.status(200).json({
        message: 'Categories retrieved successfully',
        data: categories,
        total: categories.length,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Get categories error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to retrieve categories',
        timestamp: new Date().toISOString()
      });
    }
  });

  // POST /api/discount-categories - Create new discount category
  app.post('/api/discount-categories', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log('📂 [CATEGORIES] POST /api/discount-categories - Create new category');
    
    try {
      // Simple validation
      const { name } = req.body;
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Category name is required',
          timestamp: new Date().toISOString()
        });
      }

      // Generate slug from name
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
      
      const categoryData = {
        name: name.trim(),
        slug: slug
      };

      const newCategory = await storage.createDiscountCategory(categoryData);

      res.status(201).json({
        message: 'Category created successfully',
        data: newCategory,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Create category error:', error);
      
      if (error instanceof ZodError) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Invalid input data',
          details: error.errors,
          timestamp: new Date().toISOString()
        });
      }
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create category',
        timestamp: new Date().toISOString()
      });
    }
  });

  // PATCH /api/discount-categories/:id - Update discount category
  app.patch('/api/discount-categories/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`📂 [CATEGORIES] PATCH /api/discount-categories/${req.params.id} - Update category`);
    
    try {
      const { id } = req.params;
      const { name, slug } = req.body;

      // Simple validation
      if (name && (typeof name !== 'string' || name.trim().length === 0)) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Category name must be a non-empty string',
          timestamp: new Date().toISOString()
        });
      }

      if (slug && (typeof slug !== 'string' || slug.trim().length === 0)) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Category slug must be a non-empty string',
          timestamp: new Date().toISOString()
        });
      }

      const updateData: Partial<InsertDiscountCategory> = {};
      if (name) updateData.name = name.trim();
      if (slug) updateData.slug = slug.trim();

      const updatedCategory = await storage.updateDiscountCategory(id, updateData);

      if (!updatedCategory) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Category not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Category updated successfully',
        data: updatedCategory,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Update category error:', error);
      
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to update category',
        timestamp: new Date().toISOString()
      });
    }
  });

  // DELETE /api/discount-categories/:id - Delete discount category
  app.delete('/api/discount-categories/:id', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log(`📂 [CATEGORIES] DELETE /api/discount-categories/${req.params.id} - Delete category`);
    
    try {
      const { id } = req.params;

      const deleted = await storage.deleteDiscountCategory(id);

      if (!deleted) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Category not found',
          timestamp: new Date().toISOString()
        });
      }

      res.status(200).json({
        message: 'Category deleted successfully',
        timestamp: new Date().toISOString()
      });

    } catch (error: any) {
      console.error('Delete category error:', error);
      
      // Check for our structured error messages from storage layer
      if (error.message?.startsWith('CONSTRAINT_VIOLATION:')) {
        const message = error.message.replace('CONSTRAINT_VIOLATION: ', '');
        return res.status(409).json({
          error: 'Conflict',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      if (error.message?.startsWith('NOT_FOUND:')) {
        const message = error.message.replace('NOT_FOUND: ', '');
        return res.status(404).json({
          error: 'Not Found',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      if (error.message?.startsWith('DATABASE_ERROR:')) {
        const message = error.message.replace('DATABASE_ERROR: ', '');
        return res.status(500).json({
          error: 'Internal Server Error',
          message: message,
          timestamp: new Date().toISOString()
        });
      }
      
      // Fallback for any other errors
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to delete category',
        timestamp: new Date().toISOString()
      });
    }
  });

  // Dashboard Stats Endpoint
  
  // GET /api/dashboard/stats - Get dashboard statistics (admin only)
  app.get('/api/dashboard/stats', requireAuth, requireRole('admin'), async (req: Request, res: Response) => {
    console.log('📊 [DASHBOARD] GET /api/dashboard/stats - Get dashboard statistics');
    
    try {
      // Import db here to access database directly
      const { db } = await import('./db');
      const { students, discounts, redemptions } = await import('@tullab/shared/schemas');
      const { count, and, gt, gte, lte, eq } = await import('drizzle-orm');

      // Get current date and month boundaries
      const now = new Date();
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
      const endOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0);
      const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);

      // Count active students (not expired)  
      if (!db) throw new Error("Database not available");
      const nowDateString = now.toISOString().split('T')[0]; // Convert to YYYY-MM-DD format
      
      const activeStudentsResult = await db
        .select({ count: count() })
        .from(students)
        .where(and(
          gt(students.valid_until, nowDateString),
          eq(students.status, 'active')
        ));
      const activeStudents = activeStudentsResult[0]?.count || 0;

      // Count students expiring this month
      const startOfMonthString = startOfMonth.toISOString().split('T')[0];
      const endOfMonthString = endOfMonth.toISOString().split('T')[0];
      
      const expiringThisMonthResult = await db
        .select({ count: count() })
        .from(students)
        .where(and(
          gte(students.valid_until, startOfMonthString),
          lte(students.valid_until, endOfMonthString),
          eq(students.status, 'active')
        ));
      const expiringThisMonth = expiringThisMonthResult[0]?.count || 0;

      // Count active discounts
      const activeDiscountsResult = await db
        .select({ count: count() })
        .from(discounts)
        .where(and(
          eq(discounts.is_active, true),
          lte(discounts.start_date, nowDateString),
          gte(discounts.end_date, nowDateString)
        ));
      const activeDiscounts = activeDiscountsResult[0]?.count || 0;

      // Count redemptions for today
      const redemptionsTodayResult = await db
        .select({ count: count() })
        .from(redemptions)
        .where(and(
          gte(redemptions.redeemed_at, startOfDay),
          lte(redemptions.redeemed_at, endOfDay)
        ));
      const redemptionsToday = redemptionsTodayResult[0]?.count || 0;

      // Count universities
      const { universities } = await import('@tullab/shared/schemas');
      const universitiesResult = await db
        .select({ count: count() })
        .from(universities);
      const totalUniversities = universitiesResult[0]?.count || 0;

      const stats = {
        activeStudents,
        expiringThisMonth,
        activeDiscounts,
        redemptionsToday,
        totalUniversities
      };

      res.json({
        message: 'Dashboard statistics retrieved successfully',
        data: stats,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Dashboard stats error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to get dashboard statistics',
        timestamp: new Date().toISOString()
      });
    }
  });

  const httpServer = createServer(app);

  return httpServer;
}