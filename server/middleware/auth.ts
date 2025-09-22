import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../auth';
import { logger } from './logging';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        role: 'admin' | 'university' | 'student' | 'merchant';
        email: string;
        university_id?: string;
      };
    }
  }
}

/**
 * Extract JWT token from Authorization header
 */
function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.substring(7);
}

/**
 * Middleware to authenticate JWT tokens
 */
export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const token = extractToken(req);
  
  if (!token) {
    logger.warn({ 
      path: req.path, 
      method: req.method,
      ip: req.ip 
    }, 'Authentication failed: No token provided');
    
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'MISSING_TOKEN'
    });
  }

  try {
    const payload = AuthService.verifyAccessToken(token);
    if (!payload) {
      logger.warn({ 
        path: req.path, 
        method: req.method,
        ip: req.ip 
      }, 'Authentication failed: Invalid token');
      
      return res.status(401).json({ 
        error: 'Invalid or expired token',
        code: 'INVALID_TOKEN'
      });
    }

    req.user = {
      id: payload.accountId,
      role: payload.role,
      email: payload.email,
      university_id: payload.university_id
    };

    logger.debug({
      userId: req.user.id,
      role: req.user.role,
      path: req.path
    }, 'User authenticated');

    next();
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : 'Unknown error',
      path: req.path,
      ip: req.ip
    }, 'Authentication error');
    
    return res.status(401).json({ 
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
}

/**
 * Middleware to require specific roles
 */
export function requireRole(allowedRoles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'MISSING_AUTH'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      logger.warn({
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles: allowedRoles,
        path: req.path
      }, 'Authorization failed: Insufficient role');
      
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_ROLE',
        required: allowedRoles
      });
    }

    next();
  };
}

/**
 * Middleware for admin-only endpoints
 */
export const requireAdmin = requireRole(['admin']);

/**
 * Middleware for admin or university staff
 */
export const requireStaff = requireRole(['admin', 'university']);

/**
 * Middleware for students only
 */
export const requireStudent = requireRole(['student']);

/**
 * Middleware for merchants only
 */
export const requireMerchant = requireRole(['merchant']);

/**
 * Middleware to check university access
 * Ensures university staff can only access their own university's data
 */
export function requireUniversityAccess(req: Request, res: Response, next: NextFunction) {
  if (!req.user) {
    return res.status(401).json({ 
      error: 'Authentication required',
      code: 'MISSING_AUTH'
    });
  }

  // Admins have access to all universities
  if (req.user.role === 'admin') {
    return next();
  }

  // University staff can only access their own university
  if (req.user.role === 'university') {
    const universityId = req.params.universityId || req.body.university_id || req.query.university_id;
    
    if (universityId && universityId !== req.user.university_id) {
      logger.warn({
        userId: req.user.id,
        userUniversityId: req.user.university_id,
        requestedUniversityId: universityId,
        path: req.path
      }, 'Authorization failed: University access violation');
      
      return res.status(403).json({ 
        error: 'Access denied: Cannot access other university data',
        code: 'UNIVERSITY_ACCESS_DENIED'
      });
    }
  }

  next();
}

/**
 * Optional authentication - sets user if token is valid but doesn't require it
 */
export function optionalAuth(req: Request, res: Response, next: NextFunction) {
  const token = extractToken(req);
  
  if (!token) {
    return next();
  }

  try {
    const payload = AuthService.verifyAccessToken(token);
    if (payload) {
      req.user = {
        id: payload.accountId,
        role: payload.role,
        email: payload.email,
        university_id: payload.university_id
      };
    }
  } catch (error) {
    // Ignore token errors for optional auth
    logger.debug({ error: error instanceof Error ? error.message : 'Unknown error' }, 'Optional auth failed');
  }

  next();
}