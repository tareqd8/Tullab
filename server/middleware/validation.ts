import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { logger } from './logging';

/**
 * Student eligibility validation
 */
export async function validateStudentEligibility(req: Request, res: Response, next: NextFunction) {
  if (!req.user || req.user.role !== 'student') {
    return res.status(403).json({
      error: 'Only students can perform this action',
      code: 'NOT_STUDENT'
    });
  }

  try {
    // TODO: Add database check for student status
    // const student = await db.select().from(students).where(eq(students.id, req.user.id)).limit(1);
    // 
    // if (!student.length) {
    //   logger.warn({ userId: req.user.id }, 'Student not found in database');
    //   return res.status(404).json({
    //     error: 'Student record not found',
    //     code: 'STUDENT_NOT_FOUND'
    //   });
    // }
    //
    // const studentRecord = student[0];
    //
    // // Check if student account is active
    // if (!studentRecord.is_active) {
    //   logger.warn({ userId: req.user.id }, 'Inactive student attempted action');
    //   return res.status(403).json({
    //     error: 'Student account is inactive',
    //     code: 'STUDENT_INACTIVE'
    //   });
    // }
    //
    // // Check if student ID card is still valid
    // const now = new Date();
    // if (studentRecord.expires_at && now > studentRecord.expires_at) {
    //   logger.warn({ 
    //     userId: req.user.id,
    //     expiresAt: studentRecord.expires_at 
    //   }, 'Expired student attempted action');
    //   return res.status(403).json({
    //     error: 'Student ID has expired',
    //     code: 'STUDENT_EXPIRED'
    //   });
    // }

    next();
  } catch (error) {
    logger.error({ 
      error: error instanceof Error ? error.message : 'Unknown error',
      userId: req.user.id 
    }, 'Student eligibility validation failed');
    
    return res.status(500).json({
      error: 'Failed to validate student eligibility',
      code: 'VALIDATION_ERROR'
    });
  }
}

/**
 * Middleware to validate student data updates
 * Prevents students from modifying protected fields
 */
export function validateStudentUpdate(req: Request, res: Response, next: NextFunction) {
  const protectedFields = ['full_name', 'student_id', 'university_id', 'university_name', 'expires_at', 'is_active'];
  
  // If user is a student, check they're not trying to modify protected fields
  if (req.user?.role === 'student') {
    const attemptedChanges = Object.keys(req.body);
    const forbiddenChanges = attemptedChanges.filter(field => protectedFields.includes(field));
    
    if (forbiddenChanges.length > 0) {
      logger.warn({
        userId: req.user.id,
        attemptedChanges: forbiddenChanges,
        path: req.path
      }, 'Student attempted to modify protected fields');
      
      return res.status(403).json({
        error: 'Students cannot modify these fields',
        code: 'PROTECTED_FIELDS',
        fields: forbiddenChanges,
        allowed: ['email', 'phone']
      });
    }
  }

  next();
}

/**
 * Generic request validation using Zod schemas
 */
export function validateRequest(schema: z.ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const result = schema.safeParse({
        body: req.body,
        query: req.query,
        params: req.params
      });

      if (!result.success) {
        logger.warn({
          path: req.path,
          method: req.method,
          errors: result.error.issues
        }, 'Request validation failed');

        return res.status(400).json({
          error: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: result.error.issues.map(issue => ({
            field: issue.path.join('.'),
            message: issue.message,
            code: issue.code
          }))
        });
      }

      // Store validated data
      req.validatedData = result.data;
      next();
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        path: req.path
      }, 'Validation middleware error');

      return res.status(500).json({
        error: 'Internal validation error',
        code: 'VALIDATION_INTERNAL_ERROR'
      });
    }
  };
}

// Extend Request type for validated data
declare global {
  namespace Express {
    interface Request {
      validatedData?: any;
    }
  }
}