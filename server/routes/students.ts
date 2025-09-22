import { Router } from 'express';
import { z } from 'zod';
import { authenticateToken, requireStaff, requireUniversityAccess } from '../middleware/auth';
import { validateRequest, validateStudentUpdate, validateStudentEligibility } from '../middleware/validation';
import { generalRateLimit, verifyRateLimit, redeemRateLimit } from '../middleware/rateLimiting';
import { logger, auditLogger } from '../middleware/logging';
import { sanitizeStudentForMerchant, sanitizeStudentForUniversity } from '../utils/dataMinimization';

const router = Router();

// Student search/list validation
const studentsQuerySchema = z.object({
  query: z.object({
    page: z.coerce.number().min(1).default(1),
    limit: z.coerce.number().min(1).max(100).default(20),
    search: z.string().optional(),
    university_id: z.string().optional(),
    status: z.enum(['active', 'inactive', 'expired']).optional()
  })
});

// Student update validation
const studentUpdateSchema = z.object({
  body: z.object({
    email: z.string().email().optional(),
    phone: z.string().optional(),
    is_active: z.boolean().optional(),
    first_name: z.string().optional(), // Only allowed for admin/university
    last_name: z.string().optional(), // Only allowed for admin/university
    student_id: z.string().optional(), // Only allowed for admin/university
    university_id: z.string().optional() // Only allowed for admin
  }),
  params: z.object({
    id: z.string()
  })
});

// QR verification schema
const qrVerifySchema = z.object({
  body: z.object({
    qr_code: z.string(),
    merchant_id: z.string()
  })
});

// Discount redemption schema
const redeemSchema = z.object({
  body: z.object({
    verification_id: z.string(),
    discount_id: z.string(),
    merchant_id: z.string(),
    bill_amount: z.number().min(0).optional()
  })
});

/**
 * GET /api/students
 * List students with pagination and filtering
 * Admin: See all students
 * University: See only their students
 */
router.get('/',
  generalRateLimit,
  authenticateToken,
  requireStaff,
  requireUniversityAccess,
  validateRequest(studentsQuerySchema),
  async (req, res) => {
    try {
      const { page, limit, search, university_id, status } = req.validatedData.query;
      
      // TODO: Implement actual database query
      // Build query based on user role
      let queryFilter: any = {};
      
      if (req.user!.role === 'university') {
        queryFilter.university_id = req.user!.university_id;
      } else if (university_id) {
        queryFilter.university_id = university_id;
      }
      
      if (status) {
        if (status === 'expired') {
          queryFilter.expires_at = { lt: new Date() };
        } else {
          queryFilter.is_active = status === 'active';
        }
      }
      
      // Mock data for demonstration
      const mockStudents = [
        {
          id: '1',
          full_name: 'Ahmed Hassan',
          email: 'ahmed@university.edu',
          phone: '+971501234567',
          student_id: 'STU001',
          university_id: 'univ-1',
          university_name: 'American University of Dubai',
          is_active: true,
          expires_at: new Date('2025-06-30'),
          created_at: new Date(),
          updated_at: new Date()
        }
      ];
      
      // Apply data minimization based on user role
      const sanitizedStudents = mockStudents.map(student => {
        if (req.user!.role === 'university') {
          return sanitizeStudentForUniversity(student, req.user!.university_id!);
        }
        return student; // Admin sees all data
      });
      
      const offset = (page - 1) * limit;
      const total = mockStudents.length;
      const totalPages = Math.ceil(total / limit);
      
      logger.debug({
        userId: req.user!.id,
        role: req.user!.role,
        filters: queryFilter,
        page,
        limit
      }, 'Students list requested');
      
      return res.json({
        success: true,
        data: {
          students: sanitizedStudents,
          pagination: {
            page,
            limit,
            total,
            totalPages,
            hasNext: page < totalPages,
            hasPrev: page > 1
          }
        }
      });
      
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: req.user?.id
      }, 'Students list error');
      
      return res.status(500).json({
        error: 'Failed to fetch students',
        code: 'FETCH_ERROR'
      });
    }
  }
);

/**
 * GET /api/students/:id
 * Get specific student details
 */
router.get('/:id',
  generalRateLimit,
  authenticateToken,
  requireStaff,
  requireUniversityAccess,
  async (req, res) => {
    try {
      const { id } = req.params;
      
      // TODO: Implement actual database query
      const mockStudent = {
        id,
        full_name: 'Ahmed Hassan',
        email: 'ahmed@university.edu',
        phone: '+971501234567',
        student_id: 'STU001',
        university_id: 'univ-1',
        university_name: 'American University of Dubai',
        is_active: true,
        expires_at: new Date('2025-06-30'),
        created_at: new Date(),
        updated_at: new Date()
      };
      
      // Apply data minimization
      const sanitizedStudent = req.user!.role === 'university' 
        ? sanitizeStudentForUniversity(mockStudent, req.user!.university_id!)
        : mockStudent;
      
      return res.json({
        success: true,
        data: { student: sanitizedStudent }
      });
      
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        studentId: req.params.id,
        userId: req.user?.id
      }, 'Student fetch error');
      
      return res.status(500).json({
        error: 'Failed to fetch student',
        code: 'FETCH_ERROR'
      });
    }
  }
);

/**
 * PUT /api/students/:id
 * Update student information
 * Students can only update email/phone
 * Staff can update additional fields
 */
router.put('/:id',
  generalRateLimit,
  authenticateToken,
  validateStudentUpdate,
  validateRequest(studentUpdateSchema),
  async (req, res) => {
    try {
      const { id } = req.params;
      const updateData = req.validatedData.body;
      
      // Students can only update their own record
      if (req.user!.role === 'student' && req.user!.id !== id) {
        return res.status(403).json({
          error: 'Students can only update their own profile',
          code: 'UNAUTHORIZED_UPDATE'
        });
      }
      
      // TODO: Implement actual database update
      
      auditLogger.info({
        action: 'student_update',
        studentId: id,
        updatedBy: req.user!.id,
        role: req.user!.role,
        fields: Object.keys(updateData)
      }, 'Student information updated');
      
      return res.json({
        success: true,
        message: 'Student updated successfully'
      });
      
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        studentId: req.params.id,
        userId: req.user?.id
      }, 'Student update error');
      
      return res.status(500).json({
        error: 'Failed to update student',
        code: 'UPDATE_ERROR'
      });
    }
  }
);

/**
 * POST /api/students/verify
 * Verify student QR code for merchant
 */
router.post('/verify',
  verifyRateLimit,
  authenticateToken,
  validateStudentEligibility,
  validateRequest(qrVerifySchema),
  async (req, res) => {
    try {
      const { qr_code, merchant_id } = req.validatedData.body;
      
      // TODO: Implement QR code verification
      // 1. Decode QR token
      // 2. Validate student eligibility
      // 3. Check merchant permissions
      // 4. Return sanitized student data
      
      const mockStudent = {
        id: 'student-1',
        full_name: 'Ahmed Hassan',
        student_id: 'STU001',
        university_name: 'American University of Dubai',
        is_active: true,
        expires_at: new Date('2025-06-30')
      };
      
      // Apply data minimization for merchant view
      const sanitizedStudent = sanitizeStudentForMerchant(mockStudent);
      
      auditLogger.info({
        action: 'qr_verification',
        studentId: 'student-1',
        merchantId: merchant_id,
        verifiedBy: req.user!.id,
        ip: req.ip
      }, 'QR code verified');
      
      return res.json({
        success: true,
        data: {
          verification_id: 'verify-123',
          student: sanitizedStudent,
          valid_until: new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
        }
      });
      
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: req.user?.id,
        ip: req.ip
      }, 'QR verification error');
      
      return res.status(500).json({
        error: 'Verification failed',
        code: 'VERIFICATION_ERROR'
      });
    }
  }
);

/**
 * POST /api/students/redeem
 * Redeem discount after verification
 */
router.post('/redeem',
  redeemRateLimit,
  authenticateToken,
  validateStudentEligibility,
  validateRequest(redeemSchema),
  async (req, res) => {
    try {
      const { verification_id, discount_id, merchant_id, bill_amount } = req.validatedData.body;
      
      // TODO: Implement discount redemption
      // 1. Validate verification_id
      // 2. Check discount availability
      // 3. Apply discount rules
      // 4. Record redemption
      
      auditLogger.info({
        action: 'discount_redemption',
        verificationId: verification_id,
        discountId: discount_id,
        merchantId: merchant_id,
        billAmount: bill_amount,
        redeemedBy: req.user!.id,
        ip: req.ip
      }, 'Discount redeemed');
      
      return res.json({
        success: true,
        data: {
          redemption_id: 'redeem-123',
          amount_saved: 25.00,
          final_amount: bill_amount ? bill_amount - 25.00 : null,
          redeemed_at: new Date()
        }
      });
      
    } catch (error) {
      logger.error({
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: req.user?.id,
        ip: req.ip
      }, 'Discount redemption error');
      
      return res.status(500).json({
        error: 'Redemption failed',
        code: 'REDEMPTION_ERROR'
      });
    }
  }
);

export default router;