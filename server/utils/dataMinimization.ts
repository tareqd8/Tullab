import { logger } from '../middleware/logging';

/**
 * Data minimization utilities for GDPR compliance
 */

/**
 * Mask student name for merchant view
 * Only shows first name initial and last name initial
 */
export function maskStudentName(fullName: string): string {
  if (!fullName || typeof fullName !== 'string') {
    return 'Student';
  }

  const nameParts = fullName.trim().split(' ').filter(part => part.length > 0);
  
  if (nameParts.length === 0) {
    return 'Student';
  }
  
  if (nameParts.length === 1) {
    return `${nameParts[0].charAt(0)}.`;
  }
  
  const firstName = nameParts[0];
  const lastName = nameParts[nameParts.length - 1];
  
  return `${firstName.charAt(0)}. ${lastName.charAt(0)}.`;
}

/**
 * Mask email for limited visibility
 * Shows only first letter and domain
 */
export function maskEmail(email: string): string {
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return '***@***.***';
  }
  
  const [localPart, domain] = email.split('@');
  const maskedLocal = localPart.charAt(0) + '*'.repeat(Math.max(localPart.length - 1, 2));
  
  return `${maskedLocal}@${domain}`;
}

/**
 * Mask phone number for limited visibility
 * Shows only last 4 digits
 */
export function maskPhone(phone: string): string {
  if (!phone || typeof phone !== 'string') {
    return '***-***-****';
  }
  
  const cleanPhone = phone.replace(/\D/g, '');
  
  if (cleanPhone.length < 4) {
    return '***-***-****';
  }
  
  const lastFour = cleanPhone.slice(-4);
  const maskedPart = '*'.repeat(Math.max(cleanPhone.length - 4, 3));
  
  if (cleanPhone.length === 10) {
    return `***-***-${lastFour}`;
  }
  
  return `${maskedPart}${lastFour}`;
}

/**
 * Student ID masking for merchant view
 * Shows only partial student ID
 */
export function maskStudentId(studentId: string): string {
  if (!studentId || typeof studentId !== 'string') {
    return '****';
  }
  
  if (studentId.length <= 4) {
    return '*'.repeat(studentId.length);
  }
  
  const lastTwo = studentId.slice(-2);
  const maskedPart = '*'.repeat(studentId.length - 2);
  
  return `${maskedPart}${lastTwo}`;
}

/**
 * Sanitize student data for merchant view
 * Removes or masks PII according to GDPR data minimization
 */
export function sanitizeStudentForMerchant(student: any): any {
  if (!student) {
    return null;
  }
  
  const sanitized = {
    // Keep essential fields for verification
    id: student.id,
    student_id: maskStudentId(student.student_id),
    university_name: student.university_name,
    is_active: student.is_active,
    expires_at: student.expires_at,
    
    // Mask PII
    full_name: maskStudentName(student.full_name),
    email: maskEmail(student.email),
    phone: student.phone ? maskPhone(student.phone) : null,
    
    // Timestamps for verification (no PII)
    created_at: student.created_at,
    updated_at: student.updated_at
  };
  
  logger.debug({
    originalFields: Object.keys(student),
    sanitizedFields: Object.keys(sanitized),
    component: 'data-minimization'
  }, 'Student data sanitized for merchant view');
  
  return sanitized;
}

/**
 * Sanitize redemption data for merchant view
 * Keeps redemption details but masks student PII
 */
export function sanitizeRedemptionForMerchant(redemption: any): any {
  if (!redemption) {
    return null;
  }
  
  const sanitized = {
    // Redemption details
    id: redemption.id,
    discount_id: redemption.discount_id,
    business_id: redemption.business_id,
    amount_saved: redemption.amount_saved,
    redeemed_at: redemption.redeemed_at,
    status: redemption.status,
    
    // Minimal student info (masked)
    student: redemption.student ? {
      id: redemption.student.id,
      university_name: redemption.student.university_name,
      full_name: maskStudentName(redemption.student.full_name),
      student_id: maskStudentId(redemption.student.student_id)
    } : null,
    
    // Discount info (no PII)
    discount: redemption.discount ? {
      title: redemption.discount.title,
      percentage: redemption.discount.percentage,
      flat_amount: redemption.discount.flat_amount
    } : null
  };
  
  return sanitized;
}

/**
 * Sanitize student data for university view
 * Universities can see their own students' full data
 */
export function sanitizeStudentForUniversity(student: any, universityId: string): any {
  if (!student) {
    return null;
  }
  
  // University can only see their own students' full data
  if (student.university_id !== universityId) {
    logger.warn({
      studentUniversityId: student.university_id,
      requestingUniversityId: universityId,
      component: 'data-minimization'
    }, 'University attempted to access student from different university');
    
    return sanitizeStudentForMerchant(student);
  }
  
  // Return full data for their own students
  return student;
}

/**
 * Remove sensitive fields from any object
 */
export function removeSensitiveFields(obj: any, sensitiveFields: string[] = []): any {
  if (!obj || typeof obj !== 'object') {
    return obj;
  }
  
  const defaultSensitiveFields = [
    'password',
    'password_hash',
    'token',
    'refresh_token',
    'access_token',
    'secret',
    'private_key',
    'api_key'
  ];
  
  const fieldsToRemove = [...defaultSensitiveFields, ...sensitiveFields];
  const cleaned = { ...obj };
  
  fieldsToRemove.forEach(field => {
    if (field in cleaned) {
      delete cleaned[field];
    }
  });
  
  return cleaned;
}