import { storage } from "./storage";
import { randomUUID } from "crypto";

/**
 * Test helper functions for setting up test data and cleaning up
 */

export async function createTestAccount(role: 'admin' | 'university' | 'student' | 'merchant', email: string, password: string) {
  const accountData = {
    id: randomUUID(),
    student_id: role === 'student' ? randomUUID() : null,
    business_id: role === 'merchant' ? randomUUID() : null,
    role: role as any,
    email,
    password_hash: password, // Will be hashed by storage
    last_login_at: null,
    created_at: new Date(),
    updated_at: new Date()
  };

  return await storage.createAccount(accountData);
}

export async function cleanupTestData() {
  // In a real implementation, this would clean up test data
  // For now, we'll just log that cleanup was called
  console.log('🧹 Test data cleanup called');
  
  // You could add actual cleanup logic here:
  // - Delete test accounts
  // - Delete test students
  // - Delete test universities
  // etc.
}

export function createTestUniversity(code: string, name: string) {
  return {
    id: randomUUID(),
    code,
    name,
    contact_email: `contact@${code.toLowerCase()}.edu`,
    created_at: new Date(),
    updated_at: new Date()
  };
}

export function createTestStudent(universityId: string, studentId: string, firstName: string, lastName: string, email: string) {
  return {
    id: randomUUID(),
    university_id: universityId,
    student_id: studentId,
    first_name: firstName,
    last_name: lastName,
    email,
    phone: '+1-555-0000',
    valid_from: '2024-09-01',
    valid_until: '2025-06-30',
    status: 'active' as const,
    created_at: new Date(),
    updated_at: new Date()
  };
}