import { 
  selectAccountSchema, 
  insertAccountSchema, 
  accounts, 
  selectRefreshTokenSchema, 
  insertRefreshTokenSchema, 
  refresh_tokens,
  students,
  universities,
  insertStudentSchema,
  selectStudentSchema,
  selectUniversitySchema,
  insertUniversitySchema,
  qr_tokens,
  insertQrTokenSchema,
  selectQrTokenSchema,
  businesses,
  selectBusinessSchema,
  insertBusinessSchema,
  discounts,
  selectDiscountSchema,
  insertDiscountSchema,
  discount_categories,
  selectDiscountCategorySchema,
  insertDiscountCategorySchema,
  redemptions,
  insertRedemptionSchema,
  selectRedemptionSchema,
  security_events,
  InsertSecurityEvent,
  SelectSecurityEvent,
  InsertBusiness,
  InsertDiscount,
  InsertDiscountCategory,
  InsertUniversity
} from "../packages/shared/src/schemas";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { randomUUID, createHash } from "crypto";
import * as argon2 from "argon2";
import * as bcrypt from "bcryptjs";
import { db } from "./db";
import { eq, and, lt, isNull, gt, desc, asc, ilike, or, count, sql, gte, lte } from "drizzle-orm";

export type Account = z.infer<typeof selectAccountSchema>;
export type NewAccount = z.infer<typeof insertAccountSchema>;
export type Student = z.infer<typeof selectStudentSchema>;
export type NewStudent = z.infer<typeof insertStudentSchema>;
export type University = z.infer<typeof selectUniversitySchema>;
export type NewUniversity = z.infer<typeof insertUniversitySchema>;
export type QrToken = z.infer<typeof selectQrTokenSchema>;
export type NewQrToken = z.infer<typeof insertQrTokenSchema>;
export type Business = z.infer<typeof selectBusinessSchema>;
export type NewBusiness = z.infer<typeof insertBusinessSchema>;
export type Discount = z.infer<typeof selectDiscountSchema>;
export type NewDiscount = z.infer<typeof insertDiscountSchema>;
export type Redemption = z.infer<typeof selectRedemptionSchema>;
export type NewRedemption = z.infer<typeof insertRedemptionSchema>;
export type DiscountCategory = z.infer<typeof selectDiscountCategorySchema>;
export type NewDiscountCategory = z.infer<typeof insertDiscountCategorySchema>;

export interface DiscountFilters {
  category_id?: string;
  business_id?: string;
  city?: string;
  activeOnly?: boolean;
  q?: string; // search query
  sort?: 'recent' | 'endingSoon' | 'popular';
  page?: number;
  limit?: number;
}

export interface PaginatedDiscounts {
  discounts: (Discount & { business: Business; category: DiscountCategory })[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

export interface ImportSummary {
  created: number;
  updated: number;
  expired: number;
  errors: string[];
}

export interface CSVStudentRow {
  student_id: string;
  first_name: string;
  last_name: string;
  university: string;
  valid_from: string;
  valid_until: string;
  email: string;
  phone?: string;
}

export interface QRVerificationResult {
  isValid: boolean;
  student?: {
    first_name: string;
    last_name: string;
    university_name: string;
    valid_until: string;
    eligibility: boolean;
  };
  error?: string;
  consumed?: boolean;
  consumedAt?: Date;
  withinIdempotencyWindow?: boolean;
}

export interface ConsumedQRToken {
  token_hash: string;
  consumed_at: Date;
  expires_at: Date; // for cleanup
}

/**
 * Create deterministic SHA-256 hash of QR token for storage and lookup
 */
function hashQRToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

// Zod schema for CSV row validation
const csvStudentRowSchema = z.object({
  student_id: z.string().min(1, "Student ID is required"),
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  university: z.string().min(1, "University is required"),
  valid_from: z.string().refine(val => !isNaN(Date.parse(val)), "Invalid valid_from date format"),
  valid_until: z.string().refine(val => !isNaN(Date.parse(val)), "Invalid valid_until date format"),
  email: z.string().email("Invalid email format"),
  phone: z.string().optional().or(z.literal(""))
});

// Business and discount types
export interface BusinessFilters {
  page?: number;
  limit?: number;
  search?: string;
  category?: string;
  verified?: boolean;
}

export interface PaginatedBusinesses {
  data: Business[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}


// modify the interface with any CRUD methods
// you might need

export interface IStorage {
  getAccount(id: string): Promise<Account | undefined>;
  getAccountByEmail(email: string): Promise<Account | undefined>;
  createAccount(account: NewAccount): Promise<Account>;
  verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean>;
  hashPassword(plainPassword: string): Promise<string>;
  getAllAccounts(): Promise<Account[]>;
  updateAccount(id: string, updates: Partial<NewAccount>): Promise<Account | undefined>;
  deleteAccount(id: string): Promise<boolean>;
  importStudents(csvData: CSVStudentRow[], requestingUser: Account): Promise<ImportSummary>;
  
  // QR Token methods
  storeQRToken(studentId: string, token: string, expiresAt: Date): Promise<void>;
  isQRTokenConsumed(token: string): Promise<boolean>;
  markQRTokenConsumed(token: string): Promise<void>;
  atomicConsumeQRToken(token: string): Promise<{ consumed: boolean; consumedAt?: Date; withinIdempotencyWindow?: boolean }>;
  getStudentById(studentId: string): Promise<Student | undefined>;
  getStudents(params: { page?: number; limit?: number; search?: string; university_id?: string; status?: string; dateFrom?: string; dateTo?: string }): Promise<{ data: Student[]; pagination: { page: number; limit: number; total: number; totalPages: number } }>;
  updateStudent(studentId: string, data: Partial<Student>): Promise<Student>;
  updateStudentStatus(studentId: string, status: Student['status']): Promise<Student>;
  deleteStudent(studentId: string): Promise<boolean>;
  verifyQRToken(studentId: string, discountId?: string): Promise<QRVerificationResult>;
  createRedemption(redemption: NewRedemption): Promise<Redemption>;
  
  // University methods
  getUniversities(params?: { page?: number; limit?: number; search?: string }): Promise<{ data: University[]; pagination: { page: number; limit: number; total: number; totalPages: number } }>;
  getUniversityById(id: string): Promise<University | undefined>;
  getUniversityByCode(code: string): Promise<University | undefined>;
  createUniversity(university: NewUniversity): Promise<University>;
  updateUniversity(id: string, updates: Partial<NewUniversity>): Promise<University | undefined>;
  deleteUniversity(id: string): Promise<boolean>;

  // Business methods
  getBusinesses(filters: BusinessFilters): Promise<PaginatedBusinesses>;
  getBusinessById(id: string): Promise<Business | undefined>;
  getBusinessByEmail(email: string): Promise<Business | undefined>;
  createBusiness(business: NewBusiness): Promise<Business>;
  updateBusiness(id: string, updates: Partial<NewBusiness>): Promise<Business | undefined>;
  deleteBusiness(id: string): Promise<boolean>;

  // Discount methods
  getDiscounts(filters: DiscountFilters): Promise<PaginatedDiscounts>;
  getDiscountById(id: string): Promise<Discount | undefined>;
  createDiscount(discount: NewDiscount): Promise<Discount>;
  updateDiscount(id: string, updates: Partial<NewDiscount>): Promise<Discount | undefined>;
  deleteDiscount(id: string): Promise<boolean>;
  getCategories(search?: string): Promise<DiscountCategory[]>;
  createDiscountCategory(category: NewDiscountCategory): Promise<DiscountCategory>;
  updateDiscountCategory(id: string, updates: Partial<NewDiscountCategory>): Promise<DiscountCategory | undefined>;
  deleteDiscountCategory(id: string): Promise<boolean>;
  createRedemptionFromToken(studentToken: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption>;
  createRedemptionFromStudentId(studentId: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption>;
  
  // Security methods
  createSecurityEvent(event: InsertSecurityEvent): Promise<SelectSecurityEvent>;
}

export class DatabaseStorage implements IStorage {
  async getAccount(id: string): Promise<Account | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(accounts).where(eq(accounts.id, id)).limit(1);
      return result[0] || undefined;
    } catch (error) {
      console.error("Error getting account:", error);
      return undefined;
    }
  }

  async getAccountByEmail(email: string): Promise<Account | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(accounts).where(eq(accounts.email, email)).limit(1);
      return result[0] || undefined;
    } catch (error) {
      console.error("Error getting account by email:", error);
      return undefined;
    }
  }

  async createAccount(insertAccount: NewAccount): Promise<Account> {
    if (!db) throw new Error("Database not available");
    try {
      const hashedPassword = await this.hashPassword(insertAccount.password_hash);
      const result = await db.insert(accounts).values({
        ...insertAccount,
        password_hash: hashedPassword,
      }).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating account:", error);
      throw error;
    }
  }

  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    try {
      // Support both bcrypt (legacy) and Argon2 (new) password hashes
      // This provides backward compatibility during migration
      
      // Check if it's a bcrypt hash (starts with $2a$, $2b$, or $2y$)
      if (hashedPassword.startsWith('$2a$') || hashedPassword.startsWith('$2b$') || hashedPassword.startsWith('$2y$')) {
        console.log('🔒 [AUTH] Using bcrypt verification for legacy password');
        return await bcrypt.compare(plainPassword, hashedPassword);
      }
      
      // Check if it's an Argon2 hash (starts with $argon2)
      if (hashedPassword.startsWith('$argon2')) {
        console.log('🔒 [AUTH] Using Argon2 verification for new password');
        return await argon2.verify(hashedPassword, plainPassword);
      }
      
      // Unknown hash format
      console.warn('🚨 [AUTH] Unknown password hash format');
      return false;
    } catch (error) {
      console.error("Error verifying password:", error);
      return false;
    }
  }

  async hashPassword(plainPassword: string): Promise<string> {
    try {
      return await argon2.hash(plainPassword, {
        type: argon2.argon2id,
        memoryCost: 19456, // 19 MiB in KB
        timeCost: 2,       // 2 iterations
        parallelism: 1,    // 1 thread
      });
    } catch (error) {
      console.error("Error hashing password:", error);
      throw error;
    }
  }

  async getAllAccounts(): Promise<Account[]> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(accounts);
      return result;
    } catch (error) {
      console.error("Error getting all accounts:", error);
      throw error;
    }
  }

  async updateAccount(id: string, updates: Partial<NewAccount>): Promise<Account | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const updateData = { ...updates } as any;
      if (updates.password_hash) {
        updateData.password_hash = await this.hashPassword(updates.password_hash);
      }
      const result = await db.update(accounts).set(updateData).where(eq(accounts.id, id)).returning();
      return result[0] || undefined;
    } catch (error) {
      console.error("Error updating account:", error);
      throw error;
    }
  }

  async deleteAccount(id: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.delete(accounts).where(eq(accounts.id, id)).returning();
      return result.length > 0;
    } catch (error) {
      console.error("Error deleting account:", error);
      return false;
    }
  }

  async storeQRToken(studentId: string, token: string, expiresAt: Date): Promise<void> {
    if (!db) throw new Error("Database not available");
    try {
      const tokenHash = hashQRToken(token);
      await db.insert(qr_tokens).values({
        student_id: studentId,
        token_hash: tokenHash,
        expires_at: expiresAt,
      });
    } catch (error) {
      console.error("Error storing QR token:", error);
      throw new Error("Failed to store QR token");
    }
  }

  async isQRTokenConsumed(token: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      const tokenHash = hashQRToken(token);
      const result = await db
        .select()
        .from(qr_tokens)
        .where(and(eq(qr_tokens.token_hash, tokenHash), eq(qr_tokens.active, false)))
        .limit(1);
      return result.length > 0;
    } catch (error) {
      console.error("Error checking QR token consumption:", error);
      return false;
    }
  }

  async markQRTokenConsumed(token: string): Promise<void> {
    if (!db) throw new Error("Database not available");
    try {
      const tokenHash = hashQRToken(token);
      const now = new Date();
      await db
        .update(qr_tokens)
        .set({ active: false, rotated_at: now, consumed_at: now })
        .where(and(eq(qr_tokens.token_hash, tokenHash), eq(qr_tokens.active, true)));
    } catch (error) {
      console.error("Error marking QR token as consumed:", error);
      throw new Error("Failed to mark QR token as consumed");
    }
  }

  async getStudentById(studentId: string): Promise<Student | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(students).where(eq(students.id, studentId)).limit(1);
      return result[0] || undefined;
    } catch (error) {
      console.error("Error getting student:", error);
      return undefined;
    }
  }

  async getStudents(params: { page?: number; limit?: number; search?: string; university_id?: string; status?: string; dateFrom?: string; dateTo?: string }): Promise<{ data: Student[]; pagination: { page: number; limit: number; total: number; totalPages: number } }> {
    if (!db) throw new Error("Database not available");
    
    try {
      const page = params.page || 1;
      const limit = params.limit || 20;
      const offset = (page - 1) * limit;
      
      // Build where conditions
      const conditions = [];
      
      if (params.search) {
        conditions.push(
          or(
            ilike(students.first_name, `%${params.search}%`),
            ilike(students.last_name, `%${params.search}%`),
            ilike(students.email, `%${params.search}%`),
            ilike(students.student_id, `%${params.search}%`)
          )
        );
      }
      
      if (params.university_id) {
        conditions.push(eq(students.university_id, params.university_id));
      }
      
      if (params.status) {
        conditions.push(eq(students.status, params.status as any));
      }

      // Date filters
      if (params.dateFrom) {
        conditions.push(gte(students.created_at, new Date(params.dateFrom)));
      }
      
      if (params.dateTo) {
        const endDate = new Date(params.dateTo);
        endDate.setHours(23, 59, 59, 999); // End of day
        conditions.push(lte(students.created_at, endDate));
      }
      
      const whereClause = conditions.length > 0 ? and(...conditions) : undefined;
      
      // Get total count with join for consistency
      const countResult = await db
        .select({ count: count() })
        .from(students)
        .leftJoin(universities, eq(students.university_id, universities.id))
        .where(whereClause);
      
      const total = countResult[0]?.count || 0;
      const totalPages = Math.ceil(total / limit);
      
      // Get paginated data with university information
      const studentsData = await db
        .select({
          id: students.id,
          first_name: students.first_name,
          last_name: students.last_name,
          name: sql<string>`CONCAT(${students.first_name}, ' ', ${students.last_name})`.as('name'),
          student_id: students.student_id,
          email: students.email,
          phone: students.phone,
          valid_from: students.valid_from,
          valid_until: students.valid_until,
          status: students.status,
          university_id: students.university_id,
          created_at: students.created_at,
          updated_at: students.updated_at,
          university_name: universities.name,
          university: {
            id: universities.id,
            name: universities.name,
            code: universities.code
          }
        })
        .from(students)
        .leftJoin(universities, eq(students.university_id, universities.id))
        .where(whereClause)
        .limit(limit)
        .offset(offset)
        .orderBy(desc(students.created_at));
      
      return {
        data: studentsData,
        pagination: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      console.error("Error getting students:", error);
      return {
        data: [],
        pagination: { page: 1, limit: 20, total: 0, totalPages: 0 }
      };
    }
  }

  async updateStudent(studentId: string, data: Partial<Student>): Promise<Student> {
    if (!db) throw new Error("Database not available");
    
    try {
      const updateData = { ...data, updated_at: new Date() } as any;
      
      const result = await db
        .update(students)
        .set(updateData)
        .where(eq(students.id, studentId))
        .returning();
      
      if (!result.length) {
        throw new Error("Student not found");
      }
      
      return result[0];
    } catch (error) {
      console.error("Error updating student:", error);
      throw error;
    }
  }

  async updateStudentStatus(studentId: string, status: Student['status']): Promise<Student> {
    if (!db) throw new Error("Database not available");
    
    try {
      const result = await db
        .update(students)
        .set({ 
          status,
          updated_at: new Date()
        })
        .where(eq(students.id, studentId))
        .returning();
      
      if (!result.length) {
        throw new Error("Student not found");
      }
      
      return result[0];
    } catch (error) {
      console.error("Error updating student status:", error);
      throw error;
    }
  }

  async deleteStudent(studentId: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      // Check if student has associated redemptions
      const redemptionsCount = await db.select({ count: count() })
        .from(redemptions)
        .where(eq(redemptions.student_id, studentId));
      
      if (redemptionsCount[0]?.count > 0) {
        throw new Error("Cannot delete student with existing redemptions");
      }

      const result = await db.delete(students).where(eq(students.id, studentId));
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      console.error("Error deleting student:", error);
      throw error;
    }
  }

  async verifyQRToken(studentId: string, discountId?: string): Promise<QRVerificationResult> {
    if (!db) throw new Error("Database not available");
    try {
      // Get student with university info
      const studentResult = await db
        .select({
          student: students,
          university: universities
        })
        .from(students)
        .innerJoin(universities, eq(students.university_id, universities.id))
        .where(eq(students.id, studentId))
        .limit(1);

      if (!studentResult.length) {
        return { isValid: false, error: "Student not found" };
      }

      const { student, university } = studentResult[0];
      const now = new Date();
      const validUntil = new Date(student.valid_until);
      const isEligible = validUntil >= now && student.status === 'active';

      // Mask student name (first name + last initial)
      const firstName = student.first_name;
      const lastInitial = student.last_name ? student.last_name[0] + '.' : '';
      const maskedName = `${firstName} ${lastInitial}`.trim();

      return {
        isValid: true,
        student: {
          first_name: firstName,
          last_name: lastInitial,
          university_name: university.name,
          valid_until: student.valid_until,
          eligibility: isEligible
        }
      };
    } catch (error) {
      console.error("Error verifying QR token:", error);
      return { isValid: false, error: "Internal server error" };
    }
  }

  async atomicConsumeQRToken(token: string): Promise<{ consumed: boolean; consumedAt?: Date; withinIdempotencyWindow?: boolean }> {
    if (!db) throw new Error("Database not available");
    try {
      const tokenHash = hashQRToken(token);
      const now = new Date();
      const tenSecondsAgo = new Date(now.getTime() - 10 * 1000);

      // First check if token exists and its status
      const existingToken = await db
        .select()
        .from(qr_tokens)
        .where(eq(qr_tokens.token_hash, tokenHash))
        .limit(1);

      if (!existingToken.length) {
        return { consumed: false };
      }

      const token_record = existingToken[0];

      // If token is already consumed, check if within idempotency window
      if (!token_record.active && token_record.consumed_at) {
        const withinWindow = token_record.consumed_at >= tenSecondsAgo;
        return {
          consumed: true,
          consumedAt: token_record.consumed_at,
          withinIdempotencyWindow: withinWindow
        };
      }

      // If token is still active, try to consume it atomically with all conditions
      if (token_record.active && token_record.expires_at > now) {
        const result = await db
          .update(qr_tokens)
          .set({ active: false, consumed_at: now, rotated_at: now })
          .where(and(
            eq(qr_tokens.token_hash, tokenHash), 
            eq(qr_tokens.active, true),
            isNull(qr_tokens.consumed_at),
            gt(qr_tokens.expires_at, now)
          ))
          .returning();

        if (result.length > 0) {
          // Successfully consumed
          return { consumed: false, consumedAt: now };
        } else {
          // Race condition - another request consumed it or token expired
          return { consumed: true, consumedAt: now, withinIdempotencyWindow: true };
        }
      }

      // Token expired or inactive
      return { consumed: true, consumedAt: token_record.consumed_at || undefined };
    } catch (error) {
      console.error("Error in atomic QR token consumption:", error);
      throw new Error("Failed to process QR token");
    }
  }

  async atomicConsumeQRTokenWithRedemption(
    token: string, 
    redemptionData?: NewRedemption
  ): Promise<{ 
    consumed: boolean; 
    consumedAt?: Date; 
    withinIdempotencyWindow?: boolean;
    redemption?: Redemption;
    redemptionCreated: boolean;
    firstConsumption: boolean;
    expired?: boolean;
    error?: string;
  }> {
    if (!db) throw new Error("Database not available");
    
    return await db.transaction(async (tx) => {
      try {
        const tokenHash = hashQRToken(token);
        const now = new Date();
        const tenSecondsAgo = new Date(now.getTime() - 10 * 1000);

        // First check if token exists and its status
        const existingToken = await tx
          .select()
          .from(qr_tokens)
          .where(eq(qr_tokens.token_hash, tokenHash))
          .limit(1);

        if (!existingToken.length) {
          return { 
            consumed: false, 
            redemptionCreated: false, 
            firstConsumption: false,
            error: "Token not found"
          };
        }

        const token_record = existingToken[0];

        // Check if token is expired
        if (token_record.expires_at <= now) {
          return {
            consumed: false,
            expired: true,
            redemptionCreated: false,
            firstConsumption: false,
            error: "Token expired"
          };
        }

        // If token is already consumed, check if within idempotency window
        if (!token_record.active && token_record.consumed_at) {
          const withinWindow = token_record.consumed_at >= tenSecondsAgo;
          
          // If within idempotency window and redemption data provided, 
          // check if redemption exists and create if missing
          let redemption;
          let redemptionCreated = false;
          
          if (withinWindow && redemptionData) {
            // Try to insert with ON CONFLICT DO NOTHING pattern
            try {
              const redemptionResult = await tx.insert(redemptions).values(redemptionData).returning();
              if (redemptionResult.length > 0) {
                redemption = redemptionResult[0];
                redemptionCreated = true;
              }
            } catch (insertError) {
              // If insertion fails due to constraint, try to get existing redemption
                const existingRedemption = await tx
                .select()
                .from(redemptions)
                .where(and(
                  eq(redemptions.student_id, redemptionData.student_id),
                  eq(redemptions.discount_id, redemptionData.discount_id),
                  eq(redemptions.business_id, redemptionData.business_id)
                ))
                .limit(1);
              
              if (existingRedemption.length > 0) {
                redemption = existingRedemption[0];
              }
            }
          }
          
          return {
            consumed: true,
            consumedAt: token_record.consumed_at,
            withinIdempotencyWindow: withinWindow,
            redemption,
            redemptionCreated,
            firstConsumption: false
          };
        }

        // If token is still active, try to consume it atomically with all conditions
        if (token_record.active) {
          const result = await tx
            .update(qr_tokens)
            .set({ active: false, consumed_at: now, rotated_at: now })
            .where(and(
              eq(qr_tokens.token_hash, tokenHash), 
              eq(qr_tokens.active, true),
              isNull(qr_tokens.consumed_at),
              gt(qr_tokens.expires_at, now)
            ))
            .returning();

          if (result.length > 0) {
            // Successfully consumed - create redemption if data provided
            let redemption;
            let redemptionCreated = false;
            
            if (redemptionData) {
              try {
                const redemptionResult = await tx.insert(redemptions).values(redemptionData).returning();
                redemption = redemptionResult[0];
                redemptionCreated = true;
              } catch (insertError) {
                console.error('Failed to create redemption on first consumption:', insertError);
                // Don't fail the token consumption if redemption fails
              }
            }
            
            return { 
              consumed: true, 
              consumedAt: now, 
              redemption,
              redemptionCreated,
              firstConsumption: true,
              withinIdempotencyWindow: false
            };
          } else {
            // Race condition - re-read token to get accurate state
            const rereadToken = await tx
              .select()
              .from(qr_tokens)
              .where(eq(qr_tokens.token_hash, tokenHash))
              .limit(1);
              
            if (rereadToken.length > 0) {
              const updated_record = rereadToken[0];
              
              if (updated_record.consumed_at && updated_record.consumed_at >= tenSecondsAgo) {
                // Another request consumed it within idempotency window
                return { 
                  consumed: true, 
                  consumedAt: updated_record.consumed_at, 
                  withinIdempotencyWindow: true,
                  redemptionCreated: false,
                  firstConsumption: false
                };
              } else if (updated_record.expires_at <= now) {
                // Token expired during race
                return {
                  consumed: false,
                  expired: true,
                  redemptionCreated: false,
                  firstConsumption: false,
                  error: "Token expired"
                };
              }
            }
            
            // Fallback for unexpected race condition
            return { 
              consumed: true, 
              redemptionCreated: false,
              firstConsumption: false,
              error: "Race condition occurred"
            };
          }
        }

        // Token not active but not consumed either (shouldn't happen)
        return { 
          consumed: false, 
          redemptionCreated: false,
          firstConsumption: false,
          error: "Token in invalid state"
        };
      } catch (error) {
        console.error("Error in atomic QR token consumption with redemption:", error);
        throw new Error("Failed to process QR token with redemption");
      }
    });
  }

  async createRedemption(redemption: NewRedemption): Promise<Redemption> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.insert(redemptions).values(redemption).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating redemption:", error);
      throw new Error("Failed to create redemption");
    }
  }

  // University methods implementation
  async getUniversities(params?: { page?: number; limit?: number; search?: string }): Promise<{ data: University[]; pagination: { page: number; limit: number; total: number; totalPages: number } }> {
    if (!db) throw new Error("Database not available");
    try {
      const page = params?.page || 1;
      const limit = params?.limit || 20;
      const offset = (page - 1) * limit;

      // Build where condition for search
      let whereCondition;
      if (params?.search) {
        whereCondition = or(
          ilike(universities.name, `%${params.search}%`),
          ilike(universities.code, `%${params.search}%`),
          ilike(universities.contact_email, `%${params.search}%`)
        );
      }

      // Execute queries directly with proper typing
      const dataQuery = whereCondition
        ? db.select().from(universities).where(whereCondition).orderBy(asc(universities.name)).limit(limit).offset(offset)
        : db.select().from(universities).orderBy(asc(universities.name)).limit(limit).offset(offset);
        
      const countQueryResult = whereCondition
        ? db.select({ count: count() }).from(universities).where(whereCondition)
        : db.select({ count: count() }).from(universities);

      // Execute queries
      const [data, totalResult] = await Promise.all([
        dataQuery,
        countQueryResult
      ]);

      const total = totalResult[0]?.count || 0;
      const totalPages = Math.ceil(total / limit);

      return {
        data: data as University[],
        pagination: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      console.error("Error getting universities:", error);
      throw new Error("Failed to get universities");
    }
  }

  async getUniversityById(id: string): Promise<University | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(universities).where(eq(universities.id, id)).limit(1);
      return result[0] as University || undefined;
    } catch (error) {
      console.error("Error getting university by ID:", error);
      return undefined;
    }
  }

  async getUniversityByCode(code: string): Promise<University | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(universities).where(eq(universities.code, code)).limit(1);
      return result[0] as University || undefined;
    } catch (error) {
      console.error("Error getting university by code:", error);
      return undefined;
    }
  }

  async createUniversity(university: NewUniversity): Promise<University> {
    if (!db) throw new Error("Database not available");
    try {
      // Check if university code already exists
      const existingUniversity = await this.getUniversityByCode(university.code);
      if (existingUniversity) {
        throw new Error("University with this code already exists");
      }

      const result = await db.insert(universities).values(university).returning();
      return result[0] as University;
    } catch (error) {
      console.error("Error creating university:", error);
      throw error;
    }
  }

  async updateUniversity(id: string, updates: Partial<NewUniversity>): Promise<University | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      // If updating code, check for uniqueness
      if (updates.code) {
        const existingUniversity = await this.getUniversityByCode(updates.code);
        if (existingUniversity && String(existingUniversity.id) !== id) {
          throw new Error("University with this code already exists");
        }
      }

      const updateData = {
        ...updates,
        updated_at: new Date()
      };

      const result = await db.update(universities)
        .set(updateData)
        .where(eq(universities.id, id))
        .returning();
      
      return result[0] as University || undefined;
    } catch (error) {
      console.error("Error updating university:", error);
      throw error;
    }
  }

  async deleteUniversity(id: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      // Check if university has associated students
      const studentsCount = await db.select({ count: count() })
        .from(students)
        .where(eq(students.university_id, id));
      
      if (studentsCount[0]?.count > 0) {
        throw new Error("Cannot delete university with associated students");
      }

      const result = await db.delete(universities).where(eq(universities.id, id));
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      console.error("Error deleting university:", error);
      throw error;
    }
  }

  async getDiscounts(filters: DiscountFilters): Promise<PaginatedDiscounts> {
    if (!db) throw new Error("Database not available");
    try {
      const page = filters.page || 1;
      const limit = filters.limit || 20;
      const offset = (page - 1) * limit;

      // Build where conditions array
      const whereConditions = [];
      
      // Handle active filter - only apply if explicitly set
      if (filters.activeOnly === true) {
        whereConditions.push(eq(discounts.is_active, true));
        whereConditions.push(sql`${discounts.start_date} <= CURRENT_DATE`);
        whereConditions.push(sql`${discounts.end_date} >= CURRENT_DATE`);
      } else if (filters.activeOnly === false) {
        whereConditions.push(eq(discounts.is_active, false));
      }
      // If activeOnly is undefined, show all discounts (no is_active filter)

      // Category filter
      if (filters.category_id) {
        whereConditions.push(eq(discounts.category_id, filters.category_id));
      }

      // Business filter
      if (filters.business_id) {
        whereConditions.push(eq(discounts.business_id, filters.business_id));
      }

      // City filter (based on business city) - properly handle with join
      if (filters.city) {
        whereConditions.push(ilike(businesses.city, `%${filters.city}%`));
      }

      // Search query (search in title and description)
      if (filters.q) {
        whereConditions.push(or(
          ilike(discounts.title, `%${filters.q}%`),
          ilike(discounts.description, `%${filters.q}%`)
        ));
      }

      // Create the where clause - handle empty conditions properly
      const whereClause = whereConditions.length > 0 ? and(...whereConditions) : undefined;

      // Build order by clause
      let orderBy;
      switch (filters.sort) {
        case 'endingSoon':
          orderBy = asc(discounts.end_date);
          break;
        case 'popular':
          // For now, order by creation date as proxy for popularity
          // TODO: Implement actual popularity based on redemption counts
          orderBy = desc(discounts.created_at);
          break;
        case 'recent':
        default:
          orderBy = desc(discounts.created_at);
          break;
      }

      // Get total count with same filtering logic
      const totalQuery = db
        .select({ count: count() })
        .from(discounts)
        .leftJoin(businesses, eq(discounts.business_id, businesses.id))
        .leftJoin(discount_categories, eq(discounts.category_id, discount_categories.id));
      
      const totalResult = whereClause 
        ? await totalQuery.where(whereClause)
        : await totalQuery;

      const total = totalResult[0]?.count || 0;

      // Get paginated results with joins and same filtering logic  
      const mainQuery = db
        .select({
          discount: discounts,
          business: businesses,
          category: discount_categories
        })
        .from(discounts)
        .leftJoin(businesses, eq(discounts.business_id, businesses.id))
        .leftJoin(discount_categories, eq(discounts.category_id, discount_categories.id));

      const result = whereClause
        ? await mainQuery
            .where(whereClause)
            .orderBy(orderBy)
            .limit(limit)
            .offset(offset)
        : await mainQuery
            .orderBy(orderBy)
            .limit(limit)
            .offset(offset);

      // Transform results with proper type safety
      const discountsWithRelations = result.map((row: typeof result[0]) => {
        // Ensure business and category are not null for the return type
        if (!row.business) {
          console.warn(`Discount ${row.discount.id} has no associated business`);
        }
        if (!row.category) {
          console.warn(`Discount ${row.discount.id} has no associated category`);
        }
        
        return {
          ...row.discount,
          business: row.business!,
          category: row.category!
        };
      });

      return {
        discounts: discountsWithRelations,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit)
        }
      };
    } catch (error) {
      console.error("Error getting discounts:", error);
      throw new Error("Failed to get discounts");
    }
  }

  async getDiscountById(id: string): Promise<Discount | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db
        .select({
          discount: discounts,
          business: businesses,
          category: discount_categories
        })
        .from(discounts)
        .leftJoin(businesses, eq(discounts.business_id, businesses.id))
        .leftJoin(discount_categories, eq(discounts.category_id, discount_categories.id))
        .where(eq(discounts.id, id))
        .limit(1);

      if (!result[0]) return undefined;

      return {
        ...result[0].discount,
        business: result[0].business,
        category: result[0].category
      } as Discount;
    } catch (error) {
      console.error("Error getting discount by id:", error);
      return undefined;
    }
  }

  async getCategories(search?: string): Promise<DiscountCategory[]> {
    if (!db) throw new Error("Database not available");
    try {
      const query = db
        .select()
        .from(discount_categories)
        .where(search ? ilike(discount_categories.name, `%${search}%`) : undefined)
        .orderBy(asc(discount_categories.name));

      const result = await query;
      return result;
    } catch (error) {
      console.error("Error getting categories:", error);
      throw new Error("Failed to get categories");
    }
  }

  async createRedemptionFromToken(studentToken: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption> {
    if (!db) throw new Error("Database not available");
    try {
      // Verify the student token and get student ID
      // This would use the existing QR token verification logic
      // For now, we'll extract the student ID from the token directly
      // In practice, this should use AuthService.verifyQRToken
      const payload = JSON.parse(Buffer.from(studentToken.split('.')[1], 'base64').toString());
      const studentId = payload.sub;

      return this.createRedemptionFromStudentId(studentId, discountId, businessId, verifierAccountId);
    } catch (error) {
      console.error("Error creating redemption from token:", error);
      throw new Error("Failed to create redemption from token");
    }
  }

  async createRedemptionFromStudentId(studentId: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption> {
    if (!db) throw new Error("Database not available");
    try {
      const redemptionData: NewRedemption = {
        student_id: studentId,
        discount_id: discountId,
        business_id: businessId,
        verifier_account_id: verifierAccountId,
        status: 'approved'
      };

      const result = await db.insert(redemptions).values(redemptionData).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating redemption from student ID:", error);
      throw new Error("Failed to create redemption from student ID");
    }
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SelectSecurityEvent> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.insert(security_events).values(event).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating security event:", error);
      throw new Error("Failed to create security event");
    }
  }

  async importStudents(csvData: CSVStudentRow[], requestingUser: Account): Promise<ImportSummary> {
    if (!db) throw new Error("Database not available");
    
    const summary: ImportSummary = {
      created: 0,
      updated: 0,
      expired: 0,
      errors: []
    };

    const now = new Date();
    
    try {
      // Process each CSV row
      // Parse dates with multiple format support  
      const parseFlexibleDate = (dateStr: string): Date | null => {
        // Remove any extra whitespace and handle empty/undefined values
        if (!dateStr || typeof dateStr !== 'string') {
          return null;
        }
        
        const cleanStr = dateStr.trim();
        if (!cleanStr) {
          return null;
        }
        
        // Helper function to validate and create date
        const createValidDate = (year: number, month: number, day: number): Date | null => {
          // Validate ranges
          if (year < 1900 || year > 2100) return null;
          if (month < 1 || month > 12) return null;
          if (day < 1 || day > 31) return null;
          
          // Create date and validate it's actually valid
          const date = new Date(`${year}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`);
          
          // Check if the date is valid and matches what we expect
          if (isNaN(date.getTime()) || 
              date.getFullYear() !== year || 
              date.getMonth() + 1 !== month || 
              date.getDate() !== day) {
            return null;
          }
          
          return date;
        };
        
        // Try YYYY-MM-DD format first (ISO format)
        const isoMatch = cleanStr.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
        if (isoMatch) {
          const [, year, month, day] = isoMatch;
          return createValidDate(parseInt(year), parseInt(month), parseInt(day));
        }
        
        // Try DD/MM/YYYY and MM/DD/YYYY formats (both use same pattern)
        const slashFormat = cleanStr.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
        if (slashFormat) {
          const [, first, second, year] = slashFormat;
          const firstNum = parseInt(first);
          const secondNum = parseInt(second);
          
          // If first number > 12, it must be DD/MM/YYYY
          if (firstNum > 12) {
            return createValidDate(parseInt(year), secondNum, firstNum);
          }
          
          // If second number > 12, it must be MM/DD/YYYY  
          if (secondNum > 12) {
            return createValidDate(parseInt(year), firstNum, secondNum);
          }
          
          // Ambiguous case: both numbers ≤ 12
          // Try DD/MM/YYYY first (more common internationally), then MM/DD/YYYY
          let date = createValidDate(parseInt(year), secondNum, firstNum);
          if (date) {
            return date;
          }
          
          date = createValidDate(parseInt(year), firstNum, secondNum);
          if (date) {
            return date;
          }
        }
        
        // Try DD-MM-YYYY and MM-DD-YYYY formats (both use same pattern)
        const dashFormat = cleanStr.match(/^(\d{1,2})-(\d{1,2})-(\d{4})$/);
        if (dashFormat) {
          const [, first, second, year] = dashFormat;
          const firstNum = parseInt(first);
          const secondNum = parseInt(second);
          
          // If first number > 12, it must be DD-MM-YYYY
          if (firstNum > 12) {
            return createValidDate(parseInt(year), secondNum, firstNum);
          }
          
          // If second number > 12, it must be MM-DD-YYYY
          if (secondNum > 12) {
            return createValidDate(parseInt(year), firstNum, secondNum);
          }
          
          // Ambiguous case: both numbers ≤ 12
          // Try DD-MM-YYYY first (more common internationally), then MM-DD-YYYY
          let date = createValidDate(parseInt(year), secondNum, firstNum);
          if (date) {
            return date;
          }
          
          date = createValidDate(parseInt(year), firstNum, secondNum);
          if (date) {
            return date;
          }
        }
        
        // Fall back to native Date parsing with validation
        const fallback = new Date(cleanStr);
        if (isNaN(fallback.getTime())) {
          return null;
        }
        
        // Additional validation for native parsing
        try {
          fallback.toISOString(); // This will throw if the date is invalid
          return fallback;
        } catch {
          return null;
        }
      }

      for (let i = 0; i < csvData.length; i++) {
        const row = csvData[i];
        const rowNumber = i + 2; // +2 because CSV has header row and arrays are 0-indexed
        
        try {
          // Validate row using Zod schema - skip Zod validation for now to use our flexible parsing
          // const validationResult = csvStudentRowSchema.safeParse(row);
          // if (!validationResult.success) {
          //   const errorDetails = validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
          //   summary.errors.push(`Row ${rowNumber}: Validation failed - ${errorDetails}`);
          //   continue;
          // }

          // Find university by code or name (flexible matching)
          let universityResult = await db.select().from(universities).where(eq(universities.code, row.university)).limit(1);
          
          // If not found by code, try to find by name
          if (universityResult.length === 0) {
            universityResult = await db.select().from(universities).where(eq(universities.name, row.university)).limit(1);
          }
          
          // If still not found, try partial matching
          if (universityResult.length === 0) {
            // Try code that starts with the provided value
            universityResult = await db.select().from(universities).where(sql`${universities.code} LIKE ${row.university + '%'}`).limit(1);
          }
          
          // If still not found, try name that contains the provided value
          if (universityResult.length === 0) {
            universityResult = await db.select().from(universities).where(sql`${universities.name} ILIKE ${'%' + row.university + '%'}`).limit(1);
          }
          
          if (universityResult.length === 0) {
            summary.errors.push(`Row ${rowNumber}: University '${row.university}' not found (tried code, name, and partial matching)`);
            continue;
          }
          const university = universityResult[0];

          // Note: This endpoint is restricted to admin role only
          // Future enhancement: Add university-role support with proper tenant isolation
          // when accounts.university_id field is implemented

          const validFrom = parseFlexibleDate(row.valid_from);
          const validUntil = parseFlexibleDate(row.valid_until);
          
          if (!validFrom || !validUntil) {
            const invalidFields = [];
            if (!validFrom) invalidFields.push(`valid_from: '${row.valid_from}'`);
            if (!validUntil) invalidFields.push(`valid_until: '${row.valid_until}'`);
            summary.errors.push(`Row ${rowNumber}: Invalid date format for ${invalidFields.join(', ')}. Expected YYYY-MM-DD, MM/DD/YYYY, or DD/MM/YYYY`);
            continue;
          }

          // Check if student ID already exists in this university (prevent duplicates)
          const existingStudentResult = await db.select().from(students)
            .where(and(eq(students.university_id, university.id), eq(students.student_id, row.student_id)))
            .limit(1);

          if (existingStudentResult.length > 0) {
            summary.errors.push(`Row ${rowNumber}: Student ID '${row.student_id}' already exists in university '${university.name}'. Duplicate student IDs are not allowed within the same university.`);
            continue;
          }

          const isExpired = validUntil < now;
          
          // Create new student
          const newStudent: NewStudent = {
            university_id: university.id,
            student_id: row.student_id,
            first_name: row.first_name,
            last_name: row.last_name,
            email: row.email,
            phone: row.phone || undefined,
            valid_from: validFrom.toISOString().split('T')[0],
            valid_until: validUntil.toISOString().split('T')[0],
            status: isExpired ? 'expired' : 'active'
          };

          await db.insert(students).values(newStudent);

          if (isExpired) {
            summary.expired++;
          } else {
            summary.created++;
          }
        } catch (error) {
          console.error(`Error processing row ${rowNumber}:`, error);
          summary.errors.push(`Row ${rowNumber}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }

      return summary;
    } catch (error) {
      console.error("Error importing students:", error);
      throw error;
    }
  }

  // Business methods implementation
  async getBusinesses(filters: BusinessFilters): Promise<PaginatedBusinesses> {
    if (!db) throw new Error("Database not available");
    try {
      const { page = 1, limit = 20, search, category, verified } = filters;
      const offset = (page - 1) * limit;

      let query = db.select().from(businesses);
      let countQuery = db.select({ count: sql`count(*)` }).from(businesses);

      const conditions: any[] = [];

      if (search) {
        const searchCondition = or(
          ilike(businesses.name, `%${search}%`),
          ilike(businesses.contact_email, `%${search}%`),
          ilike(businesses.owner_name, `%${search}%`)
        );
        conditions.push(searchCondition);
      }

      if (category) {
        conditions.push(eq(businesses.category, category as any));
      }

      if (verified !== undefined) {
        conditions.push(eq(businesses.verified, verified));
      }

      if (conditions.length > 0) {
        const whereCondition = and(...conditions);
        query = query.where(whereCondition);
        countQuery = countQuery.where(whereCondition);
      }

      const [data, countResult] = await Promise.all([
        query.limit(limit).offset(offset).orderBy(desc(businesses.created_at)),
        countQuery
      ]);

      const total = Number(countResult[0]?.count) || 0;
      const totalPages = Math.ceil(total / limit);

      return {
        data,
        pagination: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      console.error("Error getting businesses:", error);
      throw new Error("Failed to get businesses");
    }
  }

  async getBusinessById(id: string): Promise<Business | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(businesses).where(eq(businesses.id, id)).limit(1);
      return result[0] || undefined;
    } catch (error) {
      console.error("Error getting business by ID:", error);
      return undefined;
    }
  }

  async getBusinessByEmail(email: string): Promise<Business | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.select().from(businesses).where(eq(businesses.contact_email, email)).limit(1);
      return result[0] || undefined;
    } catch (error) {
      console.error("Error getting business by email:", error);
      return undefined;
    }
  }

  async createBusiness(business: NewBusiness): Promise<Business> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.insert(businesses).values(business).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating business:", error);
      throw new Error("Failed to create business");
    }
  }

  async updateBusiness(id: string, updates: Partial<NewBusiness>): Promise<Business | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.update(businesses)
        .set({ ...updates, updated_at: new Date() })
        .where(eq(businesses.id, id))
        .returning();
      return result[0] || undefined;
    } catch (error) {
      console.error("Error updating business:", error);
      return undefined;
    }
  }

  async deleteBusiness(id: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.delete(businesses).where(eq(businesses.id, id)).returning();
      return result.length > 0;
    } catch (error) {
      console.error("Error deleting business:", error);
      return false;
    }
  }

  async createDiscount(discount: NewDiscount): Promise<Discount> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.insert(discounts).values(discount).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating discount:", error);
      throw new Error("Failed to create discount");
    }
  }

  async updateDiscount(id: string, updates: Partial<NewDiscount>): Promise<Discount | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.update(discounts)
        .set({ ...updates, updated_at: new Date() })
        .where(eq(discounts.id, id))
        .returning();
      return result[0] || undefined;
    } catch (error) {
      console.error("Error updating discount:", error);
      return undefined;
    }
  }

  async deleteDiscount(id: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.delete(discounts).where(eq(discounts.id, id)).returning();
      return result.length > 0;
    } catch (error: any) {
      console.error("Error deleting discount:", error);
      
      // Check for foreign key constraint violation
      if (error.code === '23503' && error.constraint && error.constraint.includes('redemptions_discount_id')) {
        throw new Error('CONSTRAINT_VIOLATION: Cannot delete discount because it has been redeemed by students');
      }
      
      // Check for other constraint violations
      if (error.code === '23503') {
        throw new Error('CONSTRAINT_VIOLATION: Cannot delete discount due to existing references');
      }
      
      // Check if discount doesn't exist
      if (error.code === 'P0001' || error.message?.includes('not found')) {
        throw new Error('NOT_FOUND: Discount not found');
      }
      
      // Re-throw other database errors with a generic message
      throw new Error(`DATABASE_ERROR: Failed to delete discount - ${error.message || 'Unknown database error'}`);
    }
  }

  async createDiscountCategory(category: NewDiscountCategory): Promise<DiscountCategory> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.insert(discount_categories).values(category).returning();
      return result[0];
    } catch (error) {
      console.error("Error creating discount category:", error);
      throw new Error("Failed to create discount category");
    }
  }

  async updateDiscountCategory(id: string, updates: Partial<NewDiscountCategory>): Promise<DiscountCategory | undefined> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.update(discount_categories)
        .set(updates)
        .where(eq(discount_categories.id, id))
        .returning();
      return result[0] || undefined;
    } catch (error) {
      console.error("Error updating discount category:", error);
      throw new Error("Failed to update discount category");
    }
  }

  async deleteDiscountCategory(id: string): Promise<boolean> {
    if (!db) throw new Error("Database not available");
    try {
      const result = await db.delete(discount_categories)
        .where(eq(discount_categories.id, id))
        .returning();
      return result.length > 0;
    } catch (error: any) {
      console.error("Error deleting discount category:", error);
      
      // Check for foreign key constraint violation
      if (error.code === '23503' && error.constraint && error.constraint.includes('discounts_category_id')) {
        throw new Error('CONSTRAINT_VIOLATION: Cannot delete category because it is being used by existing discounts');
      }
      
      // Check for other constraint violations
      if (error.code === '23503') {
        throw new Error('CONSTRAINT_VIOLATION: Cannot delete category due to existing references');
      }
      
      // Check if category doesn't exist
      if (error.code === 'P0001' || error.message?.includes('not found')) {
        throw new Error('NOT_FOUND: Category not found');
      }
      
      // Re-throw other database errors with a generic message
      throw new Error(`DATABASE_ERROR: Failed to delete category - ${error.message || 'Unknown database error'}`);
    }
  }
}

export class MemStorage implements IStorage {
  private accounts: Map<string, Account>;

  constructor() {
    this.accounts = new Map();
  }

  async getAccount(id: string): Promise<Account | undefined> {
    return this.accounts.get(id);
  }

  async getAccountByEmail(email: string): Promise<Account | undefined> {
    return Array.from(this.accounts.values()).find(
      (account) => account.email === email,
    );
  }

  async createAccount(insertAccount: NewAccount): Promise<Account> {
    const id = randomUUID();
    const now = new Date();
    const hashedPassword = await this.hashPassword(insertAccount.password_hash);
    const account: Account = { 
      id: id as any, 
      student_id: insertAccount.student_id || null,
      business_id: insertAccount.business_id || null,
      role: insertAccount.role,
      email: insertAccount.email,
      password_hash: hashedPassword,
      last_login_at: null,
      created_at: now as any,
      updated_at: now as any
    };
    this.accounts.set(id, account);
    return account;
  }

  async verifyPassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    try {
      return await argon2.verify(hashedPassword, plainPassword);
    } catch (error) {
      console.error("Error verifying password:", error);
      return false;
    }
  }

  async hashPassword(plainPassword: string): Promise<string> {
    try {
      return await argon2.hash(plainPassword, {
        type: argon2.argon2id,
        memoryCost: 19456, // 19 MiB in KB
        timeCost: 2,       // 2 iterations
        parallelism: 1,    // 1 thread
      });
    } catch (error) {
      console.error("Error hashing password:", error);
      throw error;
    }
  }

  async getAllAccounts(): Promise<Account[]> {
    return Array.from(this.accounts.values());
  }

  async updateAccount(id: string, updates: Partial<NewAccount>): Promise<Account | undefined> {
    const account = this.accounts.get(id);
    if (!account) return undefined;

    const updateData: any = { ...updates };
    if (updates.password_hash) {
      updateData.password_hash = await this.hashPassword(updates.password_hash);
    }

    const updatedAccount: Account = {
      ...account,
      ...updateData,
      updated_at: new Date(),
    };
    this.accounts.set(id, updatedAccount);
    return updatedAccount;
  }

  async deleteAccount(id: string): Promise<boolean> {
    return this.accounts.delete(id);
  }

  async storeQRToken(studentId: string, token: string, expiresAt: Date): Promise<void> {
    throw new Error('MemStorage does not support QR token functionality - database required');
  }

  async isQRTokenConsumed(token: string): Promise<boolean> {
    throw new Error('MemStorage does not support QR token functionality - database required');
  }

  async markQRTokenConsumed(token: string): Promise<void> {
    throw new Error('MemStorage does not support QR token functionality - database required');
  }

  async atomicConsumeQRToken(token: string): Promise<{ consumed: boolean; consumedAt?: Date; withinIdempotencyWindow?: boolean }> {
    throw new Error('MemStorage does not support QR token functionality - database required');
  }

  async atomicConsumeQRTokenWithRedemption(
    token: string, 
    redemptionData?: NewRedemption
  ): Promise<{ 
    consumed: boolean; 
    consumedAt?: Date; 
    withinIdempotencyWindow?: boolean;
    redemption?: Redemption;
    redemptionCreated: boolean;
    firstConsumption: boolean;
    expired?: boolean;
    error?: string;
  }> {
    throw new Error('MemStorage does not support QR token functionality - database required');
  }

  async getStudentById(studentId: string): Promise<Student | undefined> {
    throw new Error('MemStorage does not support student lookup - database required');
  }

  async getStudents(params: { page?: number; limit?: number; search?: string; university_id?: string; status?: string }): Promise<{ data: Student[]; pagination: { page: number; limit: number; total: number; totalPages: number } }> {
    return {
      data: [],
      pagination: { page: 1, limit: 20, total: 0, totalPages: 0 }
    };
  }

  async updateStudent(studentId: string, data: Partial<Student>): Promise<Student> {
    throw new Error('MemStorage does not support student updates - database required');
  }

  async updateStudentStatus(studentId: string, status: Student['status']): Promise<Student> {
    throw new Error('MemStorage does not support student status updates - database required');
  }

  async deleteStudent(studentId: string): Promise<boolean> {
    throw new Error('MemStorage does not support student deletion - database required');
  }

  async verifyQRToken(studentId: string, discountId?: string): Promise<QRVerificationResult> {
    return { isValid: false, error: 'MemStorage does not support QR token verification - database required' };
  }

  async createRedemption(redemption: NewRedemption): Promise<Redemption> {
    throw new Error('MemStorage does not support redemption creation - database required');
  }

  async getDiscounts(filters: DiscountFilters): Promise<PaginatedDiscounts> {
    throw new Error('MemStorage does not support discount queries - database required');
  }

  async getDiscountById(id: string): Promise<Discount | undefined> {
    throw new Error('MemStorage does not support discount queries - database required');
  }

  async getCategories(search?: string): Promise<DiscountCategory[]> {
    throw new Error('MemStorage does not support category queries - database required');
  }

  async createRedemptionFromToken(studentToken: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption> {
    throw new Error('MemStorage does not support redemption creation - database required');
  }

  async createRedemptionFromStudentId(studentId: string, discountId: string, businessId: string, verifierAccountId: string): Promise<Redemption> {
    throw new Error('MemStorage does not support redemption creation - database required');
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SelectSecurityEvent> {
    throw new Error('MemStorage does not support security event logging - database required');
  }

  async importStudents(csvData: CSVStudentRow[], requestingUser: Account): Promise<ImportSummary> {
    // For MemStorage, we'll just return a mock summary since we don't have actual database functionality
    // This is primarily for development/testing when DB is not available
    return {
      created: 0,
      updated: 0,
      expired: 0,
      errors: ['MemStorage does not support student import functionality - database required']
    };
  }

  // Business methods - throw errors for MemStorage
  async getBusinesses(filters: BusinessFilters): Promise<PaginatedBusinesses> {
    throw new Error('MemStorage does not support business queries - database required');
  }

  async getBusinessById(id: string): Promise<Business | undefined> {
    throw new Error('MemStorage does not support business queries - database required');
  }

  async getBusinessByEmail(email: string): Promise<Business | undefined> {
    throw new Error('MemStorage does not support business queries - database required');
  }

  async createBusiness(business: NewBusiness): Promise<Business> {
    throw new Error('MemStorage does not support business creation - database required');
  }

  async updateBusiness(id: string, updates: Partial<NewBusiness>): Promise<Business | undefined> {
    throw new Error('MemStorage does not support business updates - database required');
  }

  async deleteBusiness(id: string): Promise<boolean> {
    throw new Error('MemStorage does not support business deletion - database required');
  }

  async createDiscount(discount: NewDiscount): Promise<Discount> {
    throw new Error('MemStorage does not support discount creation - database required');
  }

  async updateDiscount(id: string, updates: Partial<NewDiscount>): Promise<Discount | undefined> {
    throw new Error('MemStorage does not support discount updates - database required');
  }

  async deleteDiscount(id: string): Promise<boolean> {
    throw new Error('MemStorage does not support discount deletion - database required');
  }

  async createDiscountCategory(category: NewDiscountCategory): Promise<DiscountCategory> {
    throw new Error('MemStorage does not support discount category creation - database required');
  }

  async updateDiscountCategory(id: string, updates: Partial<NewDiscountCategory>): Promise<DiscountCategory | undefined> {
    throw new Error('MemStorage does not support discount category updates - database required');
  }

  async deleteDiscountCategory(id: string): Promise<boolean> {
    throw new Error('MemStorage does not support discount category deletion - database required');
  }

  // University methods - throw errors for MemStorage
  async getUniversities(params?: { page?: number; limit?: number; search?: string }): Promise<{ data: University[]; pagination: { page: number; limit: number; total: number; totalPages: number } }> {
    throw new Error('MemStorage does not support university queries - database required');
  }

  async getUniversityById(id: string): Promise<University | undefined> {
    throw new Error('MemStorage does not support university queries - database required');
  }

  async getUniversityByCode(code: string): Promise<University | undefined> {
    throw new Error('MemStorage does not support university queries - database required');
  }

  async createUniversity(university: NewUniversity): Promise<University> {
    throw new Error('MemStorage does not support university creation - database required');
  }

  async updateUniversity(id: string, updates: Partial<NewUniversity>): Promise<University | undefined> {
    throw new Error('MemStorage does not support university updates - database required');
  }

  async deleteUniversity(id: string): Promise<boolean> {
    throw new Error('MemStorage does not support university deletion - database required');
  }
}

// Initialize storage based on database availability
export const storage: IStorage = db ? new DatabaseStorage() : new MemStorage();

// Log the storage type being used
console.log(`📦 Storage initialized: ${db ? 'DatabaseStorage (PostgreSQL)' : 'MemStorage (in-memory)'}`);

// Classes are already exported in their declarations above