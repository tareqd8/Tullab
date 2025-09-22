import { describe, it, expect, beforeEach, beforeAll, afterAll } from "vitest";
import supertest from "supertest";
import express from "express";
import { registerRoutes } from "./routes";
import { storage } from "./storage";

const app = express();
app.use(express.json());

describe("Student Import API", () => {
  let server: any;
  let request: any;
  let adminToken: string;
  let universityToken: string;
  let studentToken: string;

  beforeAll(async () => {
    server = await registerRoutes(app);
    request = supertest(app);

    // For simplicity, we'll use mock tokens in these tests
    // In a real implementation, you'd create actual test accounts and get real tokens
    adminToken = "mock-admin-token";
    universityToken = "mock-university-token";
    studentToken = "mock-student-token";
  });

  afterAll(async () => {
    if (server && server.close) {
      server.close();
    }
  });

  describe("Authentication and Authorization", () => {
    const validCsv = Buffer.from(
      "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
      "ST001,John Doe,TEST-UNIV,2024-09-01,2025-06-30,john.doe@test.edu,+1-555-0123"
    );

    it("should reject requests without authentication", async () => {
      const response = await request
        .post("/api/university/import-students")
        .attach("csv", validCsv, "students.csv")
        .expect(401);

      expect(response.body.error).toBe("Unauthorized");
    });

    it("should reject requests from student role", async () => {
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${studentToken}`)
        .attach("csv", validCsv, "students.csv")
        .expect(403);

      expect(response.body.error).toBe("Forbidden");
    });

    it("should accept requests from admin role", async () => {
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", validCsv, "students.csv");

      expect(response.status).not.toBe(403);
    });

    it("should accept requests from university role", async () => {
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${universityToken}`)
        .attach("csv", validCsv, "students.csv");

      expect(response.status).not.toBe(403);
    });
  });

  describe("CSV File Validation", () => {
    it("should reject requests without CSV file", async () => {
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .expect(400);

      expect(response.body.message).toBe("CSV file is required");
    });

    it("should reject non-CSV files", async () => {
      const txtFile = Buffer.from("This is not a CSV file");
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", txtFile, "students.txt")
        .expect(400);

      expect(response.body.message).toBe("Only CSV files are allowed");
    });

    it("should reject empty CSV files", async () => {
      const emptyCsv = Buffer.from("");
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", emptyCsv, "students.csv")
        .expect(400);

      expect(response.body.message).toBe("CSV file is empty or has no valid data");
    });

    it("should reject CSV with missing required headers", async () => {
      const invalidCsv = Buffer.from(
        "student_id,first_name,last_name,email\n" +
        "ST001,John Doe,john.doe@test.edu"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", invalidCsv, "students.csv")
        .expect(400);

      expect(response.body.message).toContain("Missing required CSV headers");
      expect(response.body.expected).toEqual([
        "student_id", "first_name", "last_name", "university_code", "valid_from", "valid_until", "email", "phone"
      ]);
    });
  });

  describe("Student Creation", () => {
    it("should create new students successfully", async () => {
      const validCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST001,John Doe,TEST-UNIV,2024-09-01,2025-06-30,john.doe@test.edu,+1-555-0123\n" +
        "ST002,Jane Smith,TEST-UNIV,2024-09-01,2025-06-30,jane.smith@test.edu,+1-555-0124"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", validCsv, "students.csv")
        .expect(200);

      expect(response.body.message).toBe("Students imported successfully");
      expect(response.body.summary.created).toBe(2);
      expect(response.body.summary.updated).toBe(0);
      expect(response.body.summary.expired).toBe(0);
    });

    it("should handle students with missing phone numbers", async () => {
      const validCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST003,Bob Johnson,TEST-UNIV,2024-09-01,2025-06-30,bob.johnson@test.edu,"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", validCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(1);
    });

    it("should mark students as expired when valid_until is in the past", async () => {
      const expiredCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST004,Alice Brown,TEST-UNIV,2023-09-01,2024-06-30,alice.brown@test.edu,+1-555-0125"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", expiredCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(0);
      expect(response.body.summary.expired).toBe(1);
    });
  });

  describe("Student Updates", () => {
    beforeEach(async () => {
      // Create a test student first
      const initialCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST005,Charlie Wilson,TEST-UNIV,2024-09-01,2025-06-30,charlie.wilson@test.edu,+1-555-0126"
      );
      
      await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", initialCsv, "students.csv");
    });

    it("should update existing students", async () => {
      const updateCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST005,Charlie Wilson Jr,TEST-UNIV,2024-09-01,2025-06-30,charlie.wilson.new@test.edu,+1-555-9999"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", updateCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(0);
      expect(response.body.summary.updated).toBe(1);
    });

    it("should expire existing students when valid_until is in the past", async () => {
      const expireCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST005,Charlie Wilson,TEST-UNIV,2023-09-01,2024-06-30,charlie.wilson@test.edu,+1-555-0126"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", expireCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.updated).toBe(0);
      expect(response.body.summary.expired).toBe(1);
    });
  });

  describe("Error Handling", () => {
    it("should handle non-existent university codes", async () => {
      const invalidUniversityCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST006,David Lee,INVALID-UNIV,2024-09-01,2025-06-30,david.lee@test.edu,+1-555-0127"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", invalidUniversityCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(0);
      expect(response.body.summary.errors.length).toBe(1);
      expect(response.body.summary.errors[0]).toContain("University with code 'INVALID-UNIV' not found");
    });

    it("should handle invalid date formats", async () => {
      const invalidDateCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST007,Eva Green,TEST-UNIV,invalid-date,2025-06-30,eva.green@test.edu,+1-555-0128"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", invalidDateCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(0);
      expect(response.body.summary.errors.length).toBe(1);
      expect(response.body.summary.errors[0]).toContain("Invalid date format");
    });

    it("should handle missing required fields", async () => {
      const missingFieldsCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        ",Frank Miller,TEST-UNIV,2024-09-01,2025-06-30,frank.miller@test.edu,+1-555-0129"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", missingFieldsCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(0);
      expect(response.body.summary.errors.length).toBe(1);
      expect(response.body.summary.errors[0]).toContain("Missing required fields");
    });
  });

  describe("Mixed Scenarios", () => {
    it("should handle mixed create/update/error scenarios", async () => {
      // First, create one existing student
      const initialCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST008,Grace Taylor,TEST-UNIV,2024-09-01,2025-06-30,grace.taylor@test.edu,+1-555-0130"
      );
      
      await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", initialCsv, "students.csv");

      // Now import mixed data
      const mixedCsv = Buffer.from(
        "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n" +
        "ST008,Grace Taylor Updated,TEST-UNIV,2024-09-01,2025-06-30,grace.updated@test.edu,+1-555-9999\n" +
        "ST009,Henry Adams,TEST-UNIV,2024-09-01,2025-06-30,henry.adams@test.edu,+1-555-0131\n" +
        "ST010,Ivy Clark,TEST-UNIV,2023-09-01,2024-06-30,ivy.clark@test.edu,+1-555-0132\n" +
        ",Invalid Student,TEST-UNIV,2024-09-01,2025-06-30,invalid@test.edu,+1-555-0133"
      );
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", mixedCsv, "students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(1); // Henry Adams
      expect(response.body.summary.updated).toBe(1); // Grace Taylor Updated
      expect(response.body.summary.expired).toBe(1); // Ivy Clark
      expect(response.body.summary.errors.length).toBe(1); // Invalid Student
    });
  });

  describe("Large File Handling", () => {
    it("should handle files up to 5MB limit", async () => {
      // This would create a large CSV within the 5MB limit
      let largeCsv = "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n";
      
      // Add 1000 student records
      for (let i = 1; i <= 1000; i++) {
        largeCsv += `ST${i.toString().padStart(4, '0')},Student ${i},TEST-UNIV,2024-09-01,2025-06-30,student${i}@test.edu,+1-555-${i.toString().padStart(4, '0')}\n`;
      }
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", Buffer.from(largeCsv), "large-students.csv")
        .expect(200);

      expect(response.body.summary.created).toBe(1000);
    });

    it("should reject files over 5MB limit", async () => {
      // Create a CSV file larger than 5MB
      let hugeCsv = "student_id,first_name,last_name,university_code,valid_from,valid_until,email,phone\n";
      
      // Add enough data to exceed 5MB
      const largeString = "x".repeat(1000); // 1KB of padding per record
      for (let i = 1; i <= 6000; i++) {
        hugeCsv += `ST${i.toString().padStart(4, '0')},Student ${i} ${largeString},TEST-UNIV,2024-09-01,2025-06-30,student${i}@test.edu,+1-555-${i.toString().padStart(4, '0')}\n`;
      }
      
      const response = await request
        .post("/api/university/import-students")
        .set("Authorization", `Bearer ${adminToken}`)
        .attach("csv", Buffer.from(hugeCsv), "huge-students.csv")
        .expect(400);

      expect(response.body.message).toContain("file too large");
    });
  });
});