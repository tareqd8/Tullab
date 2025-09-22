#!/usr/bin/env node

/**
 * CLI Student Import Tool for Tullab
 * 
 * Usage:
 *   node scripts/import-students.js <csv-file> <admin-email> <admin-password> [server-url]
 * 
 * Note: This requires admin credentials. University users cannot import students directly.
 * 
 * Example:
 *   node scripts/import-students.js students.csv admin@tullab.com adminpassword http://localhost:5000
 */

const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const axios = require('axios');

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length < 3) {
    console.error('Usage: node import-students.js <csv-file> <admin-email> <admin-password> [server-url]');
    console.error('');
    console.error('Arguments:');
    console.error('  csv-file        Path to the CSV file to import');
    console.error('  admin-email     Email of admin or university account');
    console.error('  admin-password  Password for the account');
    console.error('  server-url      Optional. Server URL (default: http://localhost:5000)');
    console.error('');
    console.error('Example:');
    console.error('  node scripts/import-students.js students.csv admin@tullab.com password123');
    process.exit(1);
  }

  const [csvFile, adminEmail, adminPassword, serverUrl = 'http://localhost:5000'] = args;

  // Check if CSV file exists
  if (!fs.existsSync(csvFile)) {
    console.error(`❌ Error: CSV file '${csvFile}' not found`);
    process.exit(1);
  }

  console.log('🚀 Tullab Student Import Tool');
  console.log('==============================');
  console.log(`📁 CSV File: ${csvFile}`);
  console.log(`👤 Admin Email: ${adminEmail}`);
  console.log(`🌐 Server: ${serverUrl}`);
  console.log('');

  try {
    // Step 1: Login to get access token
    console.log('🔐 Authenticating...');
    const loginResponse = await axios.post(`${serverUrl}/api/auth/login`, {
      email: adminEmail,
      password: adminPassword
    });

    if (!loginResponse.data.data || !loginResponse.data.data.accessToken) {
      throw new Error('Login failed - no access token received');
    }

    const token = loginResponse.data.data.accessToken;
    console.log('✅ Authentication successful');

    // Step 2: Read and upload CSV file
    console.log('📤 Uploading CSV file...');
    const formData = new FormData();
    formData.append('csv', fs.createReadStream(csvFile));

    const uploadResponse = await axios.post(
      `${serverUrl}/api/admin/import-students`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
          'Authorization': `Bearer ${token}`
        },
        maxContentLength: Infinity,
        maxBodyLength: Infinity
      }
    );

    console.log('✅ Import completed successfully');
    console.log('');

    // Step 3: Display results
    const summary = uploadResponse.data.summary;
    console.log('📊 Import Summary:');
    console.log('==================');
    console.log(`✨ Created: ${summary.created} students`);
    console.log(`🔄 Updated: ${summary.updated} students`);
    console.log(`⏰ Expired: ${summary.expired} students`);
    console.log(`❌ Errors: ${summary.errors.length}`);

    if (summary.errors.length > 0) {
      console.log('');
      console.log('⚠️  Import Errors:');
      summary.errors.forEach((error, index) => {
        console.log(`   ${index + 1}. ${error}`);
      });
    }

    console.log('');
    console.log('🎉 Student import process completed!');

  } catch (error) {
    console.error('');
    console.error('❌ Import failed:');
    
    if (error.response) {
      // Server responded with error
      console.error(`   Status: ${error.response.status}`);
      console.error(`   Message: ${error.response.data.message || error.response.data.error || 'Unknown error'}`);
      
      if (error.response.data.details) {
        console.error(`   Details: ${JSON.stringify(error.response.data.details, null, 2)}`);
      }
    } else if (error.request) {
      // Request was made but no response received
      console.error('   No response from server. Check if the server is running.');
    } else {
      // Something else happened
      console.error(`   ${error.message}`);
    }
    
    process.exit(1);
  }
}

// Handle process termination gracefully
process.on('SIGINT', () => {
  console.log('\n👋 Import cancelled by user');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n👋 Import terminated');
  process.exit(0);
});

main().catch(error => {
  console.error('\n💥 Unexpected error:', error.message);
  process.exit(1);
});