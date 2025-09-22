import cors from 'cors';
import env from '../config/env';
import { logger } from './logging';

/**
 * Parse CORS origins from environment variable
 */
const getAllowedOrigins = (): (string | RegExp)[] => {
  const origins: (string | RegExp)[] = env.CORS_ORIGINS.split(',').map(origin => origin.trim());
  
  // In development, allow common Expo and localhost patterns
  if (env.NODE_ENV === 'development') {
    const devOrigins: (string | RegExp)[] = [
      'http://localhost:3000',
      'http://localhost:5000',
      'http://localhost:8081',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5000',
      'http://127.0.0.1:8081',
      // Expo development origins
      /^exp:\/\/192\.168\.\d+\.\d+:\d+$/,
      /^exp:\/\/10\.\d+\.\d+\.\d+:\d+$/,
      /^http:\/\/192\.168\.\d+\.\d+:\d+$/,
      /^http:\/\/10\.\d+\.\d+\.\d+:\d+$/,
      // Allow Replit development origins
      /^https:\/\/.*\.replit\.dev$/,
      /^https:\/\/.*\.janeway\.replit\.dev$/,
    ];
    
    origins.push(...devOrigins);
  }
  
  return origins;
};

/**
 * CORS configuration with strict origin validation
 */
export const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowedOrigins = getAllowedOrigins();
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check each allowed origin (string or regex)
    for (const allowedOrigin of allowedOrigins) {
      if (typeof allowedOrigin === 'string') {
        if (allowedOrigin === origin) {
          return callback(null, true);
        }
      } else if (allowedOrigin instanceof RegExp) {
        if (allowedOrigin.test(origin)) {
          return callback(null, true);
        }
      }
    }
    
    // Log blocked origin for security monitoring (only in production)
    if (env.NODE_ENV === 'production') {
      logger.warn({
        origin,
        allowedOrigins: allowedOrigins.filter(o => typeof o === 'string')
      }, 'CORS: Blocked origin');
    }
    
    const error = new Error(`CORS: Origin ${origin} not allowed`);
    callback(error, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'X-API-Key'
  ],
  exposedHeaders: ['X-Total-Count', 'X-Page-Count'],
  maxAge: 86400, // 24 hours
  optionsSuccessStatus: 200
};

/**
 * CORS middleware with logging
 */
export const corsMiddleware = cors(corsOptions);