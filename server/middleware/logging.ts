import pino from 'pino';
import { pinoHttp } from 'pino-http';
import type { Request, Response } from 'express';
import env from '../config/env';

/**
 * Create base logger with PII redaction
 */
export const logger = pino({
  level: env.LOG_LEVEL,
  redact: {
    paths: [
      // Redact sensitive authentication data
      'req.headers.authorization',
      'req.headers.cookie',
      'req.body.password',
      'req.body.current_password',
      'req.body.new_password',
      
      // Redact student PII in logs
      'req.body.first_name',
      'req.body.last_name',
      'req.body.email',
      'req.body.phone',
      'res.body.first_name',
      'res.body.last_name',
      'res.body.email', 
      'res.body.phone',
      'res.body.*.first_name',
      'res.body.*.last_name',
      'res.body.*.email',
      'res.body.*.phone',
      
      // Redact JWT tokens
      'req.body.token',
      'req.body.refresh_token',
      'res.body.token',
      'res.body.access_token',
      'res.body.refresh_token',
      
      // Redact database credentials
      'DATABASE_URL',
      'JWT_SECRET',
      'JWT_REFRESH_SECRET',
      'SESSION_SECRET'
    ],
    censor: '[REDACTED]'
  },
  serializers: {
    req: (req: Request) => ({
      method: req.method,
      url: req.url,
      user: req.user ? { id: req.user.id, role: req.user.role } : undefined,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }),
    res: (res: Response) => ({
      statusCode: res.statusCode,
      responseTime: res.get('X-Response-Time')
    })
  },
  formatters: {
    level: (label) => {
      return { level: label };
    }
  }
});

/**
 * HTTP request logging middleware with PII redaction
 */
export const httpLogger = pinoHttp({
  logger,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.body.password',
      'req.body.current_password', 
      'req.body.new_password',
      'req.body.first_name',
      'req.body.last_name',
      'req.body.email',
      'req.body.phone'
    ],
    censor: '[REDACTED]'
  },
  customLogLevel: function (req, res, err) {
    if (res.statusCode >= 400 && res.statusCode < 500) {
      return 'warn';
    } else if (res.statusCode >= 500 || err) {
      return 'error';
    } else if (res.statusCode >= 300 && res.statusCode < 400) {
      return 'silent';
    }
    return 'info';
  },
  customSuccessMessage: function (req, res) {
    if (res.statusCode === 404) {
      return 'resource not found';
    }
    return `${req.method} completed`;
  },
  customErrorMessage: function (req, res, err) {
    return `${req.method} request errored with status code: ${res.statusCode}`;
  }
});

/**
 * Security-focused logger that redacts all PII and tokens
 */
export const securityLogger = logger.child({
  component: 'security'
});

/**
 * Audit logger for compliance tracking
 */
export const auditLogger = logger.child({
  component: 'audit'
});