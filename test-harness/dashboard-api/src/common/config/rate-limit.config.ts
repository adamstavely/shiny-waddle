import { ThrottlerModuleOptions } from '@nestjs/throttler';
import { UserRole } from '../../security/guards/access-control.guard';

export interface RoleBasedRateLimit {
  [key: string]: {
    limit: number;
    ttl: number; // Time to live in seconds
  };
}

// Role-based rate limits (requests per TTL period)
export const roleBasedRateLimits: RoleBasedRateLimit = {
  [UserRole.ADMIN]: {
    limit: 1000, // 1000 requests
    ttl: 60, // per minute
  },
  [UserRole.EDITOR]: {
    limit: 500, // 500 requests
    ttl: 60, // per minute
  },
  [UserRole.VIEWER]: {
    limit: 200, // 200 requests
    ttl: 60, // per minute
  },
  [UserRole.AUDITOR]: {
    limit: 300, // 300 requests
    ttl: 60, // per minute
  },
  [UserRole.DATA_STEWARD]: {
    limit: 400, // 400 requests
    ttl: 60, // per minute
  },
  [UserRole.CYBER_RISK_MANAGER]: {
    limit: 400, // 400 requests
    ttl: 60, // per minute
  },
  default: {
    limit: 100, // 100 requests for unauthenticated users
    ttl: 60, // per minute
  },
};

// Endpoint-specific rate limits (overrides role-based limits)
export const endpointRateLimits: Record<string, { limit: number; ttl: number }> = {
  '/api/v1/auth/login': {
    limit: 5, // 5 login attempts
    ttl: 60, // per minute (to prevent brute force)
  },
  '/api/v1/auth/register': {
    limit: 3, // 3 registrations
    ttl: 3600, // per hour
  },
  '/api/v1/auth/login:POST': {
    limit: 5,
    ttl: 60,
  },
  '/api/v1/auth/register:POST': {
    limit: 3,
    ttl: 3600,
  },
};

export const defaultRateLimitConfig: ThrottlerModuleOptions = {
  throttlers: [
    {
      name: 'default',
      ttl: 60000, // 1 minute in milliseconds
      limit: 100, // 100 requests per minute for unauthenticated
    },
  ],
};

