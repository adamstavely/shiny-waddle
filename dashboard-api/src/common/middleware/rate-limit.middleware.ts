import { Injectable, NestMiddleware, HttpException, HttpStatus } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';
import { roleBasedRateLimits, endpointRateLimits } from '../config/rate-limit.config';
import { UserRole } from '../../security/guards/access-control.guard';

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

@Injectable()
export class RateLimitMiddleware implements NestMiddleware {
  private store: RateLimitStore = {};

  use(req: Request, res: Response, next: NextFunction) {
    const key = this.getRateLimitKey(req);
    const limit = this.getRateLimit(req);
    
    const now = Date.now();
    const record = this.store[key];

    // Clean up expired entries periodically
    if (Math.random() < 0.01) { // 1% chance to cleanup
      this.cleanup();
    }

    if (!record || record.resetTime < now) {
      // New or expired entry
      this.store[key] = {
        count: 1,
        resetTime: now + limit.ttl * 1000,
      };
      this.setRateLimitHeaders(res, limit.limit, 1, limit.ttl);
      return next();
    }

    if (record.count >= limit.limit) {
      // Rate limit exceeded
      this.setRateLimitHeaders(res, limit.limit, record.count, Math.ceil((record.resetTime - now) / 1000));
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message: 'Rate limit exceeded. Please try again later.',
          error: 'Too Many Requests',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // Increment count
    record.count++;
    this.setRateLimitHeaders(res, limit.limit, record.count, Math.ceil((record.resetTime - now) / 1000));
    next();
  }

  private getRateLimitKey(req: Request): string {
    const user = (req as any).user;
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    
    if (user?.id) {
      return `user:${user.id}`;
    }
    return `ip:${ip}`;
  }

  private getRateLimit(req: Request): { limit: number; ttl: number } {
    const path = req.path;
    const method = req.method;
    const endpointKey = `${path}:${method}`;

    // Check endpoint-specific limits first
    if (endpointRateLimits[endpointKey]) {
      return endpointRateLimits[endpointKey];
    }
    if (endpointRateLimits[path]) {
      return endpointRateLimits[path];
    }

    // Check role-based limits
    const user = (req as any).user;
    if (user?.role) {
      const roleLimit = roleBasedRateLimits[user.role as UserRole];
      if (roleLimit) {
        return roleLimit;
      }
    }

    // Default limit
    return roleBasedRateLimits.default;
  }

  private setRateLimitHeaders(
    res: Response,
    limit: number,
    remaining: number,
    reset: number,
  ): void {
    res.setHeader('X-RateLimit-Limit', limit.toString());
    res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - remaining).toString());
    res.setHeader('X-RateLimit-Reset', new Date(Date.now() + reset * 1000).toISOString());
  }

  private cleanup(): void {
    const now = Date.now();
    for (const key in this.store) {
      if (this.store[key].resetTime < now) {
        delete this.store[key];
      }
    }
  }
}

