import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as sanitizeHtml from 'sanitize-html';
import validator from 'validator';

@Injectable()
export class SanitizeMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Sanitize query parameters
    if (req.query) {
      req.query = this.sanitizeObject(req.query);
    }

    // Sanitize body parameters
    if (req.body && typeof req.body === 'object') {
      req.body = this.sanitizeObject(req.body);
    }

    // Sanitize route parameters
    if (req.params) {
      req.params = this.sanitizeObject(req.params);
    }

    next();
  }

  private sanitizeObject(obj: any): any {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          // Sanitize key (prevent prototype pollution)
          const sanitizedKey = this.sanitizeString(key);
          sanitized[sanitizedKey] = this.sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }

    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    return obj;
  }

  private sanitizeString(str: string): string {
    if (!str || typeof str !== 'string') {
      return str;
    }

    // Remove SQL injection patterns
    let sanitized = str
      .replace(/('|(\\')|(;)|(\\)|(\/\*)|(\*\/)|(\-\-)|(\+)|(\%)|(\=)|(\>)|(\<)|(\!)|(\@)|(\#)|(\$)|(\^)|(\&)|(\*)|(\()|(\))|(\[)|(\])|(\{)|(\})|(\|)|(\\)|(\~)|(\`)|(\?)|(\:)|(\;)|(\")|(\')/gi, '');

    // Remove XSS patterns
    sanitized = sanitizeHtml(sanitized, {
      allowedTags: [], // No HTML tags allowed
      allowedAttributes: {},
    });

    // Escape special characters
    sanitized = validator.escape(sanitized);

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Trim whitespace
    sanitized = sanitized.trim();

    return sanitized;
  }
}

