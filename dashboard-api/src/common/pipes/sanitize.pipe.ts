import { PipeTransform, Injectable, ArgumentMetadata } from '@nestjs/common';
import * as sanitizeHtml from 'sanitize-html';
import validator from 'validator';

@Injectable()
export class SanitizePipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    if (this.isPrimitive(value)) {
      return value;
    }

    return this.sanitizeObject(value);
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
      .replace(/[;\\\/\*\+\%\=\>\<\!\@\#\$\^\&\*\(\)\[\]\{\}\~\`\?\:\"\'\-]/gi, '');

    // Remove XSS patterns
    sanitized = sanitizeHtml(sanitized, {
      allowedTags: [],
      allowedAttributes: {},
    });

    // Escape special characters
    sanitized = validator.escape(sanitized);

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    return sanitized.trim();
  }

  private isPrimitive(value: any): boolean {
    return value === null || 
           value === undefined || 
           typeof value === 'boolean' || 
           typeof value === 'number' || 
           (typeof value === 'string' && value.length === 0);
  }
}

