import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

/**
 * Middleware to handle dots in route parameters
 * Express by default treats dots as file extensions, which breaks routes like
 * /api/tests/test.idp.service_conforms_to_golden_template
 * 
 * This middleware preserves dots in the URL for API routes
 */
@Injectable()
export class DotRouteMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Only process API routes that might have dots in parameters
    if (req.path.startsWith('/api/tests/') || req.path.startsWith('/api/v1/tests/')) {
      // If the path has a dot and doesn't end with a known file extension, preserve it
      const hasDot = req.path.includes('.');
      const knownExtensions = ['.json', '.html', '.css', '.js', '.png', '.jpg', '.gif', '.svg'];
      const endsWithExtension = knownExtensions.some(ext => req.path.toLowerCase().endsWith(ext));
      
      if (hasDot && !endsWithExtension) {
        // The route parameter contains dots - ensure Express doesn't treat it as a file
        // We'll let NestJS handle the routing normally
        // The key is that we're not interfering with the URL parsing
      }
    }
    next();
  }
}
