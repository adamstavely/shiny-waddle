import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class HttpsRedirectMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Only enforce HTTPS in production
    if (process.env.NODE_ENV === 'production') {
      // Check if request is already HTTPS
      const isHttps = req.secure || 
        req.headers['x-forwarded-proto'] === 'https' ||
        req.headers['x-forwarded-ssl'] === 'on';

      if (!isHttps) {
        // Redirect to HTTPS
        const httpsUrl = `https://${req.get('host')}${req.originalUrl}`;
        return res.redirect(301, httpsUrl);
      }

      // Enforce TLS 1.2+ (this is handled at the server level, but we can add headers)
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    }

    next();
  }
}

