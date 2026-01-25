import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { SecurityAuditLogService, SecurityAuditEventType } from '../audit-log.service';

@Injectable()
export class AuditLoggingMiddleware implements NestMiddleware {
  constructor(private readonly auditLogService: SecurityAuditLogService) {}

  use(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    const requestId = req.headers['x-request-id'] as string || 
                     `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const auditLogService = this.auditLogService;

    // Add request ID to headers
    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);

    // Log request
    const user = (req as any).user;
    const isWriteOperation = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method);
    const isReadOperation = req.method === 'GET';

    // Capture response
    const originalSend = res.send;
    res.send = function (body: any) {
      const duration = Date.now() - startTime;
      
      // Log asynchronously (don't block response)
      setImmediate(async () => {
        try {
          if (isWriteOperation) {
            await auditLogService.log({
              type: SecurityAuditEventType.DATA_WRITE,
              action: `${req.method} ${req.path}`,
              description: `Data write operation: ${req.method} ${req.path}`,
              userId: user?.id || user?.userId,
              username: user?.username || user?.email,
              ipAddress: req.ip,
              userAgent: req.get('user-agent'),
              resourceType: 'endpoint',
              resourceId: req.path,
              success: res.statusCode < 400,
              errorMessage: res.statusCode >= 400 ? `HTTP ${res.statusCode}` : undefined,
              requestId,
              responseCode: res.statusCode,
              duration,
              metadata: {
                method: req.method,
                path: req.path,
                query: req.query,
                bodySize: req.get('content-length'),
              },
            });
          } else if (isReadOperation && user) {
            // Only log read operations for authenticated users accessing sensitive data
            const sensitivePaths = ['/api/secrets', '/api/audit-logs', '/api/users'];
            if (sensitivePaths.some(path => req.path.startsWith(path))) {
              await auditLogService.log({
                type: SecurityAuditEventType.DATA_READ,
                action: `${req.method} ${req.path}`,
                description: `Data read operation: ${req.method} ${req.path}`,
                userId: user.id || user.userId,
                username: user.username || user.email,
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
                resourceType: 'endpoint',
                resourceId: req.path,
                success: res.statusCode < 400,
                requestId,
                responseCode: res.statusCode,
                duration,
              });
            }
          }
        } catch (error) {
          console.error('Failed to log audit event:', error);
        }
      });

      return originalSend.call(this, body);
    };

    next();
  }
}

