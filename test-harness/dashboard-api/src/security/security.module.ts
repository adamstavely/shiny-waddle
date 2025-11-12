import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { EncryptionService } from './encryption.service';
import { SecretsService } from './secrets.service';
import { SecurityAuditLogService } from './audit-log.service';
import { AccessControlGuard } from './guards/access-control.guard';
import { AuditLoggingMiddleware } from './middleware/audit-logging.middleware';
import { SecurityController } from './security.controller';

@Module({
  providers: [
    EncryptionService,
    SecretsService,
    SecurityAuditLogService,
    AccessControlGuard,
  ],
  controllers: [SecurityController],
  exports: [
    EncryptionService,
    SecretsService,
    SecurityAuditLogService,
    AccessControlGuard,
  ],
})
export class SecurityModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuditLoggingMiddleware)
      .forRoutes('*'); // Apply to all routes
  }
}


