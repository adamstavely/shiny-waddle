import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
} from '@nestjs/common';
import { SecretsService, CreateSecretDto, UpdateSecretDto } from './secrets.service';
import { SecurityAuditLogService, SecurityAuditEventType } from './audit-log.service';
import { AccessControlGuard, RequirePermission, Permission, RequireRole, UserRole } from './guards/access-control.guard';

@Controller('api/v1/security')
@UseGuards(AccessControlGuard)
export class SecurityController {
  constructor(
    private readonly secretsService: SecretsService,
    private readonly auditLogService: SecurityAuditLogService,
  ) {}

  // Secrets Management
  @Post('secrets')
  @RequirePermission(Permission.WRITE_SECRETS)
  async createSecret(@Body() dto: CreateSecretDto, @Request() req: any) {
    const user = req.user;
    const secret = await this.secretsService.createSecret({
      ...dto,
      createdBy: user?.id || user?.userId || user?.username,
    });

    await this.auditLogService.log({
      type: SecurityAuditEventType.SECRET_CREATED,
      action: 'secret-created',
      description: `Secret "${dto.key}" created`,
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      resourceType: 'secret',
      resourceId: secret.id,
      resourceName: dto.key,
      success: true,
      requestId: req.headers['x-request-id'],
    });

    return secret;
  }

  @Get('secrets')
  @RequirePermission(Permission.READ_SECRETS)
  async listSecrets(@Query('tags') tags?: string) {
    const tagArray = tags ? tags.split(',') : undefined;
    return this.secretsService.listSecrets(tagArray);
  }

  @Get('secrets/:key')
  @RequirePermission(Permission.READ_SECRETS)
  async getSecret(@Param('key') key: string, @Request() req: any) {
    const user = req.user;
    const secret = await this.secretsService.getSecretByKey(key);

    await this.auditLogService.log({
      type: SecurityAuditEventType.SECRET_ACCESSED,
      action: 'secret-accessed',
      description: `Secret "${key}" accessed`,
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      resourceType: 'secret',
      resourceId: secret.id,
      resourceName: key,
      success: true,
      requestId: req.headers['x-request-id'],
    });

    return secret;
  }

  @Put('secrets/:id')
  @RequirePermission(Permission.WRITE_SECRETS)
  async updateSecret(
    @Param('id') id: string,
    @Body() dto: UpdateSecretDto,
    @Request() req: any,
  ) {
    const user = req.user;
    const secret = await this.secretsService.updateSecret(id, {
      ...dto,
      updatedBy: user?.id || user?.userId || user?.username,
    });

    await this.auditLogService.log({
      type: SecurityAuditEventType.SECRET_UPDATED,
      action: 'secret-updated',
      description: `Secret "${secret.key}" updated`,
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      resourceType: 'secret',
      resourceId: secret.id,
      resourceName: secret.key,
      success: true,
      requestId: req.headers['x-request-id'],
    });

    return secret;
  }

  @Delete('secrets/:id')
  @RequirePermission(Permission.DELETE_SECRETS)
  async deleteSecret(@Param('id') id: string, @Request() req: any) {
    const user = req.user;
    const secret = await this.secretsService.getSecretById(id);
    
    await this.secretsService.deleteSecret(id);

    await this.auditLogService.log({
      type: SecurityAuditEventType.SECRET_DELETED,
      action: 'secret-deleted',
      description: `Secret "${secret.key}" deleted`,
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      resourceType: 'secret',
      resourceId: secret.id,
      resourceName: secret.key,
      success: true,
      requestId: req.headers['x-request-id'],
    });

    return { message: 'Secret deleted successfully' };
  }

  @Post('secrets/:id/rotate')
  @RequirePermission(Permission.WRITE_SECRETS)
  async rotateSecret(
    @Param('id') id: string,
    @Body() body: { value: string },
    @Request() req: any,
  ) {
    const user = req.user;
    const secret = await this.secretsService.rotateSecret(
      id,
      body.value,
      user?.id || user?.userId || user?.username,
    );

    await this.auditLogService.log({
      type: SecurityAuditEventType.SECRET_ROTATED,
      action: 'secret-rotated',
      description: `Secret "${secret.key}" rotated`,
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      resourceType: 'secret',
      resourceId: secret.id,
      resourceName: secret.key,
      success: true,
      requestId: req.headers['x-request-id'],
    });

    return secret;
  }

  // Audit Logs
  @Get('audit-logs')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async getAuditLogs(
    @Query('type') type?: string,
    @Query('severity') severity?: string,
    @Query('userId') userId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ) {
    return this.auditLogService.queryLogs({
      type: type as any,
      severity: severity as any,
      userId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  @Get('audit-logs/:id')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async getAuditLog(@Param('id') id: string) {
    return this.auditLogService.getLogById(id);
  }

  @Get('audit-logs/export/csv')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async exportAuditLogsCSV(
    @Query('type') type?: string,
    @Query('severity') severity?: string,
    @Query('userId') userId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ) {
    const csv = await this.auditLogService.exportToCSV({
      type: type as any,
      severity: severity as any,
      userId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
    return { format: 'csv', data: csv };
  }

  @Get('audit-logs/export/json')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async exportAuditLogsJSON(
    @Query('type') type?: string,
    @Query('severity') severity?: string,
    @Query('userId') userId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ) {
    const json = await this.auditLogService.exportToJSON({
      type: type as any,
      severity: severity as any,
      userId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
    return { format: 'json', data: JSON.parse(json) };
  }

  @Get('audit-logs/suspicious-activity')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async detectSuspiciousActivity() {
    return this.auditLogService.detectSuspiciousActivity();
  }

  @Post('audit-logs/retention-policy/apply')
  @RequirePermission(Permission.MANAGE_SYSTEM)
  async applyRetentionPolicy(@Body('retentionDays') retentionDays?: number) {
    const policy = this.auditLogService.getRetentionPolicy();
    const days = retentionDays || policy.retentionDays;
    const removedCount = await this.auditLogService.applyRetentionPolicy(days);
    return {
      message: `Retention policy applied. ${removedCount} log(s) removed.`,
      removedCount,
      retentionDays: days,
    };
  }

  @Get('audit-logs/retention-policy')
  @RequirePermission(Permission.READ_AUDIT_LOGS)
  async getRetentionPolicy() {
    return this.auditLogService.getRetentionPolicy();
  }
}


