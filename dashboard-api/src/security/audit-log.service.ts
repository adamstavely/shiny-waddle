import { Injectable } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { AppLogger } from '../common/services/logger.service';
import * as fs from 'fs/promises';
import * as path from 'path';

export enum SecurityAuditEventType {
  // Authentication & Authorization
  LOGIN_SUCCESS = 'login-success',
  LOGIN_FAILURE = 'login-failure',
  LOGOUT = 'logout',
  TOKEN_ISSUED = 'token-issued',
  TOKEN_REVOKED = 'token-revoked',
  ACCESS_GRANTED = 'access-granted',
  ACCESS_DENIED = 'access-denied',
  PERMISSION_CHANGED = 'permission-changed',
  ROLE_CHANGED = 'role-changed',

  // Data Access
  DATA_READ = 'data-read',
  DATA_WRITE = 'data-write',
  DATA_DELETE = 'data-delete',
  DATA_EXPORT = 'data-export',
  DATA_IMPORT = 'data-import',

  // Configuration Changes
  CONFIG_CHANGED = 'config-changed',
  POLICY_CREATED = 'policy-created',
  POLICY_UPDATED = 'policy-updated',
  POLICY_DELETED = 'policy-deleted',
  POLICY_DEPLOYED = 'policy-deployed',

  // Secrets Management
  SECRET_CREATED = 'secret-created',
  SECRET_ACCESSED = 'secret-accessed',
  SECRET_UPDATED = 'secret-updated',
  SECRET_DELETED = 'secret-deleted',
  SECRET_ROTATED = 'secret-rotated',

  // System Events
  SYSTEM_STARTUP = 'system-startup',
  SYSTEM_SHUTDOWN = 'system-shutdown',
  BACKUP_CREATED = 'backup-created',
  BACKUP_RESTORED = 'backup-restored',
  ENCRYPTION_KEY_ROTATED = 'encryption-key-rotated',

  // Security Events
  SECURITY_ALERT = 'security-alert',
  SUSPICIOUS_ACTIVITY = 'suspicious-activity',
  BRUTE_FORCE_ATTEMPT = 'brute-force-attempt',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'unauthorized-access-attempt',
}

export enum SecurityAuditSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface SecurityAuditLog {
  id: string;
  type: SecurityAuditEventType;
  severity: SecurityAuditSeverity;
  action: string;
  description: string;
  userId?: string;
  username?: string;
  ipAddress?: string;
  userAgent?: string;
  resourceType?: string;
  resourceId?: string;
  resourceName?: string;
  application?: string;
  team?: string;
  timestamp: Date;
  success: boolean;
  errorMessage?: string;
  metadata?: Record<string, any>;
  sessionId?: string;
  requestId?: string;
  responseCode?: number;
  duration?: number; // milliseconds
}

export interface CreateSecurityAuditLogDto {
  type: SecurityAuditEventType;
  severity?: SecurityAuditSeverity;
  action: string;
  description: string;
  userId?: string;
  username?: string;
  ipAddress?: string;
  userAgent?: string;
  resourceType?: string;
  resourceId?: string;
  resourceName?: string;
  application?: string;
  team?: string;
  success?: boolean;
  errorMessage?: string;
  metadata?: Record<string, any>;
  sessionId?: string;
  requestId?: string;
  responseCode?: number;
  duration?: number;
}

@Injectable()
export class SecurityAuditLogService {
  private auditLogs: SecurityAuditLog[] = [];
  private readonly auditLogFile: string;
  private readonly maxLogsInMemory: number = 10000;
  private readonly logger = new AppLogger(SecurityAuditLogService.name);

  constructor() {
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
    this.auditLogFile = path.join(dataDir, 'security-audit-logs.json');
    this.loadAuditLogs();
  }

  /**
   * Load audit logs from file
   */
  private async loadAuditLogs(): Promise<void> {
    try {
      const data = await fs.readFile(this.auditLogFile, 'utf8');
      const logsArray: SecurityAuditLog[] = JSON.parse(data);
      
      logsArray.forEach(log => {
        log.timestamp = new Date(log.timestamp);
        this.auditLogs.push(log);
      });

      // Keep only recent logs in memory
      if (this.auditLogs.length > this.maxLogsInMemory) {
        this.auditLogs = this.auditLogs
          .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
          .slice(0, this.maxLogsInMemory);
      }
    } catch (error: any) {
      if (error.code === 'ENOENT') {
        this.logger.debug('No existing audit log file found, starting fresh');
      } else {
        this.logger.error('Error loading audit logs', error.stack || error.message);
      }
    }
  }

  /**
   * Save audit logs to file
   */
  private async saveAuditLogs(): Promise<void> {
    try {
      const dataDir = path.dirname(this.auditLogFile);
      await fs.mkdir(dataDir, { recursive: true });

      // Append to file (for performance with large logs)
      const newLogs = this.auditLogs.slice(-100); // Save last 100 logs
      const existingLogs = await this.readAllLogsFromFile();
      const allLogs = [...existingLogs, ...newLogs.filter(log => 
        !existingLogs.some(existing => existing.id === log.id)
      )];

      // Keep only last 100000 logs in file
      const logsToKeep = allLogs
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, 100000);

      const tempFile = `${this.auditLogFile}.tmp`;
      await fs.writeFile(tempFile, JSON.stringify(logsToKeep, null, 2), 'utf8');
      await fs.rename(tempFile, this.auditLogFile);
    } catch (error: any) {
      // Suppress errors in test mode to avoid async teardown issues
      if (process.env.NODE_ENV !== 'test' && !process.env.JEST_WORKER_ID) {
        this.logger.error('Error saving audit logs', error.stack || error.message);
      }
    }
  }

  /**
   * Read all logs from file
   */
  private async readAllLogsFromFile(): Promise<SecurityAuditLog[]> {
    try {
      const data = await fs.readFile(this.auditLogFile, 'utf8');
      const logs: SecurityAuditLog[] = JSON.parse(data);
      return logs.map(log => ({
        ...log,
        timestamp: new Date(log.timestamp),
      }));
    } catch {
      return [];
    }
  }

  /**
   * Create an audit log entry
   */
  async log(dto: CreateSecurityAuditLogDto): Promise<SecurityAuditLog> {
    const log: SecurityAuditLog = {
      id: uuidv4(),
      type: dto.type,
      severity: dto.severity || this.getDefaultSeverity(dto.type),
      action: dto.action,
      description: dto.description,
      userId: dto.userId,
      username: dto.username,
      ipAddress: dto.ipAddress,
      userAgent: dto.userAgent,
      resourceType: dto.resourceType,
      resourceId: dto.resourceId,
      resourceName: dto.resourceName,
      application: dto.application,
      team: dto.team,
      timestamp: new Date(),
      success: dto.success !== undefined ? dto.success : true,
      errorMessage: dto.errorMessage,
      metadata: dto.metadata,
      sessionId: dto.sessionId,
      requestId: dto.requestId,
      responseCode: dto.responseCode,
      duration: dto.duration,
    };

    this.auditLogs.push(log);

    // Save asynchronously (don't block)
    this.saveAuditLogs().catch(err => {
      this.logger.error('Failed to save audit log', err instanceof Error ? err.stack : String(err), { logId: log.id });
    });

    // Alert on critical events
    if (log.severity === SecurityAuditSeverity.CRITICAL) {
      this.logger.error(`🚨 CRITICAL SECURITY EVENT: ${log.type} - ${log.description}`, undefined, { 
        type: log.type, 
        severity: log.severity,
        userId: log.userId 
      });
    }

    return log;
  }

  /**
   * Get default severity for event type
   */
  private getDefaultSeverity(type: SecurityAuditEventType): SecurityAuditSeverity {
    const severityMap: Record<SecurityAuditEventType, SecurityAuditSeverity> = {
      [SecurityAuditEventType.LOGIN_SUCCESS]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.LOGIN_FAILURE]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.LOGOUT]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.TOKEN_ISSUED]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.TOKEN_REVOKED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.ACCESS_GRANTED]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.ACCESS_DENIED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.PERMISSION_CHANGED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.ROLE_CHANGED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.DATA_READ]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.DATA_WRITE]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.DATA_DELETE]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.DATA_EXPORT]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.DATA_IMPORT]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.CONFIG_CHANGED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.POLICY_CREATED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.POLICY_UPDATED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.POLICY_DELETED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.POLICY_DEPLOYED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.SECRET_CREATED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.SECRET_ACCESSED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.SECRET_UPDATED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.SECRET_DELETED]: SecurityAuditSeverity.CRITICAL,
      [SecurityAuditEventType.SECRET_ROTATED]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.SYSTEM_STARTUP]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.SYSTEM_SHUTDOWN]: SecurityAuditSeverity.MEDIUM,
      [SecurityAuditEventType.BACKUP_CREATED]: SecurityAuditSeverity.LOW,
      [SecurityAuditEventType.BACKUP_RESTORED]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.ENCRYPTION_KEY_ROTATED]: SecurityAuditSeverity.CRITICAL,
      [SecurityAuditEventType.SECURITY_ALERT]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.SUSPICIOUS_ACTIVITY]: SecurityAuditSeverity.HIGH,
      [SecurityAuditEventType.BRUTE_FORCE_ATTEMPT]: SecurityAuditSeverity.CRITICAL,
      [SecurityAuditEventType.UNAUTHORIZED_ACCESS_ATTEMPT]: SecurityAuditSeverity.CRITICAL,
    };

    return severityMap[type] || SecurityAuditSeverity.MEDIUM;
  }

  /**
   * Query audit logs
   */
  async queryLogs(filters: {
    type?: SecurityAuditEventType;
    severity?: SecurityAuditSeverity;
    userId?: string;
    resourceType?: string;
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    success?: boolean;
    limit?: number;
  }): Promise<SecurityAuditLog[]> {
    let logs = [...this.auditLogs];

    if (filters.type) {
      logs = logs.filter(log => log.type === filters.type);
    }

    if (filters.severity) {
      logs = logs.filter(log => log.severity === filters.severity);
    }

    if (filters.userId) {
      logs = logs.filter(log => log.userId === filters.userId);
    }

    if (filters.resourceType) {
      logs = logs.filter(log => log.resourceType === filters.resourceType);
    }

    if (filters.resourceId) {
      logs = logs.filter(log => log.resourceId === filters.resourceId);
    }

    if (filters.startDate) {
      logs = logs.filter(log => log.timestamp >= filters.startDate!);
    }

    if (filters.endDate) {
      logs = logs.filter(log => log.timestamp <= filters.endDate!);
    }

    if (filters.success !== undefined) {
      logs = logs.filter(log => log.success === filters.success);
    }

    // Sort by timestamp (newest first)
    logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply limit
    if (filters.limit) {
      logs = logs.slice(0, filters.limit);
    }

    return logs;
  }

  /**
   * Get audit log by ID
   */
  async getLogById(id: string): Promise<SecurityAuditLog | null> {
    return this.auditLogs.find(log => log.id === id) || null;
  }

  /**
   * Apply retention policy - remove logs older than specified days
   */
  async applyRetentionPolicy(retentionDays: number = 90): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const initialCount = this.auditLogs.length;
    this.auditLogs = this.auditLogs.filter(log => log.timestamp >= cutoffDate);

    const removedCount = initialCount - this.auditLogs.length;
    
    if (removedCount > 0) {
      await this.saveAuditLogs();
    }

    return removedCount;
  }

  /**
   * Export audit logs to CSV format
   */
  async exportToCSV(filters?: {
    type?: SecurityAuditEventType;
    severity?: SecurityAuditSeverity;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<string> {
    const logs = filters ? await this.queryLogs(filters) : [...this.auditLogs];

    const headers = [
      'ID',
      'Type',
      'Severity',
      'Action',
      'Description',
      'User ID',
      'Username',
      'IP Address',
      'Resource Type',
      'Resource ID',
      'Timestamp',
      'Success',
      'Error Message',
    ];

    const rows = logs.map(log => [
      log.id,
      log.type,
      log.severity,
      log.action,
      log.description,
      log.userId || '',
      log.username || '',
      log.ipAddress || '',
      log.resourceType || '',
      log.resourceId || '',
      log.timestamp.toISOString(),
      log.success ? 'true' : 'false',
      log.errorMessage || '',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    return csvContent;
  }

  /**
   * Export audit logs to JSON format
   */
  async exportToJSON(filters?: {
    type?: SecurityAuditEventType;
    severity?: SecurityAuditSeverity;
    userId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<string> {
    const logs = filters ? await this.queryLogs(filters) : [...this.auditLogs];
    return JSON.stringify(logs, null, 2);
  }

  /**
   * Detect suspicious activity patterns
   */
  async detectSuspiciousActivity(): Promise<{
    suspiciousLogs: SecurityAuditLog[];
    patterns: Array<{
      type: string;
      description: string;
      count: number;
      severity: SecurityAuditSeverity;
    }>;
  }> {
    const suspiciousLogs: SecurityAuditLog[] = [];
    const patterns: Array<{
      type: string;
      description: string;
      count: number;
      severity: SecurityAuditSeverity;
    }> = [];

    // Pattern 1: Multiple failed login attempts from same IP
    const failedLogins = this.auditLogs.filter(
      log => log.type === SecurityAuditEventType.LOGIN_FAILURE
    );
    const loginAttemptsByIP = new Map<string, SecurityAuditLog[]>();
    failedLogins.forEach(log => {
      if (log.ipAddress) {
        const attempts = loginAttemptsByIP.get(log.ipAddress) || [];
        attempts.push(log);
        loginAttemptsByIP.set(log.ipAddress, attempts);
      }
    });

    loginAttemptsByIP.forEach((attempts, ip) => {
      if (attempts.length >= 5) {
        suspiciousLogs.push(...attempts);
        patterns.push({
          type: 'brute-force-attempt',
          description: `Multiple failed login attempts (${attempts.length}) from IP ${ip}`,
          count: attempts.length,
          severity: SecurityAuditSeverity.HIGH,
        });
      }
    });

    // Pattern 2: Multiple access denied attempts
    const accessDenied = this.auditLogs.filter(
      log => log.type === SecurityAuditEventType.ACCESS_DENIED
    );
    const deniedByUser = new Map<string, SecurityAuditLog[]>();
    accessDenied.forEach(log => {
      if (log.userId) {
        const attempts = deniedByUser.get(log.userId) || [];
        attempts.push(log);
        deniedByUser.set(log.userId, attempts);
      }
    });

    deniedByUser.forEach((attempts, userId) => {
      if (attempts.length >= 10) {
        suspiciousLogs.push(...attempts);
        patterns.push({
          type: 'unauthorized-access-pattern',
          description: `Multiple access denied attempts (${attempts.length}) for user ${userId}`,
          count: attempts.length,
          severity: SecurityAuditSeverity.MEDIUM,
        });
      }
    });

    // Pattern 3: Critical security events
    const criticalEvents = this.auditLogs.filter(
      log => log.severity === SecurityAuditSeverity.CRITICAL
    );
    if (criticalEvents.length > 0) {
      suspiciousLogs.push(...criticalEvents);
      patterns.push({
        type: 'critical-security-events',
        description: `${criticalEvents.length} critical security events detected`,
        count: criticalEvents.length,
        severity: SecurityAuditSeverity.CRITICAL,
      });
    }

    // Pattern 4: Rapid token revocation (potential account compromise)
    const tokenRevocations = this.auditLogs.filter(
      log => log.type === SecurityAuditEventType.TOKEN_REVOKED
    );
    const revocationsByUser = new Map<string, SecurityAuditLog[]>();
    tokenRevocations.forEach(log => {
      if (log.userId) {
        const revocations = revocationsByUser.get(log.userId) || [];
        revocations.push(log);
        revocationsByUser.set(log.userId, revocations);
      }
    });

    revocationsByUser.forEach((revocations, userId) => {
      // Check if revocations happened within a short time window (e.g., 1 hour)
      const sorted = revocations.sort((a, b) => 
        a.timestamp.getTime() - b.timestamp.getTime()
      );
      if (sorted.length >= 3) {
        const timeSpan = sorted[sorted.length - 1].timestamp.getTime() - sorted[0].timestamp.getTime();
        const oneHour = 60 * 60 * 1000;
        if (timeSpan < oneHour) {
          suspiciousLogs.push(...revocations);
          patterns.push({
            type: 'rapid-token-revocation',
            description: `Rapid token revocations (${revocations.length}) for user ${userId} within ${Math.round(timeSpan / 1000 / 60)} minutes`,
            count: revocations.length,
            severity: SecurityAuditSeverity.HIGH,
          });
        }
      }
    });

    // Remove duplicates
    const uniqueSuspiciousLogs = Array.from(
      new Map(suspiciousLogs.map(log => [log.id, log])).values()
    );

    return {
      suspiciousLogs: uniqueSuspiciousLogs,
      patterns,
    };
  }

  /**
   * Get retention policy configuration
   */
  getRetentionPolicy(): { enabled: boolean; retentionDays: number } {
    const retentionDays = parseInt(
      process.env.AUDIT_LOG_RETENTION_DAYS || '90',
      10
    );
    return {
      enabled: process.env.AUDIT_LOG_RETENTION_ENABLED !== 'false',
      retentionDays,
    };
  }
}


