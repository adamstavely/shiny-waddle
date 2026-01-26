/**
 * Agent Audit Trail Validator Service
 * 
 * Validates centralized audit logging for agent actions:
 * - Single agent action audit trail
 * - Multi-service access audit trail
 * - Delegated vs direct access audit differentiation
 * - Audit log correlation across services
 * - Audit log retention and compliance
 */

import { TestResult } from '../core/types';

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  agentId: string;
  agentType: 'delegated' | 'direct';
  userId?: string;
  action: string;
  serviceId: string;
  resourceId: string;
  resourceType: string;
  allowed: boolean;
  reason?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, any>;
}

export interface AgentAuditTrailTest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userId?: string;
  actions: Array<{
    serviceId: string;
    action: string;
    resourceId: string;
    resourceType: string;
    timestamp: Date;
    expectedLogged: boolean;
  }>;
  auditSources?: string[]; // Multiple providers to aggregate from
  retentionPeriod?: number; // Days
}

export interface AuditTrailValidationResult extends TestResult {
  testName: string;
  agentId: string;
  auditLogComplete: boolean;
  auditLogIntegrity: boolean;
  crossServiceCorrelation: boolean;
  retentionCompliance?: boolean;
  missingEntries?: Array<{
    serviceId: string;
    action: string;
    timestamp: Date;
  }>;
  correlationIssues?: string[];
  integrityIssues?: string[];
  details?: Record<string, any>;
}

export class AgentAuditValidator {
  private auditLogs: Map<string, AuditLogEntry[]> = new Map();
  private auditSources: Map<string, AuditLogEntry[]> = new Map();

  /**
   * Add audit log entry (simulates receiving logs from audit service)
   */
  addAuditLogEntry(entry: AuditLogEntry, source?: string): void {
    const key = `${entry.agentId}_${entry.timestamp.getTime()}`;
    
    if (!this.auditLogs.has(entry.agentId)) {
      this.auditLogs.set(entry.agentId, []);
    }
    this.auditLogs.get(entry.agentId)!.push(entry);

    // Track by source if provided
    if (source) {
      if (!this.auditSources.has(source)) {
        this.auditSources.set(source, []);
      }
      this.auditSources.get(source)!.push(entry);
    }
  }

  /**
   * Validate agent audit trail
   */
  async validateAuditTrail(
    test: AgentAuditTrailTest
  ): Promise<AuditTrailValidationResult> {
    const result: AuditTrailValidationResult = {
      testType: 'agent-audit-trail',
      testName: `Audit Trail Validation - ${test.agentId}`,
      passed: false,
      timestamp: new Date(),
      agentId: test.agentId,
      auditLogComplete: false,
      auditLogIntegrity: false,
      crossServiceCorrelation: false,
      details: {},
    };

    try {
      // Get audit logs for this agent
      const agentLogs = this.auditLogs.get(test.agentId) || [];

      // Step 1: Check completeness
      const completenessCheck = this.checkCompleteness(test, agentLogs);
      result.auditLogComplete = completenessCheck.complete;
      result.missingEntries = completenessCheck.missing;

      // Step 2: Check integrity
      const integrityCheck = this.checkIntegrity(agentLogs);
      result.auditLogIntegrity = integrityCheck.valid;
      result.integrityIssues = integrityCheck.issues;

      // Step 3: Check cross-service correlation
      const correlationCheck = await this.checkCrossServiceCorrelation(
        test,
        agentLogs
      );
      result.crossServiceCorrelation = correlationCheck.valid;
      result.correlationIssues = correlationCheck.issues;

      // Step 4: Check retention compliance
      if (test.retentionPeriod) {
        const retentionCheck = this.checkRetentionCompliance(
          agentLogs,
          test.retentionPeriod
        );
        result.retentionCompliance = retentionCheck.compliant;
        result.details = {
          ...result.details,
          retentionIssues: retentionCheck.issues,
        };
      }

      // Aggregate from multiple sources if provided
      if (test.auditSources && test.auditSources.length > 0) {
        const aggregationCheck = await this.aggregateFromSources(
          test,
          test.auditSources
        );
        result.details = {
          ...result.details,
          aggregationComplete: aggregationCheck.complete,
          aggregationIssues: aggregationCheck.issues,
        };
      }

      result.passed =
        result.auditLogComplete &&
        result.auditLogIntegrity &&
        result.crossServiceCorrelation &&
        (result.retentionCompliance !== false);

      result.details = {
        ...result.details,
        totalLogs: agentLogs.length,
        expectedActions: test.actions.length,
        loggedActions: agentLogs.length,
        agentType: test.agentType,
        userId: test.userId,
      };
    } catch (error: any) {
      result.error = error.message;
      result.details = {
        ...result.details,
        error: error.message,
      };
    }

    return result;
  }

  /**
   * Check if audit trail is complete
   */
  private checkCompleteness(
    test: AgentAuditTrailTest,
    logs: AuditLogEntry[]
  ): {
    complete: boolean;
    missing: Array<{
      serviceId: string;
      action: string;
      timestamp: Date;
    }>;
  } {
    const missing: Array<{
      serviceId: string;
      action: string;
      timestamp: Date;
    }> = [];

    for (const expectedAction of test.actions) {
      if (!expectedAction.expectedLogged) {
        continue; // Skip if not expected to be logged
      }

      // Find matching log entry
      const found = logs.find(
        log =>
          log.serviceId === expectedAction.serviceId &&
          log.action === expectedAction.action &&
          log.resourceId === expectedAction.resourceId &&
          Math.abs(
            log.timestamp.getTime() - expectedAction.timestamp.getTime()
          ) < 60000 // Within 1 minute
      );

      if (!found) {
        missing.push({
          serviceId: expectedAction.serviceId,
          action: expectedAction.action,
          timestamp: expectedAction.timestamp,
        });
      }
    }

    return {
      complete: missing.length === 0,
      missing,
    };
  }

  /**
   * Check audit log integrity
   */
  private checkIntegrity(logs: AuditLogEntry[]): {
    valid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    // Check for required fields
    for (const log of logs) {
      if (!log.id) {
        issues.push(`Log entry missing id: ${JSON.stringify(log)}`);
      }
      if (!log.timestamp) {
        issues.push(`Log entry missing timestamp: ${log.id}`);
      }
      if (!log.agentId) {
        issues.push(`Log entry missing agentId: ${log.id}`);
      }
      if (!log.action) {
        issues.push(`Log entry missing action: ${log.id}`);
      }
      if (!log.serviceId) {
        issues.push(`Log entry missing serviceId: ${log.id}`);
      }
    }

    // Check for chronological order
    const sortedLogs = [...logs].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );
    for (let i = 0; i < logs.length; i++) {
      if (logs[i].timestamp.getTime() !== sortedLogs[i].timestamp.getTime()) {
        issues.push('Log entries not in chronological order');
        break;
      }
    }

    // Check for duplicate entries
    const seenIds = new Set<string>();
    for (const log of logs) {
      if (seenIds.has(log.id)) {
        issues.push(`Duplicate log entry: ${log.id}`);
      }
      seenIds.add(log.id);
    }

    return {
      valid: issues.length === 0,
      issues,
    };
  }

  /**
   * Check cross-service correlation
   */
  private async checkCrossServiceCorrelation(
    test: AgentAuditTrailTest,
    logs: AuditLogEntry[]
  ): Promise<{
    valid: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];

    // Group logs by service
    const logsByService = new Map<string, AuditLogEntry[]>();
    for (const log of logs) {
      if (!logsByService.has(log.serviceId)) {
        logsByService.set(log.serviceId, []);
      }
      logsByService.get(log.serviceId)!.push(log);
    }

    // Check if multi-service access is properly correlated
    if (logsByService.size > 1) {
      // Check for correlation metadata
      const correlationIds = new Set<string>();
      for (const log of logs) {
        if (log.metadata?.correlationId) {
          correlationIds.add(log.metadata.correlationId);
        }
      }

      if (correlationIds.size === 0) {
        issues.push(
          'Multi-service access lacks correlation IDs for tracking'
        );
      }

      // Check if delegated access includes user context
      if (test.agentType === 'delegated' && test.userId) {
        const missingUserContext = logs.filter(
          log => !log.userId || log.userId !== test.userId
        );
        if (missingUserContext.length > 0) {
          issues.push(
            `${missingUserContext.length} log entries missing user context for delegated access`
          );
        }
      }
    }

    return {
      valid: issues.length === 0,
      issues,
    };
  }

  /**
   * Check retention compliance
   */
  private checkRetentionCompliance(
    logs: AuditLogEntry[],
    retentionPeriodDays: number
  ): {
    compliant: boolean;
    issues: string[];
  } {
    const issues: string[] = [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionPeriodDays);

    // Check if old logs are still present (should be retained)
    const oldLogs = logs.filter(log => log.timestamp < cutoffDate);
    if (oldLogs.length === 0 && logs.length > 0) {
      issues.push(
        `No logs found older than retention period (${retentionPeriodDays} days) - may indicate premature deletion`
      );
    }

    // Check if logs are within retention period
    const tooOldLogs = logs.filter(
      log => log.timestamp < new Date(Date.now() - retentionPeriodDays * 24 * 60 * 60 * 1000)
    );
    if (tooOldLogs.length > 0) {
      // This might be expected if retention period allows it
      // But flag for review
    }

    return {
      compliant: issues.length === 0,
      issues,
    };
  }

  /**
   * Aggregate audit logs from multiple sources
   */
  private async aggregateFromSources(
    test: AgentAuditTrailTest,
    sources: string[]
  ): Promise<{
    complete: boolean;
    issues: string[];
  }> {
    const issues: string[] = [];
    const aggregatedLogs: AuditLogEntry[] = [];

    // Collect logs from all sources
    for (const source of sources) {
      const sourceLogs = this.auditSources.get(source) || [];
      const agentLogs = sourceLogs.filter(log => log.agentId === test.agentId);
      aggregatedLogs.push(...agentLogs);
    }

    // Check if we have logs from all expected sources
    for (const source of sources) {
      const sourceLogs = this.auditSources.get(source) || [];
      const agentLogs = sourceLogs.filter(log => log.agentId === test.agentId);
      if (agentLogs.length === 0) {
        issues.push(`No logs found from source: ${source}`);
      }
    }

    // Check for duplicates across sources
    const seenIds = new Set<string>();
    const duplicates: string[] = [];
    for (const log of aggregatedLogs) {
      if (seenIds.has(log.id)) {
        duplicates.push(log.id);
      }
      seenIds.add(log.id);
    }

    if (duplicates.length > 0) {
      issues.push(
        `Found ${duplicates.length} duplicate log entries across sources`
      );
    }

    return {
      complete: issues.length === 0,
      issues,
    };
  }

  /**
   * Analyze audit patterns for anomalies
   */
  analyzeAuditPatterns(
    agentId: string,
    timeWindow?: { start: Date; end: Date }
  ): {
    anomalies: string[];
    patterns: Record<string, any>;
  } {
    const logs = this.auditLogs.get(agentId) || [];
    const filteredLogs = timeWindow
      ? logs.filter(
          log =>
            log.timestamp >= timeWindow.start && log.timestamp <= timeWindow.end
        )
      : logs;

    const anomalies: string[] = [];
    const patterns: Record<string, any> = {};

    // Analyze access patterns
    const accessByService = new Map<string, number>();
    const accessByAction = new Map<string, number>();
    const deniedAccess = filteredLogs.filter(log => !log.allowed);

    for (const log of filteredLogs) {
      accessByService.set(
        log.serviceId,
        (accessByService.get(log.serviceId) || 0) + 1
      );
      accessByAction.set(
        log.action,
        (accessByAction.get(log.action) || 0) + 1
      );
    }

    patterns.serviceAccess = Object.fromEntries(accessByService);
    patterns.actionFrequency = Object.fromEntries(accessByAction);
    patterns.denialRate = deniedAccess.length / filteredLogs.length;

    // Detect anomalies
    if (patterns.denialRate > 0.5) {
      anomalies.push(
        `High denial rate: ${(patterns.denialRate * 100).toFixed(1)}%`
      );
    }

    // Check for unusual access patterns
    const serviceCount = accessByService.size;
    if (serviceCount > 10) {
      anomalies.push(
        `Agent accessed ${serviceCount} different services - may indicate over-privileged access`
      );
    }

    return {
      anomalies,
      patterns,
    };
  }

  /**
   * Get audit trail for agent
   */
  getAuditTrail(
    agentId: string,
    filters?: {
      startDate?: Date;
      endDate?: Date;
      serviceId?: string;
      action?: string;
    }
  ): AuditLogEntry[] {
    let logs = this.auditLogs.get(agentId) || [];

    if (filters) {
      if (filters.startDate) {
        logs = logs.filter(log => log.timestamp >= filters.startDate!);
      }
      if (filters.endDate) {
        logs = logs.filter(log => log.timestamp <= filters.endDate!);
      }
      if (filters.serviceId) {
        logs = logs.filter(log => log.serviceId === filters.serviceId);
      }
      if (filters.action) {
        logs = logs.filter(log => log.action === filters.action);
      }
    }

    return logs.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
  }
}
