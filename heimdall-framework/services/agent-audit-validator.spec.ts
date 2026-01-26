/**
 * Agent Audit Validator Unit Tests
 */

import { AgentAuditValidator, AgentAuditTrailTest, AuditLogEntry } from './agent-audit-validator';

describe('AgentAuditValidator', () => {
  let validator: AgentAuditValidator;

  beforeEach(() => {
    validator = new AgentAuditValidator();
  });

  describe('addAuditLogEntry', () => {
    it('should add audit log entry', () => {
      const entry: AuditLogEntry = {
        id: 'audit-1',
        timestamp: new Date(),
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        action: 'read',
        serviceId: 'email-service',
        resourceId: 'inbox-123',
        resourceType: 'emails',
        allowed: true,
      };

      validator.addAuditLogEntry(entry, 'source-1');

      const auditTrail = validator.getAuditTrail('agent-001');
      expect(auditTrail).toHaveLength(1);
      expect(auditTrail[0].id).toBe('audit-1');
    });

    it('should track entries by source', () => {
      const entry1: AuditLogEntry = {
        id: 'audit-1',
        timestamp: new Date(),
        agentId: 'agent-001',
        agentType: 'delegated',
        action: 'read',
        serviceId: 'service-1',
        resourceId: 'res-1',
        resourceType: 'resource',
        allowed: true,
      };

      const entry2: AuditLogEntry = {
        id: 'audit-2',
        timestamp: new Date(),
        agentId: 'agent-001',
        agentType: 'delegated',
        action: 'write',
        serviceId: 'service-2',
        resourceId: 'res-2',
        resourceType: 'resource',
        allowed: true,
      };

      validator.addAuditLogEntry(entry1, 'source-1');
      validator.addAuditLogEntry(entry2, 'source-2');

      const auditTrail = validator.getAuditTrail('agent-001');
      expect(auditTrail).toHaveLength(2);
    });
  });

  describe('validateAuditTrail', () => {
    it('should validate complete audit trail', async () => {
      const now = new Date();
      const test: AgentAuditTrailTest = {
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(now.getTime() - 1000),
            expectedLogged: true,
          },
          {
            serviceId: 'document-service',
            action: 'read',
            resourceId: 'doc-123',
            resourceType: 'documents',
            timestamp: new Date(now.getTime() - 500),
            expectedLogged: true,
          },
        ],
      };

      // Add audit log entries
      test.actions.forEach((action, index) => {
        validator.addAuditLogEntry(
          {
            id: `audit-${index}`,
            timestamp: action.timestamp,
            agentId: test.agentId,
            agentType: test.agentType,
            userId: test.userId,
            action: action.action,
            serviceId: action.serviceId,
            resourceId: action.resourceId,
            resourceType: action.resourceType,
            allowed: true,
          },
          'source-1'
        );
      });

      const result = await validator.validateAuditTrail(test);

      expect(result.passed).toBe(true);
      expect(result.auditLogComplete).toBe(true);
      expect(result.auditLogIntegrity).toBe(true);
      expect(result.crossServiceCorrelation).toBe(true);
    });

    it('should detect missing audit log entries', async () => {
      const now = new Date();
      const test: AgentAuditTrailTest = {
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(now.getTime() - 1000),
            expectedLogged: true,
          },
          {
            serviceId: 'document-service',
            action: 'read',
            resourceId: 'doc-123',
            resourceType: 'documents',
            timestamp: new Date(now.getTime() - 500),
            expectedLogged: true,
          },
        ],
      };

      // Only add one entry
      validator.addAuditLogEntry(
        {
          id: 'audit-1',
          timestamp: test.actions[0].timestamp,
          agentId: test.agentId,
          agentType: test.agentType,
          userId: test.userId,
          action: test.actions[0].action,
          serviceId: test.actions[0].serviceId,
          resourceId: test.actions[0].resourceId,
          resourceType: test.actions[0].resourceType,
          allowed: true,
        },
        'source-1'
      );

      const result = await validator.validateAuditTrail(test);

      expect(result.passed).toBe(false);
      expect(result.auditLogComplete).toBe(false);
      expect(result.missingEntries).toHaveLength(1);
    });

    it('should detect integrity issues', async () => {
      const now = new Date();
      const test: AgentAuditTrailTest = {
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(now.getTime() - 1000),
            expectedLogged: true,
          },
        ],
      };

      // Add entry with missing required fields
      validator.addAuditLogEntry(
        {
          id: '', // Missing ID
          timestamp: test.actions[0].timestamp,
          agentId: test.agentId,
          agentType: test.agentType,
          action: test.actions[0].action,
          serviceId: test.actions[0].serviceId,
          resourceId: test.actions[0].resourceId,
          resourceType: test.actions[0].resourceType,
          allowed: true,
        },
        'source-1'
      );

      const result = await validator.validateAuditTrail(test);

      expect(result.passed).toBe(false);
      expect(result.auditLogIntegrity).toBe(false);
      expect(result.integrityIssues?.length).toBeGreaterThan(0);
    });

    it('should validate cross-service correlation', async () => {
      const now = new Date();
      const test: AgentAuditTrailTest = {
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(now.getTime() - 1000),
            expectedLogged: true,
          },
          {
            serviceId: 'document-service',
            action: 'read',
            resourceId: 'doc-123',
            resourceType: 'documents',
            timestamp: new Date(now.getTime() - 500),
            expectedLogged: true,
          },
        ],
      };

      // Add entries with correlation IDs
      test.actions.forEach((action, index) => {
        validator.addAuditLogEntry(
          {
            id: `audit-${index}`,
            timestamp: action.timestamp,
            agentId: test.agentId,
            agentType: test.agentType,
            userId: test.userId,
            action: action.action,
            serviceId: action.serviceId,
            resourceId: action.resourceId,
            resourceType: action.resourceType,
            allowed: true,
            metadata: {
              correlationId: 'correlation-123',
            },
          },
          'source-1'
        );
      });

      const result = await validator.validateAuditTrail(test);

      expect(result.passed).toBe(true);
      expect(result.crossServiceCorrelation).toBe(true);
    });

    it('should detect missing user context for delegated access', async () => {
      const now = new Date();
      const test: AgentAuditTrailTest = {
        agentId: 'agent-001',
        agentType: 'delegated',
        userId: 'user-123',
        actions: [
          {
            serviceId: 'email-service',
            action: 'read',
            resourceId: 'inbox-123',
            resourceType: 'emails',
            timestamp: new Date(now.getTime() - 1000),
            expectedLogged: true,
          },
        ],
      };

      // Add entry without user context
      validator.addAuditLogEntry(
        {
          id: 'audit-1',
          timestamp: test.actions[0].timestamp,
          agentId: test.agentId,
          agentType: test.agentType,
          // Missing userId
          action: test.actions[0].action,
          serviceId: test.actions[0].serviceId,
          resourceId: test.actions[0].resourceId,
          resourceType: test.actions[0].resourceType,
          allowed: true,
        },
        'source-1'
      );

      const result = await validator.validateAuditTrail(test);

      expect(result.passed).toBe(false);
      expect(result.crossServiceCorrelation).toBe(false);
      expect(result.correlationIssues?.length).toBeGreaterThan(0);
    });
  });

  describe('analyzeAuditPatterns', () => {
    it('should analyze audit patterns and detect anomalies', () => {
      const now = new Date();
      
      // Add multiple log entries
      for (let i = 0; i < 5; i++) {
        validator.addAuditLogEntry(
          {
            id: `audit-${i}`,
            timestamp: new Date(now.getTime() - i * 1000),
            agentId: 'agent-001',
            agentType: 'delegated',
            action: 'read',
            serviceId: `service-${i % 3}`,
            resourceId: `res-${i}`,
            resourceType: 'resource',
            allowed: i < 2, // Some denied
          },
          'source-1'
        );
      }

      const analysis = validator.analyzeAuditPatterns('agent-001');

      expect(analysis.patterns).toBeDefined();
      expect(analysis.patterns.serviceAccess).toBeDefined();
      expect(analysis.patterns.actionFrequency).toBeDefined();
      expect(analysis.patterns.denialRate).toBeDefined();
    });

    it('should detect high denial rate anomaly', () => {
      const now = new Date();
      
      // Add mostly denied entries
      for (let i = 0; i < 10; i++) {
        validator.addAuditLogEntry(
          {
            id: `audit-${i}`,
            timestamp: new Date(now.getTime() - i * 1000),
            agentId: 'agent-001',
            agentType: 'delegated',
            action: 'read',
            serviceId: 'service-1',
            resourceId: `res-${i}`,
            resourceType: 'resource',
            allowed: i < 2, // Most denied
          },
          'source-1'
        );
      }

      const analysis = validator.analyzeAuditPatterns('agent-001');

      expect(analysis.anomalies.length).toBeGreaterThan(0);
      expect(analysis.anomalies.some(a => a.includes('High denial rate'))).toBe(true);
    });

    it('should detect excessive service access anomaly', () => {
      const now = new Date();
      
      // Add entries accessing many services
      for (let i = 0; i < 15; i++) {
        validator.addAuditLogEntry(
          {
            id: `audit-${i}`,
            timestamp: new Date(now.getTime() - i * 1000),
            agentId: 'agent-001',
            agentType: 'delegated',
            action: 'read',
            serviceId: `service-${i}`,
            resourceId: `res-${i}`,
            resourceType: 'resource',
            allowed: true,
          },
          'source-1'
        );
      }

      const analysis = validator.analyzeAuditPatterns('agent-001');

      expect(analysis.anomalies.length).toBeGreaterThan(0);
      expect(analysis.anomalies.some(a => a.includes('different services'))).toBe(true);
    });
  });

  describe('getAuditTrail', () => {
    it('should filter audit trail by date range', () => {
      const now = new Date();
      const startDate = new Date(now.getTime() - 5000);
      const endDate = new Date(now.getTime() - 1000);

      // Add entries with different timestamps
      validator.addAuditLogEntry(
        {
          id: 'audit-1',
          timestamp: new Date(now.getTime() - 6000), // Outside range
          agentId: 'agent-001',
          agentType: 'delegated',
          action: 'read',
          serviceId: 'service-1',
          resourceId: 'res-1',
          resourceType: 'resource',
          allowed: true,
        },
        'source-1'
      );

      validator.addAuditLogEntry(
        {
          id: 'audit-2',
          timestamp: new Date(now.getTime() - 3000), // Inside range
          agentId: 'agent-001',
          agentType: 'delegated',
          action: 'read',
          serviceId: 'service-1',
          resourceId: 'res-2',
          resourceType: 'resource',
          allowed: true,
        },
        'source-1'
      );

      const filtered = validator.getAuditTrail('agent-001', {
        startDate,
        endDate,
      });

      expect(filtered).toHaveLength(1);
      expect(filtered[0].id).toBe('audit-2');
    });

    it('should filter audit trail by service ID', () => {
      const now = new Date();

      validator.addAuditLogEntry(
        {
          id: 'audit-1',
          timestamp: now,
          agentId: 'agent-001',
          agentType: 'delegated',
          action: 'read',
          serviceId: 'email-service',
          resourceId: 'res-1',
          resourceType: 'resource',
          allowed: true,
        },
        'source-1'
      );

      validator.addAuditLogEntry(
        {
          id: 'audit-2',
          timestamp: now,
          agentId: 'agent-001',
          agentType: 'delegated',
          action: 'read',
          serviceId: 'document-service',
          resourceId: 'res-2',
          resourceType: 'resource',
          allowed: true,
        },
        'source-1'
      );

      const filtered = validator.getAuditTrail('agent-001', {
        serviceId: 'email-service',
      });

      expect(filtered).toHaveLength(1);
      expect(filtered[0].serviceId).toBe('email-service');
    });
  });
});
