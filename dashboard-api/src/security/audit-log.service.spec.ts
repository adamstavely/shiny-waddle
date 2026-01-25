/**
 * Security Audit Log Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SecurityAuditLogService, SecurityAuditEventType, SecurityAuditSeverity, CreateSecurityAuditLogDto } from './audit-log.service';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('SecurityAuditLogService', () => {
  let service: SecurityAuditLogService;

  const mockLogDto: CreateSecurityAuditLogDto = {
    type: SecurityAuditEventType.LOGIN_SUCCESS,
    action: 'User login',
    description: 'User successfully logged in',
    userId: 'user-1',
    username: 'testuser',
    ipAddress: '192.168.1.1',
    success: true,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [SecurityAuditLogService],
    }).compile();

    service = module.get<SecurityAuditLogService>(SecurityAuditLogService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
    fs.rename = jest.fn().mockResolvedValue(undefined);

    // Clear audit logs
    (service as any).auditLogs = [];
  });

  describe('log', () => {
    it('should successfully create an audit log entry', async () => {
      // Arrange
      (service as any).auditLogs = [];

      // Act
      const result = await service.log(mockLogDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.type).toBe(mockLogDto.type);
      expect(result.action).toBe(mockLogDto.action);
      expect(result.description).toBe(mockLogDto.description);
      expect(result.userId).toBe(mockLogDto.userId);
      expect(result.username).toBe(mockLogDto.username);
      expect(result.ipAddress).toBe(mockLogDto.ipAddress);
      expect(result.success).toBe(true);
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should assign default severity when not provided', async () => {
      // Arrange
      (service as any).auditLogs = [];
      const dtoWithoutSeverity: CreateSecurityAuditLogDto = {
        ...mockLogDto,
        severity: undefined,
      };

      // Act
      const result = await service.log(dtoWithoutSeverity);

      // Assert
      expect(result.severity).toBeDefined();
      expect(Object.values(SecurityAuditSeverity)).toContain(result.severity);
    });

    it('should use provided severity when specified', async () => {
      // Arrange
      (service as any).auditLogs = [];
      const dtoWithSeverity: CreateSecurityAuditLogDto = {
        ...mockLogDto,
        severity: SecurityAuditSeverity.HIGH,
      };

      // Act
      const result = await service.log(dtoWithSeverity);

      // Assert
      expect(result.severity).toBe(SecurityAuditSeverity.HIGH);
    });

    it('should default success to true when not provided', async () => {
      // Arrange
      (service as any).auditLogs = [];
      const dtoWithoutSuccess: CreateSecurityAuditLogDto = {
        ...mockLogDto,
        success: undefined,
      };

      // Act
      const result = await service.log(dtoWithoutSuccess);

      // Assert
      expect(result.success).toBe(true);
    });

    it('should handle failure events', async () => {
      // Arrange
      (service as any).auditLogs = [];
      const failureDto: CreateSecurityAuditLogDto = {
        ...mockLogDto,
        type: SecurityAuditEventType.LOGIN_FAILURE,
        success: false,
        errorMessage: 'Invalid credentials',
      };

      // Act
      const result = await service.log(failureDto);

      // Assert
      expect(result.success).toBe(false);
      expect(result.errorMessage).toBe('Invalid credentials');
    });

    it('should include metadata when provided', async () => {
      // Arrange
      (service as any).auditLogs = [];
      const dtoWithMetadata: CreateSecurityAuditLogDto = {
        ...mockLogDto,
        metadata: { sessionId: 'session-123', requestId: 'req-456' },
      };

      // Act
      const result = await service.log(dtoWithMetadata);

      // Assert
      expect(result.metadata).toEqual({ sessionId: 'session-123', requestId: 'req-456' });
    });
  });

  describe('queryLogs', () => {
    beforeEach(() => {
      (service as any).auditLogs = [
        {
          id: 'log-1',
          type: SecurityAuditEventType.LOGIN_SUCCESS,
          severity: SecurityAuditSeverity.LOW,
          action: 'Login',
          description: 'User logged in',
          userId: 'user-1',
          timestamp: new Date('2024-01-01'),
          success: true,
        },
        {
          id: 'log-2',
          type: SecurityAuditEventType.LOGIN_FAILURE,
          severity: SecurityAuditSeverity.MEDIUM,
          action: 'Login failed',
          description: 'Failed login attempt',
          userId: 'user-2',
          timestamp: new Date('2024-01-02'),
          success: false,
        },
        {
          id: 'log-3',
          type: SecurityAuditEventType.POLICY_CREATED,
          severity: SecurityAuditSeverity.MEDIUM,
          action: 'Policy created',
          description: 'New policy created',
          userId: 'user-1',
          timestamp: new Date('2024-01-03'),
          success: true,
        },
      ];
    });

    it('should return all logs when no filters provided', async () => {
      // Act
      const result = await service.queryLogs({});

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by event type', async () => {
      // Act
      const result = await service.queryLogs({
        type: SecurityAuditEventType.LOGIN_SUCCESS,
      });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].type).toBe(SecurityAuditEventType.LOGIN_SUCCESS);
    });

    it('should filter by severity', async () => {
      // Act
      const result = await service.queryLogs({
        severity: SecurityAuditSeverity.MEDIUM,
      });

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(log => log.severity === SecurityAuditSeverity.MEDIUM)).toBe(true);
    });

    it('should filter by userId', async () => {
      // Act
      const result = await service.queryLogs({
        userId: 'user-1',
      });

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(log => log.userId === 'user-1')).toBe(true);
    });

    it('should filter by success status', async () => {
      // Act
      const result = await service.queryLogs({
        success: false,
      });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].success).toBe(false);
    });

    it('should filter by date range', async () => {
      // Act
      const result = await service.queryLogs({
        startDate: new Date('2024-01-02'),
        endDate: new Date('2024-01-03'),
      });

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(log => 
        log.timestamp >= new Date('2024-01-02') && 
        log.timestamp <= new Date('2024-01-03')
      )).toBe(true);
    });

    it('should combine multiple filters', async () => {
      // Act
      const result = await service.queryLogs({
        userId: 'user-1',
        success: true,
      });

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(log => log.userId === 'user-1' && log.success === true)).toBe(true);
    });

    it('should limit results when limit is specified', async () => {
      // Act
      const result = await service.queryLogs({
        limit: 2,
      });

      // Assert
      expect(result.length).toBe(2);
    });
  });

  describe('getDefaultSeverity', () => {
    it('should return LOW for LOGIN_SUCCESS', () => {
      // Act
      const severity = (service as any).getDefaultSeverity(SecurityAuditEventType.LOGIN_SUCCESS);

      // Assert
      expect(severity).toBe(SecurityAuditSeverity.LOW);
    });

    it('should return MEDIUM for LOGIN_FAILURE', () => {
      // Act
      const severity = (service as any).getDefaultSeverity(SecurityAuditEventType.LOGIN_FAILURE);

      // Assert
      expect(severity).toBe(SecurityAuditSeverity.MEDIUM);
    });

    it('should return CRITICAL for BRUTE_FORCE_ATTEMPT', () => {
      // Act
      const severity = (service as any).getDefaultSeverity(SecurityAuditEventType.BRUTE_FORCE_ATTEMPT);

      // Assert
      expect(severity).toBe(SecurityAuditSeverity.CRITICAL);
    });

    it('should return MEDIUM as default for unknown event types', () => {
      // Act
      const severity = (service as any).getDefaultSeverity('unknown-type' as any);

      // Assert
      expect(severity).toBe(SecurityAuditSeverity.MEDIUM);
    });
  });
});
