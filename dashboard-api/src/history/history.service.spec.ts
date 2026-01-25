/**
 * History Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { HistoryService } from './history.service';
import { CreateTestExecutionDto, CreateAuditLogDto, CreateActivityDto } from './dto/create-history.dto';
import { TestExecutionEntity, AuditLogEntity, ActivityEntity, AuditLogType, ActivityType, TestExecutionStatus } from './entities/history.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('HistoryService', () => {
  let service: HistoryService;

  const mockTestExecutionDto: CreateTestExecutionDto = {
    suiteName: 'Test Suite',
    application: 'app-1',
    team: 'team-1',
    status: TestExecutionStatus.COMPLETED,
    testCount: 10,
    passedCount: 8,
    failedCount: 2,
    score: 85,
    metadata: { user: 'user-1' },
  };

  const mockAuditLogDto: CreateAuditLogDto = {
    type: AuditLogType.POLICY_CHANGE,
    user: 'user-1',
    action: 'Updated policy',
    description: 'Policy XYZ updated',
    application: 'app-1',
    team: 'team-1',
  };

  const mockActivityDto: CreateActivityDto = {
    type: ActivityType.POLICY_UPDATE,
    user: 'user-1',
    action: 'Updated policy',
    details: 'Policy XYZ updated',
    application: 'app-1',
    team: 'team-1',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [HistoryService],
    }).compile();

    service = module.get<HistoryService>(HistoryService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).testExecutions = [];
    (service as any).auditLogs = [];
    (service as any).activities = [];
  });

  describe('createTestExecution', () => {
    it('should successfully create a test execution', async () => {
      // Arrange
      (service as any).testExecutions = [];
      (service as any).activities = [];

      // Act
      const result = await service.createTestExecution(mockTestExecutionDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.suiteName).toBe(mockTestExecutionDto.suiteName);
      expect(result.application).toBe(mockTestExecutionDto.application);
      expect(result.team).toBe(mockTestExecutionDto.team);
      expect(result.status).toBe(mockTestExecutionDto.status);
      expect(result.score).toBe(mockTestExecutionDto.score);
      expect(result.timestamp).toBeInstanceOf(Date);
    });

    it('should create an activity when test execution is created', async () => {
      // Arrange
      (service as any).testExecutions = [];
      (service as any).activities = [];

      // Act
      await service.createTestExecution(mockTestExecutionDto);

      // Assert
      expect((service as any).activities.length).toBe(1);
      const activity = (service as any).activities[0];
      expect(activity.type).toBe(ActivityType.TEST_EXECUTION);
      expect(activity.action).toContain('completed test suite');
    });
  });

  describe('findAllTestExecutions', () => {
    beforeEach(() => {
      (service as any).testExecutions = [
        {
          id: 'exec-1',
          suiteName: 'Suite 1',
          application: 'app-1',
          team: 'team-1',
          status: TestExecutionStatus.COMPLETED,
          testCount: 10,
          passedCount: 8,
          failedCount: 2,
          score: 85,
          timestamp: new Date('2024-01-01'),
        },
        {
          id: 'exec-2',
          suiteName: 'Suite 2',
          application: 'app-1',
          team: 'team-1',
          status: TestExecutionStatus.FAILED,
          testCount: 10,
          passedCount: 6,
          failedCount: 4,
          score: 60,
          timestamp: new Date('2024-01-02'),
        },
        {
          id: 'exec-3',
          suiteName: 'Suite 3',
          application: 'app-2',
          team: 'team-2',
          status: TestExecutionStatus.COMPLETED,
          testCount: 10,
          passedCount: 9,
          failedCount: 1,
          score: 90,
          timestamp: new Date('2024-01-03'),
        },
      ];
    });

    it('should return all test executions when no filters provided', async () => {
      // Act
      const result = await service.findAllTestExecutions();

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by application', async () => {
      // Act
      const result = await service.findAllTestExecutions('app-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(e => e.application === 'app-1')).toBe(true);
    });

    it('should filter by team', async () => {
      // Act
      const result = await service.findAllTestExecutions(undefined, 'team-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(e => e.team === 'team-1')).toBe(true);
    });

    it('should filter by status', async () => {
      // Act
      const result = await service.findAllTestExecutions(undefined, undefined, TestExecutionStatus.COMPLETED);

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(e => e.status === TestExecutionStatus.COMPLETED)).toBe(true);
    });

    it('should filter by date range', async () => {
      // Act
      const result = await service.findAllTestExecutions(
        undefined,
        undefined,
        undefined,
        '2024-01-02',
        '2024-01-02'
      );

      // Assert
      expect(result.length).toBe(1);
    });

    it('should sort by timestamp descending (newest first)', async () => {
      // Act
      const result = await service.findAllTestExecutions();

      // Assert
      expect(result[0].timestamp.getTime()).toBeGreaterThan(result[1].timestamp.getTime());
    });
  });

  describe('findOneTestExecution', () => {
    beforeEach(() => {
      (service as any).testExecutions = [
        { id: 'exec-1', suiteName: 'Suite 1' },
      ];
    });

    it('should return execution when found', async () => {
      // Act
      const result = await service.findOneTestExecution('exec-1');

      // Assert
      expect(result.id).toBe('exec-1');
      expect(result.suiteName).toBe('Suite 1');
    });

    it('should throw NotFoundException when execution not found', async () => {
      // Act & Assert
      await expect(
        service.findOneTestExecution('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('createAuditLog', () => {
    it('should successfully create an audit log', async () => {
      // Arrange
      (service as any).auditLogs = [];

      // Act
      const result = await service.createAuditLog(mockAuditLogDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.type).toBe(mockAuditLogDto.type);
      expect(result.user).toBe(mockAuditLogDto.user);
      expect(result.action).toBe(mockAuditLogDto.action);
      expect(result.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('findAllAuditLogs', () => {
    beforeEach(() => {
      (service as any).auditLogs = [
        {
          id: 'log-1',
          type: AuditLogType.POLICY_CHANGE,
          action: 'Updated policy',
          description: 'Policy updated',
          user: 'user-1',
          application: 'app-1',
          team: 'team-1',
          timestamp: new Date('2024-01-01'),
        },
        {
          id: 'log-2',
          type: AuditLogType.POLICY_CHANGE,
          action: 'Created policy',
          description: 'Policy created',
          user: 'user-1',
          application: 'app-1',
          team: 'team-1',
          timestamp: new Date('2024-01-02'),
        },
        {
          id: 'log-3',
          type: AuditLogType.POLICY_CHANGE,
          action: 'Updated policy',
          description: 'Policy updated',
          user: 'user-2',
          application: 'app-2',
          team: 'team-2',
          timestamp: new Date('2024-01-03'),
        },
      ];
    });

    it('should return all audit logs when no filters provided', async () => {
      // Act
      const result = await service.findAllAuditLogs();

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by type', async () => {
      // Act
      const result = await service.findAllAuditLogs(AuditLogType.POLICY_CHANGE);

      // Assert
      expect(result.length).toBe(3);
      expect(result.every(l => l.type === AuditLogType.POLICY_CHANGE)).toBe(true);
    });

    it('should filter by application', async () => {
      // Act
      const result = await service.findAllAuditLogs(undefined, 'app-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(l => l.application === 'app-1')).toBe(true);
    });

    it('should filter by team', async () => {
      // Act
      const result = await service.findAllAuditLogs(undefined, undefined, 'team-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(l => l.team === 'team-1')).toBe(true);
    });
  });

  describe('createActivity', () => {
    it('should successfully create an activity', async () => {
      // Arrange
      (service as any).activities = [];

      // Act
      const result = await service.createActivity(mockActivityDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.type).toBe(mockActivityDto.type);
      expect(result.user).toBe(mockActivityDto.user);
      expect(result.action).toBe(mockActivityDto.action);
      expect(result.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('findAllActivities', () => {
    beforeEach(() => {
      (service as any).activities = [
        {
          id: 'activity-1',
          type: ActivityType.POLICY_UPDATE,
          user: 'user-1',
          action: 'Updated policy',
          details: 'Policy updated',
          application: 'app-1',
          team: 'team-1',
          timestamp: new Date('2024-01-01'),
        },
        {
          id: 'activity-2',
          type: ActivityType.TEST_EXECUTION,
          user: 'user-1',
          action: 'Ran tests',
          details: 'Test execution completed',
          application: 'app-1',
          team: 'team-1',
          timestamp: new Date('2024-01-02'),
        },
        {
          id: 'activity-3',
          type: ActivityType.POLICY_UPDATE,
          user: 'user-2',
          action: 'Updated policy',
          details: 'Policy updated',
          application: 'app-2',
          team: 'team-2',
          timestamp: new Date('2024-01-03'),
        },
      ];
    });

    it('should return all activities when no filters provided', async () => {
      // Act
      const result = await service.findAllActivities();

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by type', async () => {
      // Act
      const result = await service.findAllActivities(ActivityType.POLICY_UPDATE);

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(a => a.type === ActivityType.POLICY_UPDATE)).toBe(true);
    });

    it('should filter by application', async () => {
      // Act
      const result = await service.findAllActivities(undefined, 'app-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(a => a.application === 'app-1')).toBe(true);
    });

    it('should filter by team', async () => {
      // Act
      const result = await service.findAllActivities(undefined, undefined, 'team-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(a => a.team === 'team-1')).toBe(true);
    });

    it('should sort by timestamp descending (newest first)', async () => {
      // Act
      const result = await service.findAllActivities();

      // Assert
      expect(result[0].timestamp.getTime()).toBeGreaterThan(result[1].timestamp.getTime());
    });
  });
});
