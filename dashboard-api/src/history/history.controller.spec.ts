/**
 * History Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { HistoryController } from './history.controller';
import { HistoryService } from './history.service';
import { CreateTestExecutionDto, CreateAuditLogDto, CreateActivityDto } from './dto/create-history.dto';

describe('HistoryController', () => {
  let controller: HistoryController;
  let historyService: jest.Mocked<HistoryService>;

  const mockTestExecution = {
    id: 'exec-1',
    application: 'app-1',
    team: 'team-1',
    status: 'passed',
    createdAt: new Date(),
  };

  const mockAuditLog = {
    id: 'audit-1',
    type: 'policy_change',
    application: 'app-1',
    team: 'team-1',
    createdAt: new Date(),
  };

  const mockActivity = {
    id: 'activity-1',
    type: 'test_run',
    application: 'app-1',
    team: 'team-1',
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockHistoryService = {
      createTestExecution: jest.fn(),
      findAllTestExecutions: jest.fn(),
      findOneTestExecution: jest.fn(),
      compareExecutions: jest.fn(),
      createAuditLog: jest.fn(),
      findAllAuditLogs: jest.fn(),
      findOneAuditLog: jest.fn(),
      createActivity: jest.fn(),
      findAllActivities: jest.fn(),
      findOneActivity: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [HistoryController],
      providers: [
        {
          provide: HistoryService,
          useValue: mockHistoryService,
        },
      ],
    }).compile();

    controller = module.get<HistoryController>(HistoryController);
    historyService = module.get(HistoryService) as jest.Mocked<HistoryService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Test Executions', () => {
    describe('createTestExecution', () => {
      const dto: CreateTestExecutionDto = {
        suiteName: 'Test Suite',
        application: 'app-1',
        team: 'team-1',
        status: 'completed' as any,
        testCount: 10,
        passedCount: 8,
        failedCount: 2,
        score: 80,
      };

      it('should create a test execution', async () => {
        // Arrange
        historyService.createTestExecution.mockResolvedValue(mockTestExecution as any);

        // Act
        const result = await controller.createTestExecution(dto);

        // Assert
        expect(result).toEqual(mockTestExecution);
        expect(historyService.createTestExecution).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllTestExecutions', () => {
      it('should find all test executions', async () => {
        // Arrange
        historyService.findAllTestExecutions.mockResolvedValue([mockTestExecution] as any);

        // Act
        const result = await controller.findAllTestExecutions();

        // Assert
        expect(result).toEqual([mockTestExecution]);
        expect(historyService.findAllTestExecutions).toHaveBeenCalledWith(undefined, undefined, undefined, undefined, undefined);
      });

      it('should find test executions with filters', async () => {
        // Arrange
        historyService.findAllTestExecutions.mockResolvedValue([mockTestExecution] as any);

        // Act
        const result = await controller.findAllTestExecutions('app-1', 'team-1', 'passed', '2024-01-01', '2024-12-31');

        // Assert
        expect(result).toEqual([mockTestExecution]);
        expect(historyService.findAllTestExecutions).toHaveBeenCalledWith('app-1', 'team-1', 'passed', '2024-01-01', '2024-12-31');
      });
    });

    describe('findOneTestExecution', () => {
      it('should find one test execution', async () => {
        // Arrange
        historyService.findOneTestExecution.mockResolvedValue(mockTestExecution as any);

        // Act
        const result = await controller.findOneTestExecution('exec-1');

        // Assert
        expect(result).toEqual(mockTestExecution);
        expect(historyService.findOneTestExecution).toHaveBeenCalledWith('exec-1');
      });
    });

    describe('compareExecutions', () => {
      it('should compare two executions', async () => {
        // Arrange
        const comparison = {
          execution1: mockTestExecution as any,
          execution2: { ...mockTestExecution, id: 'exec-2' } as any,
          differences: [],
        };
        historyService.compareExecutions.mockResolvedValue(comparison as any);

        // Act
        const result = await controller.compareExecutions('exec-1', 'exec-2');

        // Assert
        expect(result).toEqual(comparison);
        expect(historyService.compareExecutions).toHaveBeenCalledWith('exec-1', 'exec-2');
      });
    });
  });

  describe('Audit Logs', () => {
    describe('createAuditLog', () => {
      const dto: CreateAuditLogDto = {
        type: 'policy-change' as any,
        action: 'updated',
        description: 'Policy updated',
        user: 'user-1',
        application: 'app-1',
        team: 'team-1',
      };

      it('should create an audit log', async () => {
        // Arrange
        historyService.createAuditLog.mockResolvedValue(mockAuditLog as any);

        // Act
        const result = await controller.createAuditLog(dto);

        // Assert
        expect(result).toEqual(mockAuditLog);
        expect(historyService.createAuditLog).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllAuditLogs', () => {
      it('should find all audit logs', async () => {
        // Arrange
        historyService.findAllAuditLogs.mockResolvedValue([mockAuditLog] as any);

        // Act
        const result = await controller.findAllAuditLogs();

        // Assert
        expect(result).toEqual([mockAuditLog]);
        expect(historyService.findAllAuditLogs).toHaveBeenCalledWith(undefined, undefined, undefined, undefined, undefined);
      });

      it('should find audit logs with filters', async () => {
        // Arrange
        historyService.findAllAuditLogs.mockResolvedValue([mockAuditLog] as any);

        // Act
        const result = await controller.findAllAuditLogs('policy_change', 'app-1', 'team-1', '2024-01-01', '2024-12-31');

        // Assert
        expect(result).toEqual([mockAuditLog]);
        expect(historyService.findAllAuditLogs).toHaveBeenCalledWith('policy_change', 'app-1', 'team-1', '2024-01-01', '2024-12-31');
      });
    });

    describe('findOneAuditLog', () => {
      it('should find one audit log', async () => {
        // Arrange
        historyService.findOneAuditLog.mockResolvedValue(mockAuditLog as any);

        // Act
        const result = await controller.findOneAuditLog('audit-1');

        // Assert
        expect(result).toEqual(mockAuditLog);
        expect(historyService.findOneAuditLog).toHaveBeenCalledWith('audit-1');
      });
    });
  });

  describe('Activities', () => {
    describe('createActivity', () => {
      const dto: CreateActivityDto = {
        type: 'test_run' as any,
        user: 'user-1',
        action: 'ran test',
        details: 'Test execution',
        application: 'app-1',
        team: 'team-1',
      };

      it('should create an activity', async () => {
        // Arrange
        historyService.createActivity.mockResolvedValue(mockActivity as any);

        // Act
        const result = await controller.createActivity(dto);

        // Assert
        expect(result).toEqual(mockActivity);
        expect(historyService.createActivity).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllActivities', () => {
      it('should find all activities', async () => {
        // Arrange
        historyService.findAllActivities.mockResolvedValue([mockActivity] as any);

        // Act
        const result = await controller.findAllActivities();

        // Assert
        expect(result).toEqual([mockActivity]);
        expect(historyService.findAllActivities).toHaveBeenCalledWith(undefined, undefined, undefined, undefined, undefined);
      });

      it('should find activities with filters', async () => {
        // Arrange
        historyService.findAllActivities.mockResolvedValue([mockActivity] as any);

        // Act
        const result = await controller.findAllActivities('test_run', 'app-1', 'team-1', '2024-01-01', '2024-12-31');

        // Assert
        expect(result).toEqual([mockActivity]);
        expect(historyService.findAllActivities).toHaveBeenCalledWith('test_run', 'app-1', 'team-1', '2024-01-01', '2024-12-31');
      });
    });

    describe('findOneActivity', () => {
      it('should find one activity', async () => {
        // Arrange
        historyService.findOneActivity.mockResolvedValue(mockActivity as any);

        // Act
        const result = await controller.findOneActivity('activity-1');

        // Assert
        expect(result).toEqual(mockActivity);
        expect(historyService.findOneActivity).toHaveBeenCalledWith('activity-1');
      });
    });
  });
});
