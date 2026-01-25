/**
 * RLS/CLS Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { RLSCLSController } from './rls-cls.controller';
import { RLSCLSService } from './rls-cls.service';
import {
  TestRLSCoverageDto,
  TestCLSCoverageDto,
  TestDynamicMaskingDto,
  TestCrossTenantIsolationDto,
} from './dto/rls-cls.dto';

describe('RLSCLSController', () => {
  let controller: RLSCLSController;
  let rlsClsService: jest.Mocked<RLSCLSService>;

  const mockRLSCoverage = {
    database: 'test_db',
    totalTables: 10,
    tablesWithRLS: 8,
    tablesWithoutRLS: ['table1', 'table2'],
    coveragePercentage: 80,
    policies: [],
  };

  const mockCLSCoverage = {
    database: 'test_db',
    totalTables: 10,
    tablesWithCLS: 7,
    tablesWithoutCLS: ['table1', 'table2', 'table3'],
    coveragePercentage: 70,
    policies: [],
  };

  const mockTestResult = {
    passed: true,
    testType: 'rls-cls' as const,
    testName: 'Dynamic Masking Test',
    timestamp: new Date(),
    details: {},
  };

  beforeEach(async () => {
    const mockRLSCLSService = {
      testRLSCoverage: jest.fn(),
      testCLSCoverage: jest.fn(),
      testDynamicMasking: jest.fn(),
      testCrossTenantIsolation: jest.fn(),
      testPolicyBypass: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RLSCLSController],
      providers: [
        {
          provide: RLSCLSService,
          useValue: mockRLSCLSService,
        },
      ],
    }).compile();

    controller = module.get<RLSCLSController>(RLSCLSController);
    rlsClsService = module.get(RLSCLSService) as jest.Mocked<RLSCLSService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testRLSCoverage', () => {
    const dto: TestRLSCoverageDto = {
      database: {
        type: 'postgresql',
        database: 'test_db',
      },
    };

    it('should test RLS coverage', async () => {
      // Arrange
      rlsClsService.testRLSCoverage.mockResolvedValue(mockRLSCoverage as any);

      // Act
      const result = await controller.testRLSCoverage(dto);

      // Assert
      expect(result).toEqual(mockRLSCoverage);
      expect(rlsClsService.testRLSCoverage).toHaveBeenCalledTimes(1);
      expect(rlsClsService.testRLSCoverage).toHaveBeenCalledWith(dto);
    });
  });

  describe('testCLSCoverage', () => {
    const dto: TestCLSCoverageDto = {
      database: {
        type: 'postgresql',
        database: 'test_db',
      },
    };

    it('should test CLS coverage', async () => {
      // Arrange
      rlsClsService.testCLSCoverage.mockResolvedValue(mockCLSCoverage as any);

      // Act
      const result = await controller.testCLSCoverage(dto);

      // Assert
      expect(result).toEqual(mockCLSCoverage);
      expect(rlsClsService.testCLSCoverage).toHaveBeenCalledTimes(1);
      expect(rlsClsService.testCLSCoverage).toHaveBeenCalledWith(dto);
    });
  });

  describe('testDynamicMasking', () => {
    it('should test dynamic masking with applicationId', async () => {
      // Arrange
      const dto: TestDynamicMaskingDto & { applicationId?: string; databaseId?: string } = {
        applicationId: 'app-1',
        databaseId: 'db-1',
        query: { name: 'test-query', sql: 'SELECT * FROM users' },
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        maskingRules: [],
      };
      rlsClsService.testDynamicMasking.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testDynamicMasking(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(rlsClsService.testDynamicMasking).toHaveBeenCalledWith(dto);
    });

    it('should test dynamic masking without applicationId', async () => {
      // Arrange
      const dto: TestDynamicMaskingDto = {
        query: { name: 'test-query', sql: 'SELECT * FROM users' },
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        maskingRules: [],
      };
      rlsClsService.testDynamicMasking.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testDynamicMasking(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(rlsClsService.testDynamicMasking).toHaveBeenCalledWith(dto);
    });
  });

  describe('testCrossTenantIsolation', () => {
    const dto: TestCrossTenantIsolationDto = {
      tenant1: 'tenant-1',
      tenant2: 'tenant-2',
      testQueries: [
        { name: 'query-1', sql: 'SELECT * FROM users' },
      ],
    };

    const mockCrossTenantResult = {
      tenant1: 'tenant-1',
      tenant2: 'tenant-2',
      testQueries: [],
      isolationVerified: true,
      violations: [],
    };

    it('should test cross-tenant isolation', async () => {
      // Arrange
      rlsClsService.testCrossTenantIsolation.mockResolvedValue(mockCrossTenantResult as any);

      // Act
      const result = await controller.testCrossTenantIsolation(dto);

      // Assert
      expect(result).toEqual(mockCrossTenantResult);
      expect(rlsClsService.testCrossTenantIsolation).toHaveBeenCalledWith(dto);
    });
  });

  describe('testPolicyBypass', () => {
    it('should test policy bypass with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        databaseId: 'db-1',
      };
      rlsClsService.testPolicyBypass.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testPolicyBypass(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(rlsClsService.testPolicyBypass).toHaveBeenCalledWith(dto);
    });

    it('should test policy bypass without applicationId', async () => {
      // Arrange
      const dto = {
        userId: 'user-1',
        resourceId: 'resource-1',
        resourceType: 'table',
      };
      rlsClsService.testPolicyBypass.mockResolvedValue([mockTestResult]);

      // Act
      const result = await controller.testPolicyBypass(dto);

      // Assert
      expect(result).toEqual([mockTestResult]);
      expect(rlsClsService.testPolicyBypass).toHaveBeenCalledWith(dto);
    });
  });
});
