/**
 * RLS/CLS Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { RLSCLSService } from './rls-cls.service';
import { RLSCLSTester } from '../../heimdall-framework/services/rls-cls-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/rls-cls-tester');

describe('RLSCLSService', () => {
  let service: RLSCLSService;
  let tester: jest.Mocked<RLSCLSTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    tester = {
      testRLSCoverage: jest.fn(),
      testCLSCoverage: jest.fn(),
      testDynamicMasking: jest.fn(),
      testCrossTenantIsolation: jest.fn(),
      testPolicyBypassAttempts: jest.fn(),
    } as any;

    // Mock the constructor
    (RLSCLSTester as jest.Mock).mockImplementation(() => tester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [RLSCLSService],
    }).compile();

    service = module.get<RLSCLSService>(RLSCLSService);
  });

  describe('testRLSCoverage', () => {
    it('should successfully test RLS coverage', async () => {
      const mockResult = {
        database: 'test_db',
        totalTables: 5,
        tablesWithRLS: 3,
        tablesWithoutRLS: ['table1', 'table2'],
        coveragePercentage: 60,
        policies: [],
      };

      tester.testRLSCoverage.mockResolvedValue(mockResult);

      const result = await service.testRLSCoverage({
        database: { type: 'postgresql', database: 'test_db' },
      });

      expect(result).toEqual(mockResult);
      expect(tester.testRLSCoverage).toHaveBeenCalledWith({
        type: 'postgresql',
        database: 'test_db',
      });
    });

    it('should throw ValidationException for missing database', async () => {
      await expect(
        service.testRLSCoverage({ database: null as any }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid database type', async () => {
      await expect(
        service.testRLSCoverage({
          database: { type: 'invalid' as any, database: 'test' },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw InternalServerException on service error', async () => {
      tester.testRLSCoverage.mockRejectedValue(new Error('Database connection failed'));

      await expect(
        service.testRLSCoverage({
          database: { type: 'postgresql', database: 'test_db' },
        }),
      ).rejects.toThrow(InternalServerException);
    });
  });

  describe('testCLSCoverage', () => {
    it('should successfully test CLS coverage', async () => {
      const mockResult = {
        database: 'test_db',
        totalTables: 5,
        tablesWithCLS: 2,
        tablesWithoutCLS: ['table1', 'table2', 'table3'],
        coveragePercentage: 40,
        policies: [],
      };

      tester.testCLSCoverage.mockResolvedValue(mockResult);

      const result = await service.testCLSCoverage({
        database: { type: 'postgresql', database: 'test_db' },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing database type', async () => {
      await expect(
        service.testCLSCoverage({
          database: { database: 'test_db' } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testDynamicMasking', () => {
    it('should successfully test dynamic masking', async () => {
      const mockResult = {
        testType: 'data-behavior' as const,
        testName: 'Dynamic Data Masking Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      tester.testDynamicMasking.mockResolvedValue(mockResult);

      const result = await service.testDynamicMasking({
        query: { name: 'test', sql: 'SELECT * FROM users' },
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        maskingRules: [{ table: 'users', column: 'email', maskingType: 'partial' as const, applicableRoles: ['viewer'] }],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing masking rules', async () => {
      await expect(
        service.testDynamicMasking({
          query: { name: 'test', sql: 'SELECT * FROM users' },
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          maskingRules: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing query', async () => {
      await expect(
        service.testDynamicMasking({
          query: null as any,
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          maskingRules: [{ table: 'users', column: 'email', maskingType: 'partial' as const, applicableRoles: ['viewer'] }],
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testCrossTenantIsolation', () => {
    it('should successfully test cross-tenant isolation', async () => {
      const mockResult = {
        tenant1: 'tenant1',
        tenant2: 'tenant2',
        testQueries: [{ name: 'test', sql: 'SELECT * FROM data' }],
        isolationVerified: true,
        violations: [],
      };

      tester.testCrossTenantIsolation.mockResolvedValue(mockResult);

      const result = await service.testCrossTenantIsolation({
        tenant1: 'tenant1',
        tenant2: 'tenant2',
        testQueries: [{ name: 'test', sql: 'SELECT * FROM data' }],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing tenant1', async () => {
      await expect(
        service.testCrossTenantIsolation({
          tenant1: '',
          tenant2: 'tenant2',
          testQueries: [{ name: 'test', sql: 'SELECT * FROM data' }],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for same tenants', async () => {
      await expect(
        service.testCrossTenantIsolation({
          tenant1: 'tenant1',
          tenant2: 'tenant1',
          testQueries: [{ name: 'test', sql: 'SELECT * FROM data' }],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for empty test queries', async () => {
      await expect(
        service.testCrossTenantIsolation({
          tenant1: 'tenant1',
          tenant2: 'tenant2',
          testQueries: [],
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testPolicyBypass', () => {
    it('should successfully test policy bypass', async () => {
      const mockResult = [
        {
          testType: 'access-control' as const,
          testName: 'Policy Bypass Test',
          passed: true,
          details: {},
          timestamp: new Date(),
        },
      ];

      tester.testPolicyBypassAttempts.mockResolvedValue(mockResult);

      const result = await service.testPolicyBypass({
        userId: 'user-1',
        resourceId: 'resource-1',
        resourceType: 'dataset',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing userId', async () => {
      await expect(
        service.testPolicyBypass({
          userId: '',
          resourceId: 'resource-1',
          resourceType: 'dataset',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing resourceId', async () => {
      await expect(
        service.testPolicyBypass({
          userId: 'user-1',
          resourceId: '',
          resourceType: 'dataset',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing resourceType', async () => {
      await expect(
        service.testPolicyBypass({
          userId: 'user-1',
          resourceId: 'resource-1',
          resourceType: '',
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

