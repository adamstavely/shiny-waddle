/**
 * DLP Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DLPService } from './dlp.service';
import { DLPTester } from '../../../services/dlp-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/dlp-tester');

describe('DLPService', () => {
  let service: DLPService;
  let mockTester: jest.Mocked<DLPTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockTester = {
      testDataExfiltration: jest.fn(),
      validateAPIResponse: jest.fn(),
      testQueryResultValidation: jest.fn(),
      testBulkExportControls: jest.fn(),
    } as any;

    // Mock the constructor
    (DLPTester as jest.Mock).mockImplementation(() => mockTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [DLPService],
    }).compile();

    service = module.get<DLPService>(DLPService);
  });

  describe('testExfiltration', () => {
    it('should successfully test data exfiltration', async () => {
      const mockResult = {
        testType: 'data-behavior' as const,
        testName: 'Data Exfiltration Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testDataExfiltration.mockResolvedValue(mockResult);

      const result = await service.testExfiltration({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        dataOperation: {
          type: 'export',
          resource: { id: 'resource-1', type: 'dataset', attributes: {} },
          data: {},
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing user', async () => {
      await expect(
        service.testExfiltration({
          user: null as any,
          dataOperation: {
            type: 'export',
            resource: { id: 'resource-1', type: 'dataset', attributes: {} },
            data: {},
          },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing data operation', async () => {
      await expect(
        service.testExfiltration({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          dataOperation: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing operation type', async () => {
      await expect(
        service.testExfiltration({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          dataOperation: {
            resource: { id: 'resource-1', type: 'dataset', attributes: {} },
            data: {},
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid operation type', async () => {
      await expect(
        service.testExfiltration({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          dataOperation: {
            type: 'invalid' as any,
            resource: { id: 'resource-1', type: 'dataset', attributes: {} },
            data: {},
          },
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('validateAPIResponse', () => {
    it('should successfully validate API response', async () => {
      const mockResult = {
        testType: 'data-behavior' as const,
        testName: 'API Response Validation',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.validateAPIResponse.mockResolvedValue(mockResult);

      const result = await service.validateAPIResponse({
        apiResponse: { id: '1', name: 'Test' },
        allowedFields: ['id', 'name'],
        piiFields: ['email', 'ssn'],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing API response', async () => {
      await expect(
        service.validateAPIResponse({
          apiResponse: null as any,
          allowedFields: ['id', 'name'],
          piiFields: ['email'],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing allowed fields', async () => {
      await expect(
        service.validateAPIResponse({
          apiResponse: { id: '1', name: 'Test' },
          allowedFields: null as any,
          piiFields: ['email'],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing PII fields', async () => {
      await expect(
        service.validateAPIResponse({
          apiResponse: { id: '1', name: 'Test' },
          allowedFields: ['id', 'name'],
          piiFields: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testQueryValidation', () => {
    it('should successfully test query validation', async () => {
      const mockResult = {
        testType: 'data-behavior' as const,
        testName: 'Query Result Validation',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testQueryResultValidation.mockResolvedValue(mockResult);

      const result = await service.testQueryValidation({
        query: { name: 'test', sql: 'SELECT id, name FROM users' },
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        expectedFields: ['id', 'name'],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing expected fields', async () => {
      await expect(
        service.testQueryValidation({
          query: { name: 'test', sql: 'SELECT * FROM users' },
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          expectedFields: [],
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testBulkExport', () => {
    it('should successfully test bulk export controls', async () => {
      const mockResult = {
        testType: 'data-behavior' as const,
        testName: 'Bulk Export Controls Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testBulkExportControls.mockResolvedValue(mockResult);

      const result = await service.testBulkExport({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        exportRequest: {
          type: 'csv',
          recordCount: 1000,
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing export request', async () => {
      await expect(
        service.testBulkExport({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          exportRequest: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing export type', async () => {
      await expect(
        service.testBulkExport({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          exportRequest: {
            recordCount: 1000,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid export type', async () => {
      await expect(
        service.testBulkExport({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          exportRequest: {
            type: 'invalid',
            recordCount: 1000,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid record count', async () => {
      await expect(
        service.testBulkExport({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          exportRequest: {
            type: 'csv',
            recordCount: 0,
          },
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

