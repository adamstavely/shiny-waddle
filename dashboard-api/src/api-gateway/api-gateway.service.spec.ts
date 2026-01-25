/**
 * API Gateway Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { APIGatewayService } from './api-gateway.service';
import { APIGatewayTester } from '../../heimdall-framework/services/api-gateway-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/api-gateway-tester');

describe('APIGatewayService', () => {
  let service: APIGatewayService;
  let mockTester: jest.Mocked<APIGatewayTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockTester = {
      testGatewayPolicy: jest.fn(),
      testRateLimiting: jest.fn(),
      testAPIVersioning: jest.fn(),
      testServiceToServiceAuth: jest.fn(),
    } as any;

    // Mock the constructor
    (APIGatewayTester as jest.Mock).mockImplementation(() => mockTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [APIGatewayService],
    }).compile();

    service = module.get<APIGatewayService>(APIGatewayService);
  });

  describe('testGatewayPolicy', () => {
    it('should successfully test gateway policy', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'Gateway Policy Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testGatewayPolicy.mockResolvedValue(mockResult);

      const result = await service.testGatewayPolicy({
        policy: {
          id: 'policy-1',
          name: 'Test Policy',
          endpoint: '/api/test',
          method: 'GET',
          rules: [],
        },
        request: {
          endpoint: '/api/test',
          method: 'GET',
          headers: {},
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing policy', async () => {
      await expect(
        service.testGatewayPolicy({
          policy: null as any,
          request: {
            endpoint: '/api/test',
            method: 'GET',
            headers: {},
            user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing policy id', async () => {
      await expect(
        service.testGatewayPolicy({
          policy: {
            name: 'Test Policy',
            endpoint: '/api/test',
            method: 'GET',
            rules: [],
          } as any,
          request: {
            endpoint: '/api/test',
            method: 'GET',
            headers: {},
            user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing request', async () => {
      await expect(
        service.testGatewayPolicy({
          policy: {
            id: 'policy-1',
            name: 'Test Policy',
            endpoint: '/api/test',
            method: 'GET',
            rules: [],
          },
          request: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing request endpoint', async () => {
      await expect(
        service.testGatewayPolicy({
          policy: {
            id: 'policy-1',
            name: 'Test Policy',
            endpoint: '/api/test',
            method: 'GET',
            rules: [],
          },
          request: {
            method: 'GET',
            headers: {},
            user: {},
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testRateLimiting', () => {
    it('should successfully test rate limiting', async () => {
      const mockResult = {
        endpoint: '/api/test',
        requests: 50,
        blocked: false,
        actualRequests: 50,
        limit: 100,
        timeWindow: 60,
      };

      mockTester.testRateLimiting.mockResolvedValue(mockResult);

      const result = await service.testRateLimiting({
        endpoint: '/api/test',
        requests: 50,
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing endpoint', async () => {
      await expect(
        service.testRateLimiting({
          endpoint: '',
          requests: 50,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid requests', async () => {
      await expect(
        service.testRateLimiting({
          endpoint: '/api/test',
          requests: 0,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for requests exceeding limit', async () => {
      await expect(
        service.testRateLimiting({
          endpoint: '/api/test',
          requests: 10001,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testAPIVersioning', () => {
    it('should successfully test API versioning', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'API Versioning Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testAPIVersioning.mockResolvedValue(mockResult);

      const result = await service.testAPIVersioning({
        version: 'v1',
        endpoint: '/api/test',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing version', async () => {
      await expect(
        service.testAPIVersioning({
          version: '',
          endpoint: '/api/test',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid version format', async () => {
      await expect(
        service.testAPIVersioning({
          version: 'invalid-version',
          endpoint: '/api/test',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should accept valid version formats', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'API Versioning Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };
      mockTester.testAPIVersioning.mockResolvedValue(mockResult);

      await expect(
        service.testAPIVersioning({
          version: 'v1',
          endpoint: '/api/test',
        }),
      ).resolves.toEqual(mockResult);

      await expect(
        service.testAPIVersioning({
          version: 'v2.0',
          endpoint: '/api/test',
        }),
      ).resolves.toEqual(mockResult);
    });
  });

  describe('testServiceAuth', () => {
    it('should successfully test service authentication', async () => {
      const mockResult = {
        source: 'frontend',
        target: 'backend',
        authenticated: true,
        authMethod: 'jwt' as const,
      };

      mockTester.testServiceToServiceAuth.mockResolvedValue(mockResult);

      const result = await service.testServiceAuth({
        source: 'frontend',
        target: 'backend',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing source', async () => {
      await expect(
        service.testServiceAuth({
          source: '',
          target: 'backend',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for same source and target', async () => {
      await expect(
        service.testServiceAuth({
          source: 'frontend',
          target: 'frontend',
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

