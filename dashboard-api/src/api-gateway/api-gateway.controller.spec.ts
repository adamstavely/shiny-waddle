/**
 * API Gateway Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { APIGatewayController } from './api-gateway.controller';
import { APIGatewayService } from './api-gateway.service';

describe('APIGatewayController', () => {
  let controller: APIGatewayController;
  let apiGatewayService: jest.Mocked<APIGatewayService>;

  const mockTestResult = {
    passed: true,
    testType: 'api-gateway' as const,
    testName: 'API Gateway Test',
    timestamp: new Date(),
    details: {},
  };

  const mockRateLimitTest = {
    endpoint: '/api/test',
    limit: 100,
    actualRequests: 150,
    blocked: true,
    blockedAt: 100,
  };

  beforeEach(async () => {
    const mockAPIGatewayService = {
      testGatewayPolicy: jest.fn(),
      testRateLimiting: jest.fn(),
      testAPIVersioning: jest.fn(),
      testServiceAuth: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [APIGatewayController],
      providers: [
        {
          provide: APIGatewayService,
          useValue: mockAPIGatewayService,
        },
      ],
    }).compile();

    controller = module.get<APIGatewayController>(APIGatewayController);
    apiGatewayService = module.get(APIGatewayService) as jest.Mocked<APIGatewayService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testGatewayPolicy', () => {
    it('should test gateway policy with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        request: { path: '/api/users', method: 'GET' },
      };
      apiGatewayService.testGatewayPolicy.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testGatewayPolicy(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(apiGatewayService.testGatewayPolicy).toHaveBeenCalledWith(dto);
    });

    it('should test gateway policy with policy object', async () => {
      // Arrange
      const dto = {
        policy: { id: 'policy-1', name: 'Test Policy' },
        request: { path: '/api/users', method: 'GET' },
      };
      apiGatewayService.testGatewayPolicy.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testGatewayPolicy(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(apiGatewayService.testGatewayPolicy).toHaveBeenCalledWith(dto);
    });
  });

  describe('testRateLimiting', () => {
    it('should test rate limiting with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
      };
      apiGatewayService.testRateLimiting.mockResolvedValue(mockRateLimitTest as any);

      // Act
      const result = await controller.testRateLimiting(dto);

      // Assert
      expect(result).toEqual(mockRateLimitTest);
      expect(apiGatewayService.testRateLimiting).toHaveBeenCalledWith(dto);
    });

    it('should test rate limiting with endpoint and requests', async () => {
      // Arrange
      const dto = {
        endpoint: '/api/users',
        requests: 100,
      };
      apiGatewayService.testRateLimiting.mockResolvedValue(mockRateLimitTest as any);

      // Act
      const result = await controller.testRateLimiting(dto);

      // Assert
      expect(result).toEqual(mockRateLimitTest);
      expect(apiGatewayService.testRateLimiting).toHaveBeenCalledWith(dto);
    });
  });

  describe('testAPIVersioning', () => {
    it('should test API versioning with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
        version: 'v1',
        endpoint: '/api/users',
      };
      apiGatewayService.testAPIVersioning.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testAPIVersioning(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(apiGatewayService.testAPIVersioning).toHaveBeenCalledWith(dto);
    });

    it('should test API versioning without applicationId', async () => {
      // Arrange
      const dto = {
        version: 'v2',
        endpoint: '/api/users',
      };
      apiGatewayService.testAPIVersioning.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testAPIVersioning(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(apiGatewayService.testAPIVersioning).toHaveBeenCalledWith(dto);
    });
  });

  describe('testServiceAuth', () => {
    const mockServiceAuthResult = {
      source: 'service-1',
      target: 'service-2',
      authenticated: true,
      authMethod: 'jwt',
    };

    it('should test service auth with applicationId', async () => {
      // Arrange
      const dto = {
        applicationId: 'app-1',
      };
      apiGatewayService.testServiceAuth.mockResolvedValue(mockServiceAuthResult as any);

      // Act
      const result = await controller.testServiceAuth(dto);

      // Assert
      expect(result).toEqual(mockServiceAuthResult);
      expect(apiGatewayService.testServiceAuth).toHaveBeenCalledWith(dto);
    });

    it('should test service auth with source and target', async () => {
      // Arrange
      const dto = {
        source: 'service-1',
        target: 'service-2',
      };
      apiGatewayService.testServiceAuth.mockResolvedValue(mockServiceAuthResult as any);

      // Act
      const result = await controller.testServiceAuth(dto);

      // Assert
      expect(result).toEqual(mockServiceAuthResult);
      expect(apiGatewayService.testServiceAuth).toHaveBeenCalledWith(dto);
    });
  });
});
