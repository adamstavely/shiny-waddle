/**
 * API Security Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { ApiSecurityController } from './api-security.controller';
import { ApiSecurityService } from './api-security.service';
import {
  CreateAPISecurityConfigDto,
  CreateAPIEndpointDto,
  CreateAPISecurityTestDto,
  UpdateAPISecurityConfigDto,
} from './dto/create-api-security.dto';

describe('ApiSecurityController', () => {
  let controller: ApiSecurityController;
  let apiSecurityService: jest.Mocked<ApiSecurityService>;

  const mockConfig = {
    id: 'config-1',
    name: 'Test Config',
    baseUrl: 'https://api.example.com',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockEndpoint = {
    id: 'endpoint-1',
    configId: 'config-1',
    path: '/api/users',
    method: 'GET',
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockTestResult = {
    id: 'result-1',
    configId: 'config-1',
    endpointId: 'endpoint-1',
    testType: 'authentication',
    passed: true,
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockApiSecurityService = {
      findAllConfigs: jest.fn(),
      findAllEndpoints: jest.fn(),
      findAllResults: jest.fn(),
      createConfig: jest.fn(),
      findOneConfig: jest.fn(),
      updateConfig: jest.fn(),
      removeConfig: jest.fn(),
      createEndpoint: jest.fn(),
      findOneEndpoint: jest.fn(),
      removeEndpoint: jest.fn(),
      createTestResult: jest.fn(),
      findOneResult: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApiSecurityController],
      providers: [
        {
          provide: ApiSecurityService,
          useValue: mockApiSecurityService,
        },
      ],
    }).compile();

    controller = module.get<ApiSecurityController>(ApiSecurityController);
    apiSecurityService = module.get(ApiSecurityService) as jest.Mocked<ApiSecurityService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getSummary', () => {
    it('should get summary of configs, endpoints, and results', async () => {
      // Arrange
      apiSecurityService.findAllConfigs.mockResolvedValue([mockConfig] as any);
      apiSecurityService.findAllEndpoints.mockResolvedValue([mockEndpoint] as any);
      apiSecurityService.findAllResults.mockResolvedValue([mockTestResult] as any);

      // Act
      const result = await controller.getSummary();

      // Assert
      expect(result).toEqual({
        configs: 1,
        endpoints: 1,
        results: 1,
      });
    });
  });

  describe('Configs', () => {
    describe('createConfig', () => {
      const dto: CreateAPISecurityConfigDto = {
        name: 'Test Config',
        baseUrl: 'https://api.example.com',
      };

      it('should create a config', async () => {
        // Arrange
        apiSecurityService.createConfig.mockResolvedValue(mockConfig as any);

        // Act
        const result = await controller.createConfig(dto);

        // Assert
        expect(result).toEqual(mockConfig);
        expect(apiSecurityService.createConfig).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllConfigs', () => {
      it('should find all configs', async () => {
        // Arrange
        apiSecurityService.findAllConfigs.mockResolvedValue([mockConfig] as any);

        // Act
        const result = await controller.findAllConfigs();

        // Assert
        expect(result).toEqual([mockConfig]);
        expect(apiSecurityService.findAllConfigs).toHaveBeenCalledTimes(1);
      });
    });

    describe('findOneConfig', () => {
      it('should find one config', async () => {
        // Arrange
        apiSecurityService.findOneConfig.mockResolvedValue(mockConfig as any);

        // Act
        const result = await controller.findOneConfig('config-1');

        // Assert
        expect(result).toEqual(mockConfig);
        expect(apiSecurityService.findOneConfig).toHaveBeenCalledWith('config-1');
      });
    });

    describe('updateConfig', () => {
      const dto: UpdateAPISecurityConfigDto = {
        name: 'Updated Config',
      };

      it('should update a config', async () => {
        // Arrange
        const updatedConfig = { ...mockConfig, ...dto };
        apiSecurityService.updateConfig.mockResolvedValue(updatedConfig as any);

        // Act
        const result = await controller.updateConfig('config-1', dto);

        // Assert
        expect(result).toEqual(updatedConfig);
        expect(apiSecurityService.updateConfig).toHaveBeenCalledWith('config-1', dto);
      });
    });

    describe('removeConfig', () => {
      it('should remove a config', async () => {
        // Arrange
        apiSecurityService.removeConfig.mockResolvedValue(undefined);

        // Act
        const result = await controller.removeConfig('config-1');

        // Assert
        expect(result).toBeUndefined();
        expect(apiSecurityService.removeConfig).toHaveBeenCalledWith('config-1');
      });
    });
  });

  describe('Endpoints', () => {
    describe('createEndpoint', () => {
      const dto: CreateAPIEndpointDto = {
        configId: 'config-1',
        name: 'Get Users',
        endpoint: '/api/users',
        method: 'GET' as any,
        apiType: 'rest' as any,
      };

      it('should create an endpoint', async () => {
        // Arrange
        apiSecurityService.createEndpoint.mockResolvedValue(mockEndpoint as any);

        // Act
        const result = await controller.createEndpoint(dto);

        // Assert
        expect(result).toEqual(mockEndpoint);
        expect(apiSecurityService.createEndpoint).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllEndpoints', () => {
      it('should find all endpoints', async () => {
        // Arrange
        apiSecurityService.findAllEndpoints.mockResolvedValue([mockEndpoint] as any);

        // Act
        const result = await controller.findAllEndpoints();

        // Assert
        expect(result).toEqual([mockEndpoint]);
        expect(apiSecurityService.findAllEndpoints).toHaveBeenCalledWith(undefined);
      });

      it('should find endpoints filtered by configId', async () => {
        // Arrange
        apiSecurityService.findAllEndpoints.mockResolvedValue([mockEndpoint] as any);

        // Act
        const result = await controller.findAllEndpoints('config-1');

        // Assert
        expect(result).toEqual([mockEndpoint]);
        expect(apiSecurityService.findAllEndpoints).toHaveBeenCalledWith('config-1');
      });
    });

    describe('findOneEndpoint', () => {
      it('should find one endpoint', async () => {
        // Arrange
        apiSecurityService.findOneEndpoint.mockResolvedValue(mockEndpoint as any);

        // Act
        const result = await controller.findOneEndpoint('endpoint-1');

        // Assert
        expect(result).toEqual(mockEndpoint);
        expect(apiSecurityService.findOneEndpoint).toHaveBeenCalledWith('endpoint-1');
      });
    });

    describe('removeEndpoint', () => {
      it('should remove an endpoint', async () => {
        // Arrange
        apiSecurityService.removeEndpoint.mockResolvedValue(undefined);

        // Act
        const result = await controller.removeEndpoint('endpoint-1');

        // Assert
        expect(result).toBeUndefined();
        expect(apiSecurityService.removeEndpoint).toHaveBeenCalledWith('endpoint-1');
      });
    });
  });

  describe('Test Results', () => {
    describe('createTestResult', () => {
      const dto: CreateAPISecurityTestDto = {
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Authentication Test',
        endpoint: '/api/users',
        method: 'GET' as any,
        testType: 'authentication' as any,
      };

      it('should create a test result', async () => {
        // Arrange
        apiSecurityService.createTestResult.mockResolvedValue(mockTestResult as any);

        // Act
        const result = await controller.createTestResult(dto);

        // Assert
        expect(result).toEqual(mockTestResult);
        expect(apiSecurityService.createTestResult).toHaveBeenCalledWith(dto);
      });
    });

    describe('findAllResults', () => {
      it('should find all results', async () => {
        // Arrange
        apiSecurityService.findAllResults.mockResolvedValue([mockTestResult] as any);

        // Act
        const result = await controller.findAllResults();

        // Assert
        expect(result).toEqual([mockTestResult]);
        expect(apiSecurityService.findAllResults).toHaveBeenCalledWith(undefined, undefined, undefined, undefined);
      });

      it('should find results with filters', async () => {
        // Arrange
        apiSecurityService.findAllResults.mockResolvedValue([mockTestResult] as any);

        // Act
        const result = await controller.findAllResults('config-1', 'endpoint-1', 'authentication', 'passed');

        // Assert
        expect(result).toEqual([mockTestResult]);
        expect(apiSecurityService.findAllResults).toHaveBeenCalledWith('config-1', 'endpoint-1', 'authentication', 'passed');
      });
    });

    describe('findOneResult', () => {
      it('should find one result', async () => {
        // Arrange
        apiSecurityService.findOneResult.mockResolvedValue(mockTestResult as any);

        // Act
        const result = await controller.findOneResult('result-1');

        // Assert
        expect(result).toEqual(mockTestResult);
        expect(apiSecurityService.findOneResult).toHaveBeenCalledWith('result-1');
      });
    });
  });
});
