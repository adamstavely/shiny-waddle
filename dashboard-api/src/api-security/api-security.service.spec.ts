/**
 * API Security Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import { ApplicationsService } from '../applications/applications.service';
import { CreateAPISecurityConfigDto, CreateAPIEndpointDto, CreateAPISecurityTestDto } from './dto/create-api-security.dto';
import { APITestType, HTTPMethod, AuthenticationType } from './entities/api-security.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ApiSecurityService', () => {
  let service: ApiSecurityService;
  let applicationsService: jest.Mocked<ApplicationsService>;

  const mockConfig: CreateAPISecurityConfigDto = {
    name: 'Test API Config',
    baseUrl: 'https://api.example.com',
    authentication: {
      type: AuthenticationType.BEARER,
      credentials: { token: 'test-token' },
    },
  };

  const mockEndpoint: CreateAPIEndpointDto = {
    configId: 'config-1',
    name: 'Test Endpoint',
    endpoint: '/api/test',
    method: HTTPMethod.GET,
    apiType: APITestType.REST,
  };

  beforeEach(async () => {
    // Mock fs before creating module (constructor calls loadData)
    (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
    (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

    const mockApplicationsService = {
      findOne: jest.fn(),
      findAll: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiSecurityService,
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
      ],
    }).compile();

    service = module.get<ApiSecurityService>(ApiSecurityService);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;

    // Wait for async loadData to complete
    await new Promise(resolve => setImmediate(resolve));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Config Management', () => {
    it('should create a config', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createConfig(mockConfig);

      // Assert
      expect(result.id).toBe('mock-uuid-v4');
      expect(result.name).toBe('Test API Config');
      expect(result.baseUrl).toBe('https://api.example.com');
    });

    it('should find all configs', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([
        { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ]));
      await (service as any).loadConfigs();

      // Act
      const result = await service.findAllConfigs();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('Test API Config');
    });

    it('should find one config by id', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([
        { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ]));
      await (service as any).loadConfigs();

      // Act
      const result = await service.findOneConfig('config-1');

      // Assert
      expect(result.id).toBe('config-1');
      expect(result.name).toBe('Test API Config');
    });

    it('should throw NotFoundException when config not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));
      await (service as any).loadConfigs();

      // Act & Assert
      await expect(service.findOneConfig('non-existent')).rejects.toThrow(NotFoundException);
    });

    it('should update config', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([
        { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ]));
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadConfigs();

      // Act
      const result = await service.updateConfig('config-1', { name: 'Updated Config' });

      // Assert
      expect(result.name).toBe('Updated Config');
      expect(result.id).toBe('config-1');
    });

    it('should remove config', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([
        { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ]));
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadConfigs();

      // Act
      await service.removeConfig('config-1');

      // Assert
      await expect(service.findOneConfig('config-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('Endpoint Management', () => {
    it('should create an endpoint', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([
        { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
      ]));
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadConfigs();

      // Act
      const result = await service.createEndpoint(mockEndpoint);

      // Assert
      expect(result.id).toBe('mock-uuid-v4');
      expect(result.name).toBe('Test Endpoint');
      expect(result.endpoint).toBe('/api/test');
    });

    it('should find all endpoints', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]));
      await (service as any).loadData();

      // Act
      const result = await service.findAllEndpoints();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('Test Endpoint');
    });

    it('should find endpoints by configId', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', configId: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
          { ...mockEndpoint, id: 'endpoint-2', configId: 'config-2', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]));
      await (service as any).loadData();

      // Act
      const result = await service.findAllEndpoints('config-1');

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('endpoint-1');
    });

    it('should find one endpoint by id', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]));
      await (service as any).loadData();

      // Act
      const result = await service.findOneEndpoint('endpoint-1');

      // Assert
      expect(result.id).toBe('endpoint-1');
    });

    it('should throw NotFoundException when endpoint not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]));
      await (service as any).loadData();

      // Act & Assert
      await expect(service.findOneEndpoint('non-existent')).rejects.toThrow(NotFoundException);
    });

    it('should remove endpoint', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]));
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadData();

      // Act
      await service.removeEndpoint('endpoint-1');

      // Assert
      await expect(service.findOneEndpoint('endpoint-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('Test Results', () => {
    it('should create test result', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([]));
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadData();

      const testDto: CreateAPISecurityTestDto = {
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Test',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
      };

      // Mock APISecurityTester
      jest.spyOn(service as any, 'executeAPISecurityTest').mockResolvedValue({
        id: 'result-1',
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Test',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
        status: 'passed',
        timestamp: new Date(),
        createdAt: new Date(),
      });

      // Act
      const result = await service.createTestResult(testDto);

      // Assert
      expect(result.configId).toBe('config-1');
      expect(result.endpointId).toBe('endpoint-1');
    });

    it('should throw NotFoundException when config not found for test result', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]));
      await (service as any).loadData();

      const testDto: CreateAPISecurityTestDto = {
        configId: 'non-existent',
        endpointId: 'endpoint-1',
        testName: 'Test',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
      };

      // Act & Assert
      await expect(service.createTestResult(testDto)).rejects.toThrow(NotFoundException);
    });

    it('should find all results', async () => {
      // Arrange
      const mockResult = {
        id: 'result-1',
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Test',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
        status: 'passed',
        timestamp: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([mockResult]));
      await (service as any).loadData();

      // Act
      const result = await service.findAllResults();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('result-1');
    });

    it('should filter results by configId', async () => {
      // Arrange
      const mockResults = [
        {
          id: 'result-1',
          configId: 'config-1',
          endpointId: 'endpoint-1',
          testName: 'Test',
          endpoint: '/api/test',
          method: HTTPMethod.GET,
          testType: APITestType.REST,
          status: 'passed',
          timestamp: new Date().toISOString(),
          createdAt: new Date().toISOString(),
        },
        {
          id: 'result-2',
          configId: 'config-2',
          endpointId: 'endpoint-2',
          testName: 'Test 2',
          endpoint: '/api/test2',
          method: HTTPMethod.GET,
          testType: APITestType.REST,
          status: 'passed',
          timestamp: new Date().toISOString(),
          createdAt: new Date().toISOString(),
        },
      ];
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify(mockResults));
      await (service as any).loadData();

      // Act
      const result = await service.findAllResults('config-1');

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].configId).toBe('config-1');
    });

    it('should find one result by id', async () => {
      // Arrange
      const mockResult = {
        id: 'result-1',
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Test',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
        status: 'passed',
        timestamp: new Date().toISOString(),
        createdAt: new Date().toISOString(),
      };
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([mockResult]));
      await (service as any).loadData();

      // Act
      const result = await service.findOneResult('result-1');

      // Assert
      expect(result.id).toBe('result-1');
    });

    it('should throw NotFoundException when result not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]));
      await (service as any).loadData();

      // Act & Assert
      await expect(service.findOneResult('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('runTest', () => {
    it('should run test with standalone config', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockEndpoint, id: 'endpoint-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([]));
      await (service as any).loadData();

      // Mock executeAPISecurityTest
      jest.spyOn(service as any, 'executeAPISecurityTest').mockResolvedValue({
        id: 'result-1',
        configId: 'config-1',
        endpointId: 'endpoint-1',
        testName: 'Test Endpoint',
        endpoint: '/api/test',
        method: HTTPMethod.GET,
        testType: APITestType.REST,
        status: 'passed',
        timestamp: new Date(),
        createdAt: new Date(),
      });

      // Act
      const result = await service.runTest('config-1');

      // Assert
      expect(result.passed).toBeDefined();
      expect(result.testType).toBe('api-security');
    });

    it('should throw NotFoundException when no endpoints found', async () => {
      // Arrange
      (fs.readFile as jest.Mock)
        .mockResolvedValueOnce(JSON.stringify([
          { ...mockConfig, id: 'config-1', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() },
        ]))
        .mockResolvedValueOnce(JSON.stringify([]))
        .mockResolvedValueOnce(JSON.stringify([]));
      await (service as any).loadData();

      // Act & Assert
      await expect(service.runTest('config-1')).rejects.toThrow(NotFoundException);
    });
  });
});
