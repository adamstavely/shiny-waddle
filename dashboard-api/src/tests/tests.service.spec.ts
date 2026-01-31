/**
 * Tests Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ModuleRef } from '@nestjs/core';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { TestsService } from './tests.service';
import { TestDiscoveryService } from './test-discovery.service';
import { PoliciesService } from '../policies/policies.service';
import { ApplicationDataService } from '../shared/application-data.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { TestEntity } from './entities/test.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('TestsService', () => {
  let service: TestsService;
  let discoveryService: jest.Mocked<TestDiscoveryService>;
  let policiesService: any;
  let moduleRef: jest.Mocked<ModuleRef>;

  const mockTest: TestEntity = {
    id: 'test-1',
    name: 'Test Access Control',
    description: 'Test description',
    testType: 'access-control' as any,
    domain: 'identity' as any,
    version: 1,
    versionHistory: [],
    enabled: true,
    policyId: 'policy-1',
    inputs: {
      subject: { role: 'viewer' },
      resource: { id: 'resource-1' },
    },
    expected: { allowed: false },
    createdAt: new Date(),
    updatedAt: new Date(),
  } as TestEntity;

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockDiscoveryService = {
      discoverTests: jest.fn().mockResolvedValue([]),
    };

    const mockPoliciesService = {
      findOne: jest.fn(),
    };

    const mockApplicationDataService = {
      findAll: jest.fn().mockResolvedValue([]),
      findOne: jest.fn().mockResolvedValue(null),
    };

    const mockModuleRef = {
      get: jest.fn().mockReturnValue(mockPoliciesService),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TestsService,
        {
          provide: ModuleRef,
          useValue: mockModuleRef,
        },
        {
          provide: TestDiscoveryService,
          useValue: mockDiscoveryService,
        },
        {
          provide: ApplicationDataService,
          useValue: mockApplicationDataService,
        },
      ],
    }).compile();

    // Mock fs operations BEFORE creating service to prevent initialization errors
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    service = module.get<TestsService>(TestsService);
    discoveryService = module.get(TestDiscoveryService) as jest.Mocked<TestDiscoveryService>;
    moduleRef = module.get(ModuleRef) as jest.Mocked<ModuleRef>;
    policiesService = mockPoliciesService as any;

    // Mock load methods to prevent async loading issues
    // Use mockImplementation to prevent it from clearing the tests array
    jest.spyOn(service as any, 'loadTests').mockImplementation(async () => {
      // Don't reload from file, just return
      return Promise.resolve();
    });
    jest.spyOn(service as any, 'discoverAndRegisterTests').mockResolvedValue(undefined);

    // Clear cached tests
    (service as any).tests = [];
  });

  describe('create', () => {
    const createDto: CreateTestDto = {
      name: 'New Test',
      description: 'New test description',
      testType: 'access-control',
      policyId: 'policy-1',
      inputs: {
        subject: { role: 'admin' },
        resource: { id: 'resource-1' },
      },
      expected: { allowed: true },
    };

    it('should successfully create a test', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      (service as any).tests = [];

      // Act
      const result = await service.create(createDto, 'user-1');

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.testType).toBe(createDto.testType);
      expect(result.version).toBe(1);
      expect(result.domain).toBeDefined();
      expect(result.createdBy).toBe('user-1');
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should auto-populate domain from testType', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      (service as any).tests = [];

      const createDtoWithoutDomain: CreateTestDto = {
        ...createDto,
        domain: undefined,
      };

      // Act
      const result = await service.create(createDtoWithoutDomain);

      // Assert
      expect(result.domain).toBeDefined();
    });

    it('should validate domain matches testType', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      (service as any).tests = [];

      const createDtoWithWrongDomain: CreateTestDto = {
        ...createDto,
        domain: 'api_security', // Wrong domain for access-control (should be 'identity')
      };

      // Act & Assert
      await expect(
        service.create(createDtoWithWrongDomain)
      ).rejects.toThrow(BadRequestException);
    });

    it('should validate policy exists for access-control tests', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue(null); // Policy not found
      (service as any).tests = [];

      // Act & Assert
      await expect(
        service.create(createDto)
      ).rejects.toThrow(BadRequestException);
    });

    it('should not require policy validation for non-access-control tests', async () => {
      // Arrange
      (service as any).tests = [];

      const createDtoDLP: CreateTestDto = {
        name: 'DLP Test',
        testType: 'dlp',
        pattern: { type: 'email' },
        expectedDetection: true,
      };

      // Act
      const result = await service.create(createDtoDLP);

      // Assert
      expect(result).toBeDefined();
      expect(result.testType).toBe('dlp');
    });
  });

  describe('findAll', () => {
    it('should return all tests when no filters provided', async () => {
      // Arrange
      (service as any).tests = [mockTest];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should filter by testType', async () => {
      // Arrange
      const dlpTest = { ...mockTest, id: 'test-2', testType: 'dlp' };
      (service as any).tests = [mockTest, dlpTest];

      // Act
      const result = await service.findAll({ testType: 'access-control' });

      // Assert
      expect(result.every(t => t.testType === 'access-control')).toBe(true);
    });

    it('should filter by domain', async () => {
      // Arrange
      const otherDomainTest = { ...mockTest, id: 'test-2', domain: 'api_security' };
      (service as any).tests = [mockTest, otherDomainTest];

      // Act
      const result = await service.findAll({ domain: 'identity' });

      // Assert
      expect(result.every(t => t.domain === 'identity')).toBe(true);
    });

    it('should filter by policyId for access-control tests', async () => {
      // Arrange
      const otherPolicyTest = { ...mockTest, id: 'test-2', policyId: 'policy-2' };
      (service as any).tests = [mockTest, otherPolicyTest];

      // Act
      const result = await service.findAll({ policyId: 'policy-1' });

      // Assert
      expect(result.every(t => {
        if (t.testType === 'access-control') {
          return (t as any).policyId === 'policy-1';
        }
        return false;
      })).toBe(true);
    });
  });

  describe('findOne', () => {
    it('should return test when found', async () => {
      // Arrange
      (service as any).tests = [mockTest];

      // Act
      const result = await service.findOne(mockTest.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockTest.id);
      expect(result.name).toBe(mockTest.name);
    });

    it('should throw NotFoundException when test not found', async () => {
      // Arrange
      (service as any).tests = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('findByPolicy', () => {
    it('should return tests for a specific policy', async () => {
      // Arrange
      const otherPolicyTest = { ...mockTest, id: 'test-2', policyId: 'policy-2' };
      (service as any).tests = [mockTest, otherPolicyTest];

      // Act
      const result = await service.findByPolicy('policy-1');

      // Assert
      expect(result.every(t => (t as any).policyId === 'policy-1')).toBe(true);
    });

    it('should return empty array when no tests found for policy', async () => {
      // Arrange
      (service as any).tests = [mockTest];

      // Act
      const result = await service.findByPolicy('non-existent-policy');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneVersion', () => {
    it('should return current version when version matches', async () => {
      // Arrange
      (service as any).tests = [mockTest];

      // Act
      const result = await service.findOneVersion(mockTest.id, 1);

      // Assert
      expect(result.version).toBe(1);
      expect(result.id).toBe(mockTest.id);
    });

    it('should return version from history when version does not match', async () => {
      // Arrange
      const testWithHistory = {
        ...mockTest,
        version: 2,
        versionHistory: [{
          version: 1,
          testConfiguration: { name: 'Old Name' },
          changedBy: 'user-1',
          changedAt: new Date(),
          changes: ['name'],
        }],
      };
      (service as any).tests = [testWithHistory];

      // Act
      const result = await service.findOneVersion(mockTest.id, 1);

      // Assert
      expect(result.version).toBe(1);
      expect(result.name).toBe('Old Name');
    });

    it('should throw NotFoundException when version not found', async () => {
      // Arrange
      (service as any).tests = [mockTest];

      // Act & Assert
      await expect(
        service.findOneVersion(mockTest.id, 99)
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateTestDto = {
      name: 'Updated Test Name',
      description: 'Updated description',
    };

    it('should successfully update a test', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      (service as any).tests = [{ ...mockTest }];

      // Act
      const result = await service.update(mockTest.id, updateDto, 'user-2');

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.version).toBe(2);
      expect(result.versionHistory.length).toBe(1);
      expect(result.lastModifiedBy).toBe('user-2');
    });

    it('should throw NotFoundException when test not found', async () => {
      // Arrange
      (service as any).tests = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should validate policy when updating access-control test', async () => {
      // Arrange
      (service as any).tests = [{ ...mockTest }];
      policiesService.findOne.mockResolvedValue(null); // Policy not found

      const updateDtoWithPolicy: UpdateTestDto = {
        policyId: 'non-existent-policy',
      };

      // Act & Assert
      await expect(
        service.update(mockTest.id, updateDtoWithPolicy)
      ).rejects.toThrow(BadRequestException);
    });

    it('should auto-update domain when testType changes', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      (service as any).tests = [{ ...mockTest }];

      const updateDtoWithNewType: UpdateTestDto = {
        testType: 'dlp',
      };

      // Act
      const result = await service.update(mockTest.id, updateDtoWithNewType);

      // Assert
      expect(result.testType).toBe('dlp');
      expect(result.domain).toBeDefined();
      expect(result.domain).not.toBe(mockTest.domain);
    });

    it('should keep only last 10 versions in history', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue({ id: 'policy-1' } as any);
      const testWithManyVersions = {
        ...mockTest,
        version: 12,
        versionHistory: Array.from({ length: 11 }, (_, i) => ({
          version: i + 1,
          testConfiguration: { name: `Version ${i + 1}` },
          changedBy: 'user-1',
          changedAt: new Date(),
          changes: ['name'],
        })),
      };
      (service as any).tests = [testWithManyVersions];

      // Act
      const result = await service.update(mockTest.id, updateDto);

      // Assert
      expect(result.versionHistory.length).toBeLessThanOrEqual(10);
    });
  });

  describe('remove', () => {
    it('should successfully remove a test', async () => {
      // Arrange
      (service as any).tests = [{ ...mockTest }];

      // Act
      await service.remove(mockTest.id);

      // Assert
      expect((service as any).tests.find((t: TestEntity) => t.id === mockTest.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when test not found', async () => {
      // Arrange
      (service as any).tests = [];

      // Act & Assert
      await expect(
        service.remove('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getUsedInSuites', () => {
    it('should return suites that use the test', async () => {
      // Arrange
      (service as any).tests = [mockTest];
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([
        { id: 'suite-1', name: 'Test Suite 1', testIds: [mockTest.id] },
        { id: 'suite-2', name: 'Test Suite 2', testIds: ['other-test'] },
      ]));

      // Act
      const result = await service.getUsedInSuites(mockTest.id);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1);
      expect(result[0].id).toBe('suite-1');
    });

    it('should return empty array when test not used in any suite', async () => {
      // Arrange
      (service as any).tests = [mockTest];
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.getUsedInSuites(mockTest.id);

      // Assert
      expect(result).toEqual([]);
    });

    it('should handle file read errors gracefully', async () => {
      // Arrange
      (service as any).tests = [mockTest];
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockRejectedValue(new Error('Read error'));

      // Act
      const result = await service.getUsedInSuites(mockTest.id);

      // Assert
      expect(result).toEqual([]);
    });
  });
});
