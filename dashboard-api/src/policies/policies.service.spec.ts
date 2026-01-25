/**
 * Policies Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ModuleRef } from '@nestjs/core';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { PoliciesService } from './policies.service';
import { PolicyVersioningService, VersionComparison, ImpactAnalysis } from './services/policy-versioning.service';
import { CreatePolicyDto, PolicyType, PolicyStatus, PolicyEffect } from './dto/create-policy.dto';
import { UpdatePolicyDto } from './dto/update-policy.dto';
import { Policy, PolicyVersion } from './entities/policy.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('PoliciesService', () => {
  let service: PoliciesService;
  let versioningService: jest.Mocked<PolicyVersioningService>;
  let moduleRef: jest.Mocked<ModuleRef>;

  const mockPolicy: Policy = {
    id: 'policy-1',
    name: 'Test Policy',
    description: 'Test policy description',
    type: PolicyType.RBAC,
    version: '1.0.0',
    status: PolicyStatus.DRAFT,
    effect: PolicyEffect.ALLOW,
    priority: 100,
    rules: [{ id: 'rule-1', effect: PolicyEffect.ALLOW, conditions: {} }],
    conditions: [],
    applicationId: 'app-1',
    versions: [{
      version: '1.0.0',
      status: PolicyStatus.DRAFT,
      date: new Date(),
      changes: [{ type: 'added', description: 'Initial policy creation' }],
    }],
    createdAt: new Date(),
    updatedAt: new Date(),
    ruleCount: 1,
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Create mock versioning service
    const mockVersioningService = {
      getVersionHistory: jest.fn(),
      compareVersions: jest.fn(),
      analyzeImpact: jest.fn(),
      rollbackToVersion: jest.fn(),
      getVersion: jest.fn(),
    };

    const mockModuleRef = {
      get: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PoliciesService,
        {
          provide: ModuleRef,
          useValue: mockModuleRef,
        },
        {
          provide: PolicyVersioningService,
          useValue: mockVersioningService,
        },
      ],
    }).compile();

    service = module.get<PoliciesService>(PoliciesService);
    versioningService = module.get(PolicyVersioningService) as jest.Mocked<PolicyVersioningService>;
    moduleRef = module.get(ModuleRef) as jest.Mocked<ModuleRef>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear cached policies and ensure they're loaded fresh for each test
    (service as any).policies = [];
    (service as any).auditLogs = [];
    
    // Mock the load methods to prevent async loading issues
    jest.spyOn(service as any, 'loadPolicies').mockResolvedValue(undefined);
    jest.spyOn(service as any, 'loadAuditLogs').mockResolvedValue(undefined);
  });

  describe('create', () => {
    const createDto: CreatePolicyDto = {
      name: 'New Policy',
      description: 'New policy description',
      type: PolicyType.RBAC,
      version: '1.0.0',
      status: PolicyStatus.DRAFT,
      effect: PolicyEffect.ALLOW,
      rules: [{ id: 'rule-1', effect: PolicyEffect.ALLOW, conditions: {} }],
    };

    it('should successfully create a policy', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
      (service as any).policies = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.type).toBe(createDto.type);
      expect(result.version).toBe(createDto.version);
      expect(result.status).toBe(createDto.status);
      expect(result.versions).toHaveLength(1);
      expect(result.ruleCount).toBe(1);
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should use default status when not provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoWithoutStatus: CreatePolicyDto = {
        ...createDto,
        status: undefined,
      };

      // Act
      const result = await service.create(createDtoWithoutStatus);

      // Assert
      expect(result.status).toBe(PolicyStatus.DRAFT);
    });

    it('should calculate ruleCount correctly for RBAC policies', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoWithRules: CreatePolicyDto = {
        ...createDto,
        rules: [
          { id: 'rule-1', effect: PolicyEffect.ALLOW, conditions: {} },
          { id: 'rule-2', effect: PolicyEffect.DENY, conditions: {} },
        ],
      };

      // Act
      const result = await service.create(createDtoWithRules);

      // Assert
      expect(result.ruleCount).toBe(2);
    });

    it('should calculate ruleCount correctly for ABAC policies', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));

      const createDtoABAC: CreatePolicyDto = {
        ...createDto,
        type: PolicyType.ABAC,
        conditions: [
          { attribute: 'department', operator: 'equals', value: 'Engineering' },
          { attribute: 'role', operator: 'equals', value: 'admin' },
        ],
      };

      // Act
      const result = await service.create(createDtoABAC);

      // Assert
      expect(result.ruleCount).toBe(2);
    });
  });

  describe('findAll', () => {
    it('should return all policies when no filters provided', async () => {
      // Arrange
      const fs = require('fs/promises');
      fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([mockPolicy]));
      (service as any).policies = [mockPolicy];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should filter by type', async () => {
      // Arrange
      const fs = require('fs/promises');
      const abacPolicy = { ...mockPolicy, id: 'policy-2', type: PolicyType.ABAC };
      (service as any).policies = [mockPolicy, abacPolicy];

      // Act
      const result = await service.findAll(PolicyType.RBAC);

      // Assert
      expect(result.every(p => p.type === PolicyType.RBAC)).toBe(true);
    });

    it('should filter by status', async () => {
      // Arrange
      const activePolicy = { ...mockPolicy, id: 'policy-2', status: PolicyStatus.ACTIVE };
      (service as any).policies = [mockPolicy, activePolicy];

      // Act
      const result = await service.findAll(undefined, PolicyStatus.DRAFT);

      // Assert
      expect(result.every(p => p.status === PolicyStatus.DRAFT)).toBe(true);
    });

    it('should filter by applicationId', async () => {
      // Arrange
      const otherAppPolicy = { ...mockPolicy, id: 'policy-2', applicationId: 'app-2' };
      (service as any).policies = [mockPolicy, otherAppPolicy];

      // Act
      const result = await service.findAll(undefined, undefined, 'app-1');

      // Assert
      expect(result.every(p => p.applicationId === 'app-1')).toBe(true);
    });

    it('should apply multiple filters', async () => {
      // Arrange
      const otherPolicy = { ...mockPolicy, id: 'policy-2', type: PolicyType.ABAC, status: PolicyStatus.ACTIVE };
      (service as any).policies = [mockPolicy, otherPolicy];

      // Act
      const result = await service.findAll(PolicyType.RBAC, PolicyStatus.DRAFT, 'app-1');

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].type).toBe(PolicyType.RBAC);
      expect(result[0].status).toBe(PolicyStatus.DRAFT);
      expect(result[0].applicationId).toBe('app-1');
    });
  });

  describe('findOne', () => {
    it('should return policy when found', async () => {
      // Arrange
      (service as any).policies = [mockPolicy];

      // Act
      const result = await service.findOne(mockPolicy.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockPolicy.id);
      expect(result.name).toBe(mockPolicy.name);
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdatePolicyDto = {
      name: 'Updated Policy Name',
      description: 'Updated description',
    };

    it('should successfully update a policy', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      // Act
      const result = await service.update(mockPolicy.id, updateDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should track status changes in audit log', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];
      (service as any).auditLogs = [];

      const updateDtoWithStatus: UpdatePolicyDto = {
        status: PolicyStatus.ACTIVE,
      };

      // Act
      await service.update(mockPolicy.id, updateDtoWithStatus);

      // Assert
      const auditLogs = (service as any).auditLogs;
      expect(auditLogs.some(log => log.action === 'status_changed')).toBe(true);
    });

    it('should update ruleCount when rules change', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy, type: PolicyType.RBAC }];

      const updateDtoWithRules: UpdatePolicyDto = {
        type: PolicyType.RBAC,
        rules: [
          { id: 'rule-1', effect: PolicyEffect.ALLOW, conditions: {} },
          { id: 'rule-2', effect: PolicyEffect.ALLOW, conditions: {} },
          { id: 'rule-3', effect: PolicyEffect.ALLOW, conditions: {} },
        ],
      };

      // Act
      const result = await service.update(mockPolicy.id, updateDtoWithRules);

      // Assert
      expect(result.ruleCount).toBe(3);
    });
  });

  describe('remove', () => {
    it('should successfully remove a policy', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      // Act
      await service.remove(mockPolicy.id);

      // Assert
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.remove('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('addVersion', () => {
    it('should successfully add a new version', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      const newVersion: PolicyVersion = {
        version: '1.1.0',
        status: PolicyStatus.ACTIVE,
        date: new Date(),
        changes: [{ type: 'changed', description: 'Updated rules' }],
      };

      // Act
      const result = await service.addVersion(mockPolicy.id, newVersion);

      // Assert
      expect(result.versions).toContainEqual(newVersion);
      expect(result.version).toBe(newVersion.version);
      expect(result.status).toBe(newVersion.status);
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      const newVersion: PolicyVersion = {
        version: '1.1.0',
        status: PolicyStatus.ACTIVE,
        date: new Date(),
        changes: [],
      };

      // Act & Assert
      await expect(
        service.addVersion('non-existent-id', newVersion)
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getVersions', () => {
    it('should return version history', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      const mockVersions: PolicyVersion[] = [
        { version: '1.0.0', status: PolicyStatus.DRAFT, date: new Date(), changes: [] },
        { version: '1.1.0', status: PolicyStatus.ACTIVE, date: new Date(), changes: [] },
      ];
      versioningService.getVersionHistory.mockReturnValue(mockVersions);

      // Act
      const result = await service.getVersions(mockPolicy.id);

      // Assert
      expect(result).toEqual(mockVersions);
      expect(versioningService.getVersionHistory).toHaveBeenCalledWith(mockPolicy);
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.getVersions('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('compareVersions', () => {
    it('should compare two versions', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      const mockComparison: VersionComparison = {
        version1: '1.0.0',
        version2: '1.1.0',
        differences: [],
        summary: {
          totalChanges: 0,
          addedFields: 0,
          removedFields: 0,
          modifiedFields: 0,
        },
      };
      versioningService.compareVersions.mockReturnValue(mockComparison);

      // Act
      const result = await service.compareVersions(mockPolicy.id, '1.0.0', '1.1.0');

      // Assert
      expect(result).toEqual(mockComparison);
      expect(versioningService.compareVersions).toHaveBeenCalledWith(mockPolicy, '1.0.0', '1.1.0');
    });
  });

  describe('analyzeImpact', () => {
    it('should analyze impact of policy changes', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      const mockImpact: ImpactAnalysis = {
        affectedApplications: ['app-1'],
        affectedTestResults: 5,
        potentialViolations: 2,
        riskLevel: 'medium',
        recommendations: ['Review test results', 'Update affected applications'],
      };
      versioningService.getVersion.mockReturnValue(mockPolicy.versions[0]);
      versioningService.analyzeImpact.mockResolvedValue(mockImpact);

      // Act
      const result = await service.analyzeImpact(mockPolicy.id);

      // Assert
      expect(result).toEqual(mockImpact);
    });

    it('should throw NotFoundException when version not found', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];
      versioningService.getVersion.mockReturnValue(undefined);

      // Act & Assert
      await expect(
        service.analyzeImpact(mockPolicy.id, '2.0.0')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deploy', () => {
    it('should successfully deploy a policy version', async () => {
      // Arrange
      const activeVersion = { ...mockPolicy.versions[0], status: PolicyStatus.ACTIVE };
      const activePolicy = {
        ...mockPolicy,
        version: activeVersion.version,
        versions: [activeVersion],
      };
      (service as any).policies = [activePolicy];

      // Act
      const result = await service.deploy(activePolicy.id, activeVersion.version);

      // Assert
      expect(result.status).toBe(PolicyStatus.ACTIVE);
      expect(result.lastDeployedAt).toBeInstanceOf(Date);
      expect(result.deployedVersion).toBeDefined();
    });

    it('should throw NotFoundException when version not found', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      // Act & Assert
      await expect(
        service.deploy(mockPolicy.id, '2.0.0')
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException when deploying non-active version', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      // Act & Assert
      await expect(
        service.deploy(mockPolicy.id)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('rollback', () => {
    it('should successfully rollback to a previous version', async () => {
      // Arrange
      const policyWithMultipleVersions = {
        ...mockPolicy,
        versions: [
          { ...mockPolicy.versions[0], version: '1.0.0' },
          { ...mockPolicy.versions[0], version: '1.1.0', date: new Date() },
        ],
      };
      (service as any).policies = [policyWithMultipleVersions];

      versioningService.rollbackToVersion.mockReturnValue({
        success: true,
        newVersion: '1.0.1',
        message: 'Rollback successful',
      });

      // Act
      const result = await service.rollback(mockPolicy.id, '1.0.0');

      // Assert
      expect(result.version).toBe('1.0.1');
      expect(result.versions.length).toBeGreaterThan(policyWithMultipleVersions.versions.length);
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.rollback('non-existent-id', '1.0.0')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getAuditLogs', () => {
    it('should return audit logs for a policy', async () => {
      // Arrange
      (service as any).auditLogs = [
        { id: 'log-1', policyId: mockPolicy.id, action: 'created', timestamp: new Date() },
        { id: 'log-2', policyId: 'other-policy', action: 'created', timestamp: new Date() },
      ];

      // Act
      const result = await service.getAuditLogs(mockPolicy.id);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.every(log => log.policyId === mockPolicy.id)).toBe(true);
    });
  });

  describe('testPolicy', () => {
    it('should test a policy with test data', async () => {
      // Arrange
      (service as any).policies = [{ ...mockPolicy }];

      const testData = { user: { role: 'admin' }, resource: { type: 'dataset' } };

      // Act
      const result = await service.testPolicy(mockPolicy.id, testData);

      // Assert
      expect(result).toBeDefined();
      expect(result.policyId).toBe(mockPolicy.id);
      expect(result.testData).toEqual(testData);
      expect(result.result).toBe('passed');
    });

    it('should throw NotFoundException when policy not found', async () => {
      // Arrange
      (service as any).policies = [];

      // Act & Assert
      await expect(
        service.testPolicy('non-existent-id', {})
      ).rejects.toThrow(NotFoundException);
    });
  });
});
