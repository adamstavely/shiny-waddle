/**
 * Policies Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { PoliciesController } from './policies.controller';
import { PoliciesService } from './policies.service';
import { CreatePolicyDto, PolicyType, PolicyStatus, PolicyEffect } from './dto/create-policy.dto';
import { UpdatePolicyDto } from './dto/update-policy.dto';
import { Policy, PolicyVersion } from './entities/policy.entity';

describe('PoliciesController', () => {
  let controller: PoliciesController;
  let policiesService: jest.Mocked<PoliciesService>;

  const mockPolicy: Policy = {
    id: 'policy-1',
    name: 'Test Policy',
    description: 'Test policy description',
    type: PolicyType.RBAC,
    version: '1.0.0',
    status: PolicyStatus.DRAFT,
    effect: PolicyEffect.ALLOW,
    priority: 1,
    rules: [],
    conditions: [],
    applicationId: 'app-1',
    versions: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockPolicies: Policy[] = [
    mockPolicy,
    {
      ...mockPolicy,
      id: 'policy-2',
      name: 'Another Policy',
      status: PolicyStatus.ACTIVE,
    },
  ];

  const mockPolicyVersion: PolicyVersion = {
    version: '1.1.0',
    status: PolicyStatus.ACTIVE,
    date: new Date(),
    author: 'user-1',
    changes: [{ type: 'added', description: 'Added new rule' }],
  };

  beforeEach(async () => {
    const mockPoliciesService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
      getVersions: jest.fn(),
      addVersion: jest.fn(),
      compareVersions: jest.fn(),
      deploy: jest.fn(),
      rollback: jest.fn(),
      getAuditLogs: jest.fn(),
      analyzeImpact: jest.fn(),
      testPolicy: jest.fn(),
      findTestsUsingPolicy: jest.fn(),
      getDomainConfig: jest.fn(),
      saveDomainConfig: jest.fn(),
      getAllDomainConfigs: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [PoliciesController],
      providers: [
        {
          provide: PoliciesService,
          useValue: mockPoliciesService,
        },
      ],
    }).compile();

    controller = module.get<PoliciesController>(PoliciesController);
    policiesService = module.get(PoliciesService) as jest.Mocked<PoliciesService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createPolicyDto: CreatePolicyDto = {
      name: 'New Policy',
      description: 'New policy description',
      type: PolicyType.RBAC,
      version: '1.0.0',
      status: PolicyStatus.DRAFT,
      effect: PolicyEffect.ALLOW,
    };

    it('should create a policy successfully', async () => {
      // Arrange
      policiesService.create.mockResolvedValue(mockPolicy);

      // Act
      const result = await controller.create(createPolicyDto);

      // Assert
      expect(result).toEqual(mockPolicy);
      expect(policiesService.create).toHaveBeenCalledTimes(1);
      expect(policiesService.create).toHaveBeenCalledWith(createPolicyDto);
    });

    it('should create a policy with minimal required fields', async () => {
      // Arrange
      const minimalDto: CreatePolicyDto = {
        name: 'Minimal Policy',
        type: PolicyType.ABAC,
        version: '1.0.0',
      };
      policiesService.create.mockResolvedValue({
        ...mockPolicy,
        ...minimalDto,
      });

      // Act
      const result = await controller.create(minimalDto);

      // Assert
      expect(result).toEqual({ ...mockPolicy, ...minimalDto });
      expect(policiesService.create).toHaveBeenCalledWith(minimalDto);
    });
  });

  describe('findAll', () => {
    it('should return all policies when no filters provided', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue(mockPolicies);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockPolicies);
      expect(policiesService.findAll).toHaveBeenCalledTimes(1);
      expect(policiesService.findAll).toHaveBeenCalledWith(undefined, undefined, undefined);
    });

    it('should filter policies by type', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue([mockPolicy]);

      // Act
      const result = await controller.findAll(PolicyType.RBAC);

      // Assert
      expect(result).toEqual([mockPolicy]);
      expect(policiesService.findAll).toHaveBeenCalledWith(PolicyType.RBAC, undefined, undefined);
    });

    it('should filter policies by status', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue([mockPolicies[1]]);

      // Act
      const result = await controller.findAll(undefined, PolicyStatus.ACTIVE);

      // Assert
      expect(result).toEqual([mockPolicies[1]]);
      expect(policiesService.findAll).toHaveBeenCalledWith(undefined, PolicyStatus.ACTIVE, undefined);
    });

    it('should filter policies by applicationId', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue([mockPolicy]);

      // Act
      const result = await controller.findAll(undefined, undefined, 'app-1');

      // Assert
      expect(result).toEqual([mockPolicy]);
      expect(policiesService.findAll).toHaveBeenCalledWith(undefined, undefined, 'app-1');
    });

    it('should filter policies by all parameters', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue([mockPolicy]);

      // Act
      const result = await controller.findAll(PolicyType.RBAC, PolicyStatus.DRAFT, 'app-1');

      // Assert
      expect(result).toEqual([mockPolicy]);
      expect(policiesService.findAll).toHaveBeenCalledWith(
        PolicyType.RBAC,
        PolicyStatus.DRAFT,
        'app-1'
      );
    });

    it('should return empty array when no policies found', async () => {
      // Arrange
      policiesService.findAll.mockResolvedValue([]);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOne', () => {
    it('should return a policy by id', async () => {
      // Arrange
      policiesService.findOne.mockResolvedValue(mockPolicy);

      // Act
      const result = await controller.findOne('policy-1');

      // Assert
      expect(result).toEqual(mockPolicy);
      expect(policiesService.findOne).toHaveBeenCalledTimes(1);
      expect(policiesService.findOne).toHaveBeenCalledWith('policy-1');
    });

    it('should propagate NotFoundException when policy not found', async () => {
      // Arrange
      policiesService.findOne.mockRejectedValue(new NotFoundException('Policy not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
      expect(policiesService.findOne).toHaveBeenCalledWith('non-existent');
    });
  });

  describe('update', () => {
    const updatePolicyDto: UpdatePolicyDto = {
      name: 'Updated Policy',
      status: PolicyStatus.ACTIVE,
    };

    it('should update a policy successfully', async () => {
      // Arrange
      const updatedPolicy = { ...mockPolicy, ...updatePolicyDto };
      policiesService.update.mockResolvedValue(updatedPolicy);

      // Act
      const result = await controller.update('policy-1', updatePolicyDto);

      // Assert
      expect(result).toEqual(updatedPolicy);
      expect(policiesService.update).toHaveBeenCalledTimes(1);
      expect(policiesService.update).toHaveBeenCalledWith('policy-1', updatePolicyDto);
    });

    it('should propagate NotFoundException when policy not found', async () => {
      // Arrange
      policiesService.update.mockRejectedValue(new NotFoundException('Policy not found'));

      // Act & Assert
      await expect(controller.update('non-existent', updatePolicyDto)).rejects.toThrow(
        NotFoundException
      );
    });
  });

  describe('remove', () => {
    it('should delete a policy successfully', async () => {
      // Arrange
      policiesService.remove.mockResolvedValue(undefined);

      // Act
      await controller.remove('policy-1');

      // Assert
      expect(policiesService.remove).toHaveBeenCalledTimes(1);
      expect(policiesService.remove).toHaveBeenCalledWith('policy-1');
    });

    it('should propagate NotFoundException when policy not found', async () => {
      // Arrange
      policiesService.remove.mockRejectedValue(new NotFoundException('Policy not found'));

      // Act & Assert
      await expect(controller.remove('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('getVersions', () => {
    const mockVersions: PolicyVersion[] = [mockPolicyVersion];

    it('should return policy versions', async () => {
      // Arrange
      policiesService.getVersions.mockResolvedValue(mockVersions);

      // Act
      const result = await controller.getVersions('policy-1');

      // Assert
      expect(result).toEqual(mockVersions);
      expect(policiesService.getVersions).toHaveBeenCalledTimes(1);
      expect(policiesService.getVersions).toHaveBeenCalledWith('policy-1');
    });

    it('should return empty array when no versions exist', async () => {
      // Arrange
      policiesService.getVersions.mockResolvedValue([]);

      // Act
      const result = await controller.getVersions('policy-1');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('addVersion', () => {
    it('should add a version to a policy', async () => {
      // Arrange
      const updatedPolicy = { ...mockPolicy, versions: [mockPolicyVersion] };
      policiesService.addVersion.mockResolvedValue(updatedPolicy);

      // Act
      const result = await controller.addVersion('policy-1', mockPolicyVersion);

      // Assert
      expect(result).toEqual(updatedPolicy);
      expect(policiesService.addVersion).toHaveBeenCalledTimes(1);
      expect(policiesService.addVersion).toHaveBeenCalledWith('policy-1', mockPolicyVersion);
    });
  });

  describe('compareVersions', () => {
    const mockComparison = {
      version1: '1.0.0',
      version2: '1.1.0',
      differences: [
        {
          field: 'rules',
          oldValue: [],
          newValue: [{ id: 'rule-1' }],
          changeType: 'added' as const,
        },
      ],
      summary: {
        totalChanges: 1,
        addedFields: 1,
        removedFields: 0,
        modifiedFields: 0,
      },
    };

    it('should compare two policy versions', async () => {
      // Arrange
      policiesService.compareVersions.mockResolvedValue(mockComparison);

      // Act
      const result = await controller.compareVersions('policy-1', '1.0.0', '1.1.0');

      // Assert
      expect(result).toEqual(mockComparison);
      expect(policiesService.compareVersions).toHaveBeenCalledTimes(1);
      expect(policiesService.compareVersions).toHaveBeenCalledWith('policy-1', '1.0.0', '1.1.0');
    });
  });

  describe('deploy', () => {
    it('should deploy a policy with default version', async () => {
      // Arrange
      const deployedPolicy = { ...mockPolicy, status: PolicyStatus.ACTIVE };
      policiesService.deploy.mockResolvedValue(deployedPolicy);

      // Act
      const result = await controller.deploy('policy-1', undefined);

      // Assert
      expect(result).toEqual(deployedPolicy);
      expect(policiesService.deploy).toHaveBeenCalledTimes(1);
      expect(policiesService.deploy).toHaveBeenCalledWith('policy-1', undefined);
    });

    it('should deploy a policy with specific version', async () => {
      // Arrange
      const deployedPolicy = { ...mockPolicy, status: PolicyStatus.ACTIVE };
      policiesService.deploy.mockResolvedValue(deployedPolicy);

      // Act
      const result = await controller.deploy('policy-1', '1.1.0');

      // Assert
      expect(result).toEqual(deployedPolicy);
      expect(policiesService.deploy).toHaveBeenCalledWith('policy-1', '1.1.0');
    });
  });

  describe('rollback', () => {
    it('should rollback a policy to a specific version', async () => {
      // Arrange
      const rolledBackPolicy = { ...mockPolicy, version: '1.0.0' };
      policiesService.rollback.mockResolvedValue(rolledBackPolicy);

      // Act
      const result = await controller.rollback('policy-1', '1.0.0');

      // Assert
      expect(result).toEqual(rolledBackPolicy);
      expect(policiesService.rollback).toHaveBeenCalledTimes(1);
      expect(policiesService.rollback).toHaveBeenCalledWith('policy-1', '1.0.0');
    });
  });

  describe('getAuditLogs', () => {
    const mockAuditLogs = [
      {
        id: 'log-1',
        policyId: 'policy-1',
        action: 'created' as const,
        userId: 'user-1',
        timestamp: new Date(),
      },
    ];

    it('should return audit logs for a policy', async () => {
      // Arrange
      policiesService.getAuditLogs.mockResolvedValue(mockAuditLogs);

      // Act
      const result = await controller.getAuditLogs('policy-1');

      // Assert
      expect(result).toEqual(mockAuditLogs);
      expect(policiesService.getAuditLogs).toHaveBeenCalledTimes(1);
      expect(policiesService.getAuditLogs).toHaveBeenCalledWith('policy-1');
    });
  });

  describe('analyzeImpact', () => {
    const mockImpactAnalysis = {
      affectedApplications: ['app-1', 'app-2'],
      affectedTestResults: 5,
      potentialViolations: 10,
      riskLevel: 'medium' as const,
      recommendations: ['Review test results', 'Update affected applications'],
    };

    it('should analyze impact with default version', async () => {
      // Arrange
      policiesService.analyzeImpact.mockResolvedValue(mockImpactAnalysis);

      // Act
      const result = await controller.analyzeImpact('policy-1', undefined);

      // Assert
      expect(result).toEqual(mockImpactAnalysis);
      expect(policiesService.analyzeImpact).toHaveBeenCalledTimes(1);
      expect(policiesService.analyzeImpact).toHaveBeenCalledWith('policy-1', undefined);
    });

    it('should analyze impact with specific version', async () => {
      // Arrange
      policiesService.analyzeImpact.mockResolvedValue(mockImpactAnalysis);

      // Act
      const result = await controller.analyzeImpact('policy-1', '1.1.0');

      // Assert
      expect(result).toEqual(mockImpactAnalysis);
      expect(policiesService.analyzeImpact).toHaveBeenCalledWith('policy-1', '1.1.0');
    });
  });

  describe('testPolicy', () => {
    const mockTestData = { userId: 'user-1', resource: 'resource-1' };
    const mockTestResult = { passed: true, details: {} };

    it('should test a policy with test data', async () => {
      // Arrange
      policiesService.testPolicy.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testPolicy('policy-1', mockTestData);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(policiesService.testPolicy).toHaveBeenCalledTimes(1);
      expect(policiesService.testPolicy).toHaveBeenCalledWith('policy-1', mockTestData);
    });
  });

  describe('getTestsUsingPolicy', () => {
    const mockTests = [{ id: 'test-1', name: 'Test 1' }];

    it('should return tests using a policy', async () => {
      // Arrange
      policiesService.findTestsUsingPolicy.mockResolvedValue(mockTests);

      // Act
      const result = await controller.getTestsUsingPolicy('policy-1');

      // Assert
      expect(result).toEqual(mockTests);
      expect(policiesService.findTestsUsingPolicy).toHaveBeenCalledTimes(1);
      expect(policiesService.findTestsUsingPolicy).toHaveBeenCalledWith('policy-1');
    });
  });

  describe('getDomainConfig', () => {
    const mockDomainConfig = { domain: 'rbac', config: { enabled: true } };

    it('should return domain configuration', async () => {
      // Arrange
      policiesService.getDomainConfig.mockResolvedValue(mockDomainConfig);

      // Act
      const result = await controller.getDomainConfig('rbac');

      // Assert
      expect(result).toEqual(mockDomainConfig);
      expect(policiesService.getDomainConfig).toHaveBeenCalledTimes(1);
      expect(policiesService.getDomainConfig).toHaveBeenCalledWith('rbac');
    });
  });

  describe('saveDomainConfig', () => {
    const mockConfig = { enabled: true, rules: [] };

    it('should save domain configuration', async () => {
      // Arrange
      policiesService.saveDomainConfig.mockResolvedValue(undefined);

      // Act
      const result = await controller.saveDomainConfig('rbac', mockConfig);

      // Assert
      expect(result).toEqual({ message: 'Domain configuration saved successfully' });
      expect(policiesService.saveDomainConfig).toHaveBeenCalledTimes(1);
      expect(policiesService.saveDomainConfig).toHaveBeenCalledWith('rbac', mockConfig);
    });
  });

  describe('getAllDomainConfigs', () => {
    const mockAllConfigs = {
      rbac: { enabled: true },
      abac: { enabled: false },
    };

    it('should return all domain configurations', async () => {
      // Arrange
      policiesService.getAllDomainConfigs.mockResolvedValue(mockAllConfigs);

      // Act
      const result = await controller.getAllDomainConfigs();

      // Assert
      expect(result).toEqual(mockAllConfigs);
      expect(policiesService.getAllDomainConfigs).toHaveBeenCalledTimes(1);
      expect(policiesService.getAllDomainConfigs).toHaveBeenCalledWith();
    });
  });
});
