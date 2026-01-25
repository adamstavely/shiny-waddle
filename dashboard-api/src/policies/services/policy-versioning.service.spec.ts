/**
 * Policy Versioning Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { PolicyVersioningService, VersionComparison, ImpactAnalysis } from './policy-versioning.service';
import { TestResultsService } from '../../test-results/test-results.service';
import { Policy, PolicyVersion } from '../entities/policy.entity';
import { PolicyStatus } from '../dto/create-policy.dto';

describe('PolicyVersioningService', () => {
  let service: PolicyVersioningService;
  let testResultsService: jest.Mocked<TestResultsService>;

  const mockPolicy: Policy = {
    id: 'policy-1',
    name: 'Test Policy',
    version: '1.0.0',
    type: 'rbac' as any,
    status: PolicyStatus.ACTIVE,
    rules: [],
    versions: [
      {
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        date: new Date('2024-01-01'),
        author: 'user-1',
        changes: [
          { type: 'added', description: 'Initial policy' },
        ],
      },
    ],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockTestResultsService = {
      query: jest.fn().mockResolvedValue([]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PolicyVersioningService,
        {
          provide: TestResultsService,
          useValue: mockTestResultsService,
        },
      ],
    }).compile();

    service = module.get<PolicyVersioningService>(PolicyVersioningService);
    testResultsService = module.get(TestResultsService) as jest.Mocked<TestResultsService>;
  });

  describe('createVersion', () => {
    it('should create a new version with incremented minor version', () => {
      // Arrange
      const changes: PolicyVersion['changes'] = [
        { type: 'changed', description: 'Updated rule' },
      ];

      // Act
      const result = service.createVersion(mockPolicy, changes, 'user-2', 'Update notes');

      // Assert
      expect(result.version).toBe('1.1.0');
      expect(result.status).toBe(mockPolicy.status);
      expect(result.author).toBe('user-2');
      expect(result.notes).toBe('Update notes');
      expect(result.changes).toEqual(changes);
      expect(result.date).toBeInstanceOf(Date);
    });

    it('should create version without author and notes', () => {
      // Arrange
      const changes: PolicyVersion['changes'] = [
        { type: 'added', description: 'New rule' },
      ];

      // Act
      const result = service.createVersion(mockPolicy, changes);

      // Assert
      expect(result.version).toBe('1.1.0');
      expect(result.author).toBeUndefined();
      expect(result.notes).toBeUndefined();
    });
  });

  describe('getVersionHistory', () => {
    beforeEach(() => {
      mockPolicy.versions = [
        {
          version: '1.0.0',
          status: PolicyStatus.ACTIVE,
          date: new Date('2024-01-01'),
          author: 'user-1',
          changes: [] as PolicyVersion['changes'],
        },
        {
          version: '1.1.0',
          status: PolicyStatus.ACTIVE,
          date: new Date('2024-01-15'),
          author: 'user-2',
          changes: [] as PolicyVersion['changes'],
        },
        {
          version: '1.2.0',
          status: PolicyStatus.ACTIVE,
          date: new Date('2024-01-10'),
          author: 'user-1',
          changes: [] as PolicyVersion['changes'],
        },
      ];
    });

    it('should return version history sorted by date descending', () => {
      // Act
      const result = service.getVersionHistory(mockPolicy);

      // Assert
      expect(result.length).toBe(3);
      expect(result[0].version).toBe('1.1.0'); // Most recent
      expect(result[1].version).toBe('1.2.0');
      expect(result[2].version).toBe('1.0.0'); // Oldest
    });
  });

  describe('getVersion', () => {
    it('should return version when found', () => {
      // Act
      const result = service.getVersion(mockPolicy, '1.0.0');

      // Assert
      expect(result).toBeDefined();
      expect(result?.version).toBe('1.0.0');
    });

    it('should return null when version not found', () => {
      // Act
      const result = service.getVersion(mockPolicy, '2.0.0');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('compareVersions', () => {
    beforeEach(() => {
      mockPolicy.versions = [
        {
          version: '1.0.0',
          status: PolicyStatus.ACTIVE,
          date: new Date('2024-01-01'),
          author: 'user-1',
          changes: [
            { type: 'added' as const, description: 'Initial rule' },
          ],
        },
        {
          version: '1.1.0',
          status: PolicyStatus.ACTIVE,
          date: new Date('2024-01-15'),
          author: 'user-2',
          changes: [
            { type: 'added' as const, description: 'Initial rule' },
            { type: 'changed' as const, description: 'Updated rule' },
          ],
        },
      ];
    });

    it('should compare two versions', () => {
      // Act
      const result = service.compareVersions(mockPolicy, '1.0.0', '1.1.0');

      // Assert
      expect(result.version1).toBe('1.0.0');
      expect(result.version2).toBe('1.1.0');
      expect(result.differences).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(result.summary.totalChanges).toBeGreaterThanOrEqual(0);
    });

    it('should throw NotFoundException when version1 not found', () => {
      // Act & Assert
      expect(() =>
        service.compareVersions(mockPolicy, '2.0.0', '1.1.0')
      ).toThrow(NotFoundException);
    });

    it('should throw NotFoundException when version2 not found', () => {
      // Act & Assert
      expect(() =>
        service.compareVersions(mockPolicy, '1.0.0', '2.0.0')
      ).toThrow(NotFoundException);
    });

    it('should detect status changes', () => {
      // Arrange
      const policyWithDifferentStatus: Policy = {
        id: 'policy-1',
        name: 'Test Policy',
        version: '1.0.0',
        type: 'rbac' as any,
        status: PolicyStatus.ACTIVE,
        rules: [],
        versions: [
          {
            version: '1.0.0',
            status: PolicyStatus.ACTIVE,
            date: new Date('2024-01-01'),
            author: 'user-1',
            changes: [
              { type: 'added' as const, description: 'Initial rule' },
            ],
          },
          {
            version: '1.1.0',
            status: PolicyStatus.DEPRECATED,
            date: new Date('2024-01-15'),
            author: 'user-2',
            changes: [
              { type: 'added' as const, description: 'Initial rule' },
              { type: 'changed' as const, description: 'Updated rule' },
            ],
          },
        ],
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      // Act
      const result = service.compareVersions(policyWithDifferentStatus, '1.0.0', '1.1.0');

      // Assert
      const statusChange = result.differences.find(d => d.field === 'status');
      expect(statusChange).toBeDefined();
      expect(statusChange?.changeType).toBe('modified');
    });
  });

  describe('analyzeImpact', () => {
    beforeEach(() => {
      mockPolicy.applicationId = 'app-1';
      testResultsService.query.mockResolvedValue([
        { id: 'result-1', applicationId: 'app-1', metadata: { policyId: 'policy-1' } },
        { id: 'result-2', applicationId: 'app-2', metadata: { policyId: 'policy-1' } },
      ] as any);
    });

    it('should analyze impact of policy version change', async () => {
      // Arrange
      const version: PolicyVersion = {
        version: '1.1.0',
        status: PolicyStatus.ACTIVE,
        date: new Date(),
        author: 'user-1',
        changes: [
          { type: 'changed', description: 'Updated rule' },
        ],
      };

      // Act
      const result = await service.analyzeImpact(mockPolicy, version);

      // Assert
      expect(result).toBeDefined();
      expect(result.affectedApplications).toBeDefined();
      expect(Array.isArray(result.affectedApplications)).toBe(true);
      expect(result.riskLevel).toBeDefined();
      expect(['low', 'medium', 'high', 'critical']).toContain(result.riskLevel);
      expect(result.recommendations).toBeDefined();
      expect(Array.isArray(result.recommendations)).toBe(true);
    });

    it('should calculate risk level based on changes', async () => {
      // Arrange
      const version: PolicyVersion = {
        version: '1.1.0',
        status: PolicyStatus.ACTIVE,
        date: new Date(),
        author: 'user-1',
        changes: [
          { type: 'changed', description: 'Critical rule change' },
        ],
      };

      // Act
      const result = await service.analyzeImpact(mockPolicy, version);

      // Assert
      expect(result.riskLevel).toBeDefined();
    });
  });
});
