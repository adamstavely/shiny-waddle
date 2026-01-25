/**
 * Unified Findings Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, HttpException } from '@nestjs/common';
import { UnifiedFindingsController } from './unified-findings.controller';
import { UnifiedFindingsService } from './unified-findings.service';
import { UserContext } from '../common/interfaces/user-context.interface';

describe('UnifiedFindingsController', () => {
  let controller: UnifiedFindingsController;
  let service: jest.Mocked<UnifiedFindingsService>;

  const mockUser: UserContext = {
    id: 'user-1',
    email: 'test@example.com',
    roles: ['developer'],
    applicationIds: ['app-1'],
    teamNames: ['team-1'],
  };

  const mockFinding = {
    id: 'finding-1',
    source: 'scanner-1',
    severity: 'high',
    status: 'open',
    applicationId: 'app-1',
  };

  beforeEach(async () => {
    const mockService = {
      getAllFindings: jest.fn(),
      getStatistics: jest.fn(),
      getFindingsAsECS: jest.fn(),
      getFindingById: jest.fn(),
      normalizeAndIngest: jest.fn(),
      updateFinding: jest.fn(),
      deleteFinding: jest.fn(),
      getSchemaVersionInfo: jest.fn(),
      detectFindingVersion: jest.fn(),
      migrateFinding: jest.fn(),
      validateFinding: jest.fn(),
      calculateRiskScore: jest.fn(),
      calculateAllRiskScores: jest.fn(),
      getPrioritizedFindings: jest.fn(),
      aggregateRiskByApplication: jest.fn(),
      aggregateRiskByTeam: jest.fn(),
      aggregateRiskByOrganization: jest.fn(),
      getRiskTrends: jest.fn(),
      correlateFindings: jest.fn(),
      getRelatedFindings: jest.fn(),
      analyzeAttackPaths: jest.fn(),
      getApplicationAttackPaths: jest.fn(),
      getAttackPathPrioritizedFindings: jest.fn(),
      getDeveloperDashboard: jest.fn(),
      getRemediationHelp: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [UnifiedFindingsController],
      providers: [
        {
          provide: UnifiedFindingsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<UnifiedFindingsController>(UnifiedFindingsController);
    service = module.get(UnifiedFindingsService) as jest.Mocked<UnifiedFindingsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAllFindings', () => {
    it('should get all findings', async () => {
      // Arrange
      service.getAllFindings.mockResolvedValue([mockFinding] as any);

      // Act
      const result = await controller.getAllFindings();

      // Assert
      expect(result).toEqual([mockFinding]);
      expect(service.getAllFindings).toHaveBeenCalledWith({});
    });

    it('should get findings with filters', async () => {
      // Arrange
      service.getAllFindings.mockResolvedValue([mockFinding] as any);

      // Act
      const result = await controller.getAllFindings('scanner-1', 'scanner-1', 'high', 'open', 'app-1');

      // Assert
      expect(result).toEqual([mockFinding]);
      expect(service.getAllFindings).toHaveBeenCalledWith({
        source: 'scanner-1',
        scannerId: 'scanner-1',
        severity: 'high',
        status: 'open',
        applicationId: 'app-1',
      });
    });
  });

  describe('getStatistics', () => {
    it('should get statistics', async () => {
      // Arrange
      const stats = {
        total: 100,
        bySource: {},
        bySeverity: {},
        byStatus: {},
        byScanner: {},
      };
      service.getStatistics.mockResolvedValue(stats as any);

      // Act
      const result = await controller.getStatistics();

      // Assert
      expect(result).toEqual(stats);
      expect(service.getStatistics).toHaveBeenCalledTimes(1);
    });
  });

  describe('getFindingsAsECS', () => {
    it('should get findings as ECS format', async () => {
      // Arrange
      const ecsFindings = [{ '@timestamp': '2024-01-01', event: {} }];
      service.getFindingsAsECS.mockResolvedValue(ecsFindings as any);

      // Act
      const result = await controller.getFindingsAsECS();

      // Assert
      expect(result).toEqual(ecsFindings);
      expect(service.getFindingsAsECS).toHaveBeenCalledWith({});
    });
  });

  describe('getFindingById', () => {
    it('should get finding by id', async () => {
      // Arrange
      service.getFindingById.mockResolvedValue(mockFinding as any);

      // Act
      const result = await controller.getFindingById('finding-1');

      // Assert
      expect(result).toEqual(mockFinding);
      expect(service.getFindingById).toHaveBeenCalledWith('finding-1');
    });

    it('should throw HttpException when finding not found', async () => {
      // Arrange
      service.getFindingById.mockResolvedValue(null);

      // Act & Assert
      await expect(controller.getFindingById('finding-1')).rejects.toThrow(HttpException);
      expect(service.getFindingById).toHaveBeenCalledWith('finding-1');
    });
  });

  describe('normalizeAndIngest', () => {
    it('should normalize and ingest scanner results', async () => {
      // Arrange
      const scannerResults = [{ id: 'result-1', scannerId: 'scanner-1', findings: [] }] as any;
      const result = { ingested: 1 };
      service.normalizeAndIngest.mockResolvedValue(result as any);

      // Act
      const response = await controller.normalizeAndIngest(scannerResults);

      // Assert
      expect(response).toEqual(result);
      expect(service.normalizeAndIngest).toHaveBeenCalledWith(scannerResults);
    });
  });

  describe('updateFinding', () => {
    it('should update a finding', async () => {
      // Arrange
      const updates = { status: 'resolved' as const };
      const updatedFinding = { ...mockFinding, ...updates };
      service.updateFinding.mockResolvedValue(updatedFinding as any);

      // Act
      const result = await controller.updateFinding('finding-1', updates);

      // Assert
      expect(result).toEqual(updatedFinding);
      expect(service.updateFinding).toHaveBeenCalledWith('finding-1', updates);
    });
  });

  describe('deleteFinding', () => {
    it('should delete a finding', async () => {
      // Arrange
      service.deleteFinding.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteFinding('finding-1');

      // Assert
      expect(result).toEqual({ success: true });
      expect(service.deleteFinding).toHaveBeenCalledWith('finding-1');
    });
  });

  describe('Schema Versioning', () => {
    describe('getSchemaVersion', () => {
      it('should get schema version info', async () => {
        // Arrange
        const versionInfo = { version: '1.0.0' };
        service.getSchemaVersionInfo.mockResolvedValue(versionInfo as any);

        // Act
        const result = await controller.getSchemaVersion();

        // Assert
        expect(result).toEqual(versionInfo);
        expect(service.getSchemaVersionInfo).toHaveBeenCalledWith(undefined);
      });
    });

    describe('detectVersion', () => {
      it('should detect finding version', async () => {
        // Arrange
        const finding = { id: 'finding-1' };
        const detected = { version: '1.0.0' };
        service.detectFindingVersion.mockResolvedValue(detected as any);

        // Act
        const result = await controller.detectVersion(finding);

        // Assert
        expect(result).toEqual(detected);
        expect(service.detectFindingVersion).toHaveBeenCalledWith(finding);
      });
    });

    describe('migrateFinding', () => {
      it('should migrate finding', async () => {
        // Arrange
        const body = { finding: { id: 'finding-1' }, fromVersion: '1.0.0', toVersion: '2.0.0' };
        const migrated = { id: 'finding-1', version: '2.0.0' };
        service.migrateFinding.mockResolvedValue(migrated as any);

        // Act
        const result = await controller.migrateFinding(body);

        // Assert
        expect(result).toEqual(migrated);
        expect(service.migrateFinding).toHaveBeenCalledWith(body.finding, body.fromVersion, body.toVersion);
      });
    });

    describe('validateFinding', () => {
      it('should validate finding', async () => {
        // Arrange
        const body = { finding: { id: 'finding-1' }, version: '1.0.0' };
        const validation = { valid: true };
        service.validateFinding.mockResolvedValue(validation as any);

        // Act
        const result = await controller.validateFinding(body);

        // Assert
        expect(result).toEqual(validation);
        expect(service.validateFinding).toHaveBeenCalledWith(body.finding, body.version);
      });
    });
  });

  describe('Risk Scoring', () => {
    describe('calculateRiskScore', () => {
      it('should calculate risk score for a finding', async () => {
        // Arrange
        const riskScore = { score: 85 };
        service.calculateRiskScore.mockResolvedValue(riskScore as any);

        // Act
        const result = await controller.calculateRiskScore('finding-1');

        // Assert
        expect(result).toEqual(riskScore);
        expect(service.calculateRiskScore).toHaveBeenCalledWith('finding-1');
      });
    });

    describe('calculateAllRiskScores', () => {
      it('should calculate risk scores for all findings', async () => {
        // Arrange
        const result = { calculated: 100 };
        service.calculateAllRiskScores.mockResolvedValue(result as any);

        // Act
        const response = await controller.calculateAllRiskScores();

        // Assert
        expect(response).toEqual(result);
        expect(service.calculateAllRiskScores).toHaveBeenCalledTimes(1);
      });
    });

    describe('getPrioritizedFindings', () => {
      it('should get prioritized findings', async () => {
        // Arrange
        service.getPrioritizedFindings.mockResolvedValue([mockFinding] as any);

        // Act
        const result = await controller.getPrioritizedFindings();

        // Assert
        expect(result).toEqual([mockFinding]);
        expect(service.getPrioritizedFindings).toHaveBeenCalledWith(undefined);
      });
    });

    describe('getApplicationRisk', () => {
      it('should get application risk aggregation', async () => {
        // Arrange
        const risk = { applicationId: 'app-1', totalRisk: 75 };
        service.aggregateRiskByApplication.mockResolvedValue(risk as any);

        // Act
        const result = await controller.getApplicationRisk('app-1');

        // Assert
        expect(result).toEqual(risk);
        expect(service.aggregateRiskByApplication).toHaveBeenCalledWith('app-1');
      });
    });

    describe('getTeamRisk', () => {
      it('should get team risk aggregation', async () => {
        // Arrange
        const risk = { teamName: 'team-1', totalRisk: 70 };
        service.aggregateRiskByTeam.mockResolvedValue(risk as any);

        // Act
        const result = await controller.getTeamRisk('team-1');

        // Assert
        expect(result).toEqual(risk);
        expect(service.aggregateRiskByTeam).toHaveBeenCalledWith('team-1');
      });
    });

    describe('getOrganizationRisk', () => {
      it('should get organization risk aggregation', async () => {
        // Arrange
        const risk = { totalRisk: 65 };
        service.aggregateRiskByOrganization.mockResolvedValue(risk as any);

        // Act
        const result = await controller.getOrganizationRisk();

        // Assert
        expect(result).toEqual(risk);
        expect(service.aggregateRiskByOrganization).toHaveBeenCalledTimes(1);
      });
    });

    describe('getRiskTrends', () => {
      it('should get risk trends', async () => {
        // Arrange
        const trends = [{ date: '2024-01-01', risk: 75 }];
        service.getRiskTrends.mockResolvedValue(trends as any);

        // Act
        const result = await controller.getRiskTrends();

        // Assert
        expect(result).toEqual(trends);
        expect(service.getRiskTrends).toHaveBeenCalledWith(30);
      });
    });
  });

  describe('Correlation & Deduplication', () => {
    describe('correlateFindings', () => {
      it('should correlate findings', async () => {
        // Arrange
        const correlated = { groups: [] };
        service.correlateFindings.mockResolvedValue(correlated as any);

        // Act
        const result = await controller.correlateFindings();

        // Assert
        expect(result).toEqual(correlated);
        expect(service.correlateFindings).toHaveBeenCalledWith({});
      });
    });

    describe('getRelatedFindings', () => {
      it('should get related findings', async () => {
        // Arrange
        service.getRelatedFindings.mockResolvedValue([mockFinding] as any);

        // Act
        const result = await controller.getRelatedFindings('finding-1');

        // Assert
        expect(result).toEqual([mockFinding]);
        expect(service.getRelatedFindings).toHaveBeenCalledWith('finding-1');
      });
    });
  });

  describe('Attack Path Analysis', () => {
    describe('analyzeAttackPaths', () => {
      it('should analyze attack paths', async () => {
        // Arrange
        const paths = { paths: [] };
        service.analyzeAttackPaths.mockResolvedValue(paths as any);

        // Act
        const result = await controller.analyzeAttackPaths();

        // Assert
        expect(result).toEqual(paths);
        expect(service.analyzeAttackPaths).toHaveBeenCalledWith({});
      });
    });

    describe('getApplicationAttackPaths', () => {
      it('should get application attack paths', async () => {
        // Arrange
        const paths = { paths: [] };
        service.getApplicationAttackPaths.mockResolvedValue(paths as any);

        // Act
        const result = await controller.getApplicationAttackPaths('app-1');

        // Assert
        expect(result).toEqual(paths);
        expect(service.getApplicationAttackPaths).toHaveBeenCalledWith('app-1');
      });
    });

    describe('getAttackPathPrioritizedFindings', () => {
      it('should get attack path prioritized findings', async () => {
        // Arrange
        service.getAttackPathPrioritizedFindings.mockResolvedValue([mockFinding] as any);

        // Act
        const result = await controller.getAttackPathPrioritizedFindings();

        // Assert
        expect(result).toEqual([mockFinding]);
        expect(service.getAttackPathPrioritizedFindings).toHaveBeenCalledWith(undefined);
      });
    });
  });

  describe('Developer Dashboard', () => {
    describe('getDeveloperDashboard', () => {
      it('should get developer dashboard', async () => {
        // Arrange
        const dashboard = { findings: [] };
        service.getDeveloperDashboard.mockResolvedValue(dashboard as any);

        // Act
        const result = await controller.getDeveloperDashboard(mockUser);

        // Assert
        expect(result).toEqual(dashboard);
        expect(service.getDeveloperDashboard).toHaveBeenCalledWith(['app-1'], ['team-1']);
      });
    });

    describe('getRemediationHelp', () => {
      it('should get remediation help', async () => {
        // Arrange
        const help = { steps: [] };
        service.getRemediationHelp.mockResolvedValue(help as any);

        // Act
        const result = await controller.getRemediationHelp('finding-1');

        // Assert
        expect(result).toEqual(help);
        expect(service.getRemediationHelp).toHaveBeenCalledWith('finding-1');
      });
    });
  });
});
