/**
 * Unified Findings Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { UnifiedFindingsService } from './unified-findings.service';
import { ApplicationsService } from '../applications/applications.service';
import { UsersService } from '../users/users.service';
import { NotificationsService } from '../notifications/notifications.service';
import { AlertingService } from '../alerting/alerting.service';
import { UnifiedFinding } from '../../../heimdall-framework/core/unified-finding-schema';
import { ScannerResult } from '../../../heimdall-framework/services/normalization-engine';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');

describe('UnifiedFindingsService', () => {
  let service: UnifiedFindingsService;
  let applicationsService: jest.Mocked<ApplicationsService>;
  let usersService: jest.Mocked<UsersService>;
  let notificationsService: jest.Mocked<NotificationsService>;
  let alertingService: jest.Mocked<AlertingService>;

  const mockFinding: UnifiedFinding = {
    id: 'finding-1',
    title: 'Test Finding',
    description: 'Test finding description',
    severity: 'high',
    confidence: 'confirmed',
    status: 'open',
    source: 'test-scanner' as any,
    scannerId: 'scanner-1' as any,
    scannerFindingId: 'scanner-finding-1',
    event: {
      kind: 'event',
      category: 'security',
      type: 'finding',
      action: 'detected',
      severity: 700,
    },
    asset: {
      type: 'application',
      applicationId: 'app-1',
    },
    remediation: {
      description: 'Fix the issue',
      steps: ['Step 1', 'Step 2'],
      references: [],
    },
    riskScore: 75,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockScannerResult: ScannerResult = {
    scannerId: 'scanner-1',
    source: 'test-scanner',
    findings: [
      {
        id: 'finding-1',
        title: 'Test Finding',
        description: 'Test description',
        severity: 'high',
        asset: {
          applicationId: 'app-1',
          applicationName: 'Test App',
          type: 'application',
        },
      },
    ],
    metadata: {},
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Mock fs operations BEFORE creating service (constructor calls loadFindings)
    const fs = require('fs/promises');
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
    fs.mkdir = jest.fn().mockResolvedValue(undefined);

    const mockApplicationsService = {
      findAll: jest.fn().mockResolvedValue([
        { id: 'app-1', name: 'Test App', team: 'team-1' },
      ]),
    };

    const mockUsersService = {
      findAll: jest.fn().mockResolvedValue([
        { id: 'user-1', roles: ['admin'], teams: ['team-1'] },
      ]),
    };

    const mockNotificationsService = {
      getUserPreferences: jest.fn().mockReturnValue({
        enabled: true,
        notifyOnCriticalFinding: true,
        scoreDropThreshold: 5,
      }),
      notifyCriticalFinding: jest.fn().mockResolvedValue(undefined),
      notifyScoreDrop: jest.fn().mockResolvedValue(undefined),
    };

    const mockAlertingService = {
      evaluateFinding: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UnifiedFindingsService,
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
        {
          provide: AlertingService,
          useValue: mockAlertingService,
        },
      ],
    }).compile();

    service = module.get<UnifiedFindingsService>(UnifiedFindingsService);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;
    usersService = module.get(UsersService) as jest.Mocked<UsersService>;
    notificationsService = module.get(NotificationsService) as jest.Mocked<NotificationsService>;
    alertingService = module.get(AlertingService) as jest.Mocked<AlertingService>;

    // Wait for loadFindings to complete (it's called in constructor without await)
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Mock loadFindings to prevent it from resetting our test data in future calls
    jest.spyOn(service as any, 'loadFindings').mockResolvedValue(undefined);
    
    // Ensure findings array is initialized and empty
    if (!(service as any).findings) {
      (service as any).findings = [];
    } else {
      (service as any).findings = [];
    }
  });

  describe('getAllFindings', () => {
    beforeEach(() => {
      // Set findings array for tests
      (service as any).findings = [mockFinding];
    });

    it('should return all findings when no filters provided', async () => {
      // Act
      const result = await service.getAllFindings();

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].id).toBe(mockFinding.id);
    });

    it('should filter by source', async () => {
      // Act
      const result = await service.getAllFindings({ source: 'test-scanner' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].source).toBe('test-scanner');
    });

    it('should filter by severity', async () => {
      // Act
      const result = await service.getAllFindings({ severity: 'high' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].severity).toBe('high');
    });

    it('should filter by status', async () => {
      // Act
      const result = await service.getAllFindings({ status: 'open' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].status).toBe('open');
    });

    it('should filter by applicationId', async () => {
      // Act
      const result = await service.getAllFindings({ applicationId: 'app-1' });

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].asset.applicationId).toBe('app-1');
    });

    it('should return empty array when no findings match filters', async () => {
      // Act
      const result = await service.getAllFindings({ severity: 'low' });

      // Assert
      expect(result.length).toBe(0);
    });

    it('should sort findings by createdAt descending', async () => {
      // Arrange
      const olderFinding = {
        ...mockFinding,
        id: 'finding-2',
        createdAt: new Date('2024-01-01'),
      };
      (service as any).findings = [olderFinding, mockFinding];

      // Act
      const result = await service.getAllFindings();

      // Assert
      expect(result[0].id).toBe(mockFinding.id);
      expect(result[1].id).toBe(olderFinding.id);
    });
  });

  describe('getFindingById', () => {
    beforeEach(() => {
      (service as any).findings = [mockFinding];
    });

    it('should return finding when found', async () => {
      // Act
      const result = await service.getFindingById('finding-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('finding-1');
    });

    it('should return null when finding not found', async () => {
      // Act
      const result = await service.getFindingById('non-existent-id');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('updateFinding', () => {
    beforeEach(() => {
      (service as any).findings = [{ ...mockFinding }];
      const fs = require('fs/promises');
      fs.writeFile = jest.fn().mockResolvedValue(undefined);
    });

    it('should successfully update a finding', async () => {
      // Arrange
      const updates = { status: 'resolved' as const };

      // Act
      const result = await service.updateFinding('finding-1', updates);

      // Assert
      expect(result.status).toBe('resolved');
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error when finding not found', async () => {
      // Act & Assert
      await expect(
        service.updateFinding('non-existent-id', { status: 'resolved' })
      ).rejects.toThrow('Finding not found');
    });

    it('should block direct status change to risk-accepted', async () => {
      // Act & Assert
      await expect(
        service.updateFinding('finding-1', { status: 'risk-accepted' })
      ).rejects.toThrow('Cannot directly change status');
    });

    it('should block direct status change to false-positive', async () => {
      // Act & Assert
      await expect(
        service.updateFinding('finding-1', { status: 'false-positive' })
      ).rejects.toThrow('Cannot directly change status');
    });

    it('should allow status change if already set to that status', async () => {
      // Arrange
      (service as any).findings = [{ ...mockFinding, status: 'risk-accepted' }];

      // Act
      const result = await service.updateFinding('finding-1', { status: 'risk-accepted' });

      // Assert
      expect(result.status).toBe('risk-accepted');
    });
  });

  describe('deleteFinding', () => {
    beforeEach(() => {
      (service as any).findings = [{ ...mockFinding }];
      const fs = require('fs/promises');
      fs.writeFile = jest.fn().mockResolvedValue(undefined);
    });

    it('should successfully delete a finding', async () => {
      // Act
      await service.deleteFinding('finding-1');

      // Assert
      expect((service as any).findings.find((f: UnifiedFinding) => f.id === 'finding-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error when finding not found', async () => {
      // Act & Assert
      await expect(
        service.deleteFinding('non-existent-id')
      ).rejects.toThrow('Finding not found');
    });
  });

  describe('getStatistics', () => {
    beforeEach(() => {
      (service as any).findings = [
        { ...mockFinding, severity: 'high', status: 'open' },
        { ...mockFinding, id: 'finding-2', severity: 'critical', status: 'open' },
        { ...mockFinding, id: 'finding-3', severity: 'medium', status: 'resolved' },
      ];
    });

    it('should return statistics for all findings', async () => {
      // Act
      const result = await service.getStatistics();

      // Assert
      expect(result).toBeDefined();
      expect(result.total).toBe(3);
      expect(result.bySeverity).toBeDefined();
      expect(result.byStatus).toBeDefined();
    });

    it('should calculate severity distribution', async () => {
      // Act
      const result = await service.getStatistics();

      // Assert
      expect(result.bySeverity.high).toBeGreaterThanOrEqual(1);
      expect(result.bySeverity.critical).toBeGreaterThanOrEqual(1);
    });

    it('should calculate status distribution', async () => {
      // Act
      const result = await service.getStatistics();

      // Assert
      expect(result.byStatus.open).toBeGreaterThanOrEqual(2);
      expect(result.byStatus.resolved).toBeGreaterThanOrEqual(1);
    });
  });
});
