/**
 * Finding Approvals Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { FindingApprovalsService } from './finding-approvals.service';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { NotificationsService } from '../notifications/notifications.service';
import { UsersService } from '../users/users.service';
import { CreateApprovalRequestDto } from './entities/finding-approval.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('FindingApprovalsService', () => {
  let service: FindingApprovalsService;
  let findingsService: jest.Mocked<UnifiedFindingsService>;
  let notificationsService: jest.Mocked<NotificationsService>;
  let usersService: jest.Mocked<UsersService>;

  const mockFinding = {
    id: 'finding-1',
    title: 'Test Finding',
    severity: 'high',
    asset: { applicationId: 'app-1' },
  };

  const createDto: CreateApprovalRequestDto = {
    findingId: 'finding-1',
    type: 'risk-acceptance',
    requestedBy: 'user-1',
    reason: 'Business justification',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockFindingsService = {
      getFindingById: jest.fn().mockResolvedValue(mockFinding),
    };

    const mockNotificationsService = {
      getUserPreferences: jest.fn().mockReturnValue({
        enabled: true,
        notifyOnApprovalRequest: true,
      }),
      notifyApprovalRequest: jest.fn().mockResolvedValue(undefined),
    };

    const mockUsersService = {
      getUsersByRoles: jest.fn().mockResolvedValue([
        { id: 'approver-1', roles: ['cyber-risk-manager'] },
      ]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        FindingApprovalsService,
        {
          provide: UnifiedFindingsService,
          useValue: mockFindingsService,
        },
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    service = module.get<FindingApprovalsService>(FindingApprovalsService);
    findingsService = module.get(UnifiedFindingsService) as jest.Mocked<UnifiedFindingsService>;
    notificationsService = module.get(NotificationsService) as jest.Mocked<NotificationsService>;
    usersService = module.get(UsersService) as jest.Mocked<UsersService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear approvals
    (service as any).approvals = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
    
    // Mock constructor's loadData call
    await (service as any).loadData();
  });

  describe('createRequest', () => {
    it('should successfully create an approval request', async () => {
      // Arrange
      (service as any).approvals = [];

      // Act
      const result = await service.createRequest(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.findingId).toBe(createDto.findingId);
      expect(result.type).toBe(createDto.type);
      expect(result.status).toBe('pending');
      expect(result.requestedBy).toBe(createDto.requestedBy);
      expect(result.requestedAt).toBeInstanceOf(Date);
      expect(findingsService.getFindingById).toHaveBeenCalledWith(createDto.findingId);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when finding not found', async () => {
      // Arrange
      findingsService.getFindingById.mockResolvedValue(null);

      // Act & Assert
      await expect(
        service.createRequest(createDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for duplicate pending request', async () => {
      // Arrange
      (service as any).approvals = [
        {
          id: 'request-1',
          findingId: 'finding-1',
          status: 'pending',
        },
      ];

      // Act & Assert
      await expect(
        service.createRequest(createDto)
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('getRequestById', () => {
    beforeEach(() => {
      (service as any).approvals = [
        {
          id: 'request-1',
          findingId: 'finding-1',
          status: 'pending',
          requestedAt: new Date(),
        },
      ];
    });

    it('should return request when found', async () => {
      // Act
      const result = await service.getRequestById('request-1');

      // Assert
      expect(result.id).toBe('request-1');
    });

    it('should throw NotFoundException when request not found', async () => {
      // Act & Assert
      await expect(
        service.getRequestById('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getRequestByFindingId', () => {
    beforeEach(() => {
      (service as any).approvals = [
        {
          id: 'request-1',
          findingId: 'finding-1',
          status: 'pending',
        },
      ];
    });

    it('should return request when found', async () => {
      // Act
      const result = await service.getRequestByFindingId('finding-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('request-1');
    });

    it('should return null when request not found', async () => {
      // Act
      const result = await service.getRequestByFindingId('non-existent-finding');

      // Assert
      expect(result).toBeNull();
    });
  });
});
