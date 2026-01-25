/**
 * Finding Approvals Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, HttpException } from '@nestjs/common';
import { FindingApprovalsController } from './finding-approvals.controller';
import { FindingApprovalsService } from './finding-approvals.service';
import {
  CreateApprovalRequestDto,
  ApproveRequestDto,
  RejectRequestDto,
} from './entities/finding-approval.entity';

describe('FindingApprovalsController', () => {
  let controller: FindingApprovalsController;
  let approvalsService: jest.Mocked<FindingApprovalsService>;

  const mockUser: any = {
    id: 'user-1',
    userId: 'user-1',
    email: 'test@example.com',
    roles: ['cyber-risk-manager'],
  };

  const mockApprovalRequest = {
    id: 'request-1',
    findingId: 'finding-1',
    requestedBy: 'user-1',
    status: 'pending',
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockApprovalsService = {
      createRequest: jest.fn(),
      getPendingApprovals: jest.fn(),
      getRequestByFindingId: jest.fn(),
      getRequestsByUser: jest.fn(),
      getRequestById: jest.fn(),
      approveRequest: jest.fn(),
      rejectRequest: jest.fn(),
      cancelRequest: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [FindingApprovalsController],
      providers: [
        {
          provide: FindingApprovalsService,
          useValue: mockApprovalsService,
        },
      ],
    }).compile();

    controller = module.get<FindingApprovalsController>(FindingApprovalsController);
    approvalsService = module.get(FindingApprovalsService) as jest.Mocked<FindingApprovalsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createRequest', () => {
    const dto: CreateApprovalRequestDto = {
      findingId: 'finding-1',
      type: 'risk-acceptance',
      reason: 'Business justification',
      requestedBy: 'user-1',
    };

    it('should create an approval request', async () => {
      // Arrange
      approvalsService.createRequest.mockResolvedValue(mockApprovalRequest as any);

      // Act
      const result = await controller.createRequest(mockUser, dto);

      // Assert
      expect(result).toEqual(mockApprovalRequest);
      expect(approvalsService.createRequest).toHaveBeenCalledWith({ ...dto, requestedBy: 'user-1' });
    });
  });

  describe('getPendingApprovals', () => {
    it('should get pending approvals with detected role', async () => {
      // Arrange
      approvalsService.getPendingApprovals.mockResolvedValue([mockApprovalRequest] as any);

      // Act
      const result = await controller.getPendingApprovals(mockUser);

      // Assert
      expect(result).toEqual([mockApprovalRequest]);
      expect(approvalsService.getPendingApprovals).toHaveBeenCalledWith('cyber-risk-manager', 'user-1');
    });

    it('should get pending approvals with explicit role', async () => {
      // Arrange
      approvalsService.getPendingApprovals.mockResolvedValue([mockApprovalRequest] as any);

      // Act
      const result = await controller.getPendingApprovals(mockUser, 'data-steward');

      // Assert
      expect(result).toEqual([mockApprovalRequest]);
      expect(approvalsService.getPendingApprovals).toHaveBeenCalledWith('data-steward', 'user-1');
    });

    it('should throw HttpException when user has no approver role', async () => {
      // Arrange
      const userWithoutRole = { ...mockUser, roles: [] };

      // Act & Assert
      await expect(controller.getPendingApprovals(userWithoutRole)).rejects.toThrow(HttpException);
    });
  });

  describe('getRequestByFinding', () => {
    it('should get request by finding id', async () => {
      // Arrange
      approvalsService.getRequestByFindingId.mockResolvedValue(mockApprovalRequest as any);

      // Act
      const result = await controller.getRequestByFinding('finding-1');

      // Assert
      expect(result).toEqual(mockApprovalRequest);
      expect(approvalsService.getRequestByFindingId).toHaveBeenCalledWith('finding-1');
    });
  });

  describe('getRequestsByUser', () => {
    it('should get requests by user', async () => {
      // Arrange
      approvalsService.getRequestsByUser.mockResolvedValue([mockApprovalRequest] as any);

      // Act
      const result = await controller.getRequestsByUser(mockUser);

      // Assert
      expect(result).toEqual([mockApprovalRequest]);
      expect(approvalsService.getRequestsByUser).toHaveBeenCalledWith('user-1');
    });
  });

  describe('getRequest', () => {
    it('should get request by id', async () => {
      // Arrange
      approvalsService.getRequestById.mockResolvedValue(mockApprovalRequest as any);

      // Act
      const result = await controller.getRequest('request-1');

      // Assert
      expect(result).toEqual(mockApprovalRequest);
      expect(approvalsService.getRequestById).toHaveBeenCalledWith('request-1');
    });
  });

  describe('approveRequest', () => {
    const dto: ApproveRequestDto = {
      approverId: 'user-1',
      approverRole: 'cyber-risk-manager',
      comment: 'Approved',
    };

    it('should approve request with detected role', async () => {
      // Arrange
      const approved = { ...mockApprovalRequest, status: 'approved' };
      approvalsService.approveRequest.mockResolvedValue(approved as any);

      // Act
      const result = await controller.approveRequest('request-1', mockUser, dto);

      // Assert
      expect(result).toEqual(approved);
      expect(approvalsService.approveRequest).toHaveBeenCalledWith('request-1', {
        ...dto,
        approverRole: 'cyber-risk-manager',
        approverId: 'user-1',
      });
    });

    it('should throw HttpException when user has no approver role', async () => {
      // Arrange
      const userWithoutRole = { ...mockUser, roles: [] };
      const dtoWithoutRole: ApproveRequestDto = {
        approverId: 'user-1',
        approverRole: undefined as any,
      };

      // Act & Assert
      await expect(controller.approveRequest('request-1', userWithoutRole, dtoWithoutRole)).rejects.toThrow(HttpException);
    });
  });

  describe('rejectRequest', () => {
    const dto: RejectRequestDto = {
      approverId: 'user-1',
      approverRole: 'cyber-risk-manager',
      comment: 'Not acceptable',
    };

    it('should reject request with detected role', async () => {
      // Arrange
      const rejected = { ...mockApprovalRequest, status: 'rejected' };
      approvalsService.rejectRequest.mockResolvedValue(rejected as any);

      // Act
      const result = await controller.rejectRequest('request-1', mockUser, dto);

      // Assert
      expect(result).toEqual(rejected);
      expect(approvalsService.rejectRequest).toHaveBeenCalledWith('request-1', {
        ...dto,
        approverRole: 'cyber-risk-manager',
        approverId: 'user-1',
      });
    });

    it('should throw HttpException when user has no approver role', async () => {
      // Arrange
      const userWithoutRole = { ...mockUser, roles: [] };
      const dtoWithoutRole: RejectRequestDto = {
        approverId: 'user-1',
        approverRole: undefined as any,
        comment: 'Not acceptable',
      };

      // Act & Assert
      await expect(controller.rejectRequest('request-1', userWithoutRole, dtoWithoutRole)).rejects.toThrow(HttpException);
    });
  });

  describe('cancelRequest', () => {
    it('should cancel request', async () => {
      // Arrange
      const cancelled = { ...mockApprovalRequest, status: 'cancelled' };
      approvalsService.cancelRequest.mockResolvedValue(cancelled as any);

      // Act
      const result = await controller.cancelRequest('request-1', mockUser);

      // Assert
      expect(result).toEqual(cancelled);
      expect(approvalsService.cancelRequest).toHaveBeenCalledWith('request-1', 'user-1');
    });
  });
});
