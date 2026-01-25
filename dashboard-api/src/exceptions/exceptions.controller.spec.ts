/**
 * Exceptions Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { ExceptionsController } from './exceptions.controller';
import { ExceptionsService } from './exceptions.service';
import { CreateExceptionDto } from './dto/create-exception.dto';

describe('ExceptionsController', () => {
  let controller: ExceptionsController;
  let exceptionsService: jest.Mocked<ExceptionsService>;

  const mockException = {
    id: 'exception-1',
    name: 'Test Exception',
    description: 'Test description',
    policyId: 'policy-1',
    reason: 'Test reason',
    status: 'pending' as const,
    requestedBy: 'user-1',
    requestedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockExceptionsService = {
      getExceptions: jest.fn(),
      createException: jest.fn(),
      updateException: jest.fn(),
      deleteException: jest.fn(),
      approveException: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ExceptionsController],
      providers: [
        {
          provide: ExceptionsService,
          useValue: mockExceptionsService,
        },
      ],
    }).compile();

    controller = module.get<ExceptionsController>(ExceptionsController);
    exceptionsService = module.get(ExceptionsService) as jest.Mocked<ExceptionsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getExceptions', () => {
    it('should get all exceptions', async () => {
      // Arrange
      exceptionsService.getExceptions.mockResolvedValue([mockException]);

      // Act
      const result = await controller.getExceptions();

      // Assert
      expect(result).toEqual([mockException]);
      expect(exceptionsService.getExceptions).toHaveBeenCalledWith(undefined, undefined);
    });

    it('should get exceptions filtered by policyId', async () => {
      // Arrange
      exceptionsService.getExceptions.mockResolvedValue([mockException]);

      // Act
      const result = await controller.getExceptions('policy-1');

      // Assert
      expect(result).toEqual([mockException]);
      expect(exceptionsService.getExceptions).toHaveBeenCalledWith('policy-1', undefined);
    });

    it('should get exceptions filtered by status', async () => {
      // Arrange
      exceptionsService.getExceptions.mockResolvedValue([mockException]);

      // Act
      const result = await controller.getExceptions(undefined, 'pending');

      // Assert
      expect(result).toEqual([mockException]);
      expect(exceptionsService.getExceptions).toHaveBeenCalledWith(undefined, 'pending');
    });

    it('should get exceptions filtered by both policyId and status', async () => {
      // Arrange
      exceptionsService.getExceptions.mockResolvedValue([mockException]);

      // Act
      const result = await controller.getExceptions('policy-1', 'pending');

      // Assert
      expect(result).toEqual([mockException]);
      expect(exceptionsService.getExceptions).toHaveBeenCalledWith('policy-1', 'pending');
    });
  });

  describe('createException', () => {
    const dto: CreateExceptionDto = {
      name: 'Test Exception',
      policyId: 'policy-1',
      reason: 'Test reason',
      requestedBy: 'user-1',
    };

    it('should create an exception', async () => {
      // Arrange
      exceptionsService.createException.mockResolvedValue(mockException);

      // Act
      const result = await controller.createException(dto);

      // Assert
      expect(result).toEqual(mockException);
      expect(exceptionsService.createException).toHaveBeenCalledWith(dto);
    });
  });

  describe('updateException', () => {
    const updates: Partial<CreateExceptionDto> = {
      reason: 'Updated reason',
    };

    it('should update an exception', async () => {
      // Arrange
      const updatedException = { ...mockException, reason: 'Updated reason', updatedAt: new Date() };
      exceptionsService.updateException.mockResolvedValue(updatedException);

      // Act
      const result = await controller.updateException('exception-1', updates);

      // Assert
      expect(result).toEqual(updatedException);
      expect(exceptionsService.updateException).toHaveBeenCalledWith('exception-1', updates);
    });
  });

  describe('deleteException', () => {
    it('should delete an exception', async () => {
      // Arrange
      exceptionsService.deleteException.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteException('exception-1');

      // Assert
      expect(result).toEqual(undefined);
      expect(exceptionsService.deleteException).toHaveBeenCalledWith('exception-1');
    });
  });

  describe('approveException', () => {
    it('should approve an exception', async () => {
      // Arrange
      const approvedException = { ...mockException, status: 'approved' as const, approvedBy: 'approver-1', approvedAt: new Date() };
      exceptionsService.approveException.mockResolvedValue(approvedException);

      // Act
      const result = await controller.approveException('exception-1', {
        approver: 'approver-1',
        notes: 'Approved',
      });

      // Assert
      expect(result).toEqual(approvedException);
      expect(exceptionsService.approveException).toHaveBeenCalledWith('exception-1', 'approver-1', 'Approved');
    });

    it('should approve an exception without notes', async () => {
      // Arrange
      const approvedException = { ...mockException, status: 'approved' as const, approvedBy: 'approver-1', approvedAt: new Date() };
      exceptionsService.approveException.mockResolvedValue(approvedException);

      // Act
      const result = await controller.approveException('exception-1', {
        approver: 'approver-1',
      });

      // Assert
      expect(result).toEqual(approvedException);
      expect(exceptionsService.approveException).toHaveBeenCalledWith('exception-1', 'approver-1', undefined);
    });
  });
});
