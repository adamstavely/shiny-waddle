/**
 * Exceptions Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ExceptionsService, Exception } from './exceptions.service';
import { CreateExceptionDto } from './dto/create-exception.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ExceptionsService', () => {
  let service: ExceptionsService;

  const mockException: Exception = {
    id: 'exception-1',
    name: 'Test Exception',
    description: 'Test exception description',
    policyId: 'policy-1',
    ruleId: 'rule-1',
    reason: 'Business justification',
    status: 'pending',
    requestedBy: 'user-1',
    requestedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const createDto: CreateExceptionDto = {
    name: 'New Exception',
    description: 'New exception description',
    policyId: 'policy-1',
    ruleId: 'rule-1',
    reason: 'Business justification',
    requestedBy: 'user-1',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [ExceptionsService],
    }).compile();

    service = module.get<ExceptionsService>(ExceptionsService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear exceptions
    (service as any).exceptions = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('createException', () => {
    it('should successfully create an exception', async () => {
      // Arrange
      (service as any).exceptions = [];

      // Act
      const result = await service.createException(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.description).toBe(createDto.description);
      expect(result.policyId).toBe(createDto.policyId);
      expect(result.ruleId).toBe(createDto.ruleId);
      expect(result.reason).toBe(createDto.reason);
      expect(result.status).toBe('pending');
      expect(result.requestedBy).toBe(createDto.requestedBy);
      expect(result.requestedAt).toBeInstanceOf(Date);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should set status to pending by default', async () => {
      // Arrange
      (service as any).exceptions = [];

      // Act
      const result = await service.createException(createDto);

      // Assert
      expect(result.status).toBe('pending');
    });
  });

  describe('getExceptions', () => {
    beforeEach(() => {
      (service as any).exceptions = [
        { ...mockException, id: 'exception-1', policyId: 'policy-1', status: 'pending' },
        { ...mockException, id: 'exception-2', policyId: 'policy-1', status: 'approved' },
        { ...mockException, id: 'exception-3', policyId: 'policy-2', status: 'pending' },
      ];
    });

    it('should return all exceptions when no filters provided', async () => {
      // Act
      const result = await service.getExceptions();

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by policyId', async () => {
      // Act
      const result = await service.getExceptions('policy-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(e => e.policyId === 'policy-1')).toBe(true);
    });

    it('should filter by status', async () => {
      // Act
      const result = await service.getExceptions(undefined, 'pending');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(e => e.status === 'pending')).toBe(true);
    });

    it('should filter by both policyId and status', async () => {
      // Act
      const result = await service.getExceptions('policy-1', 'approved');

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].policyId).toBe('policy-1');
      expect(result[0].status).toBe('approved');
    });
  });

  describe('updateException', () => {
    beforeEach(() => {
      (service as any).exceptions = [{ ...mockException }];
    });

    it('should successfully update an exception', async () => {
      // Arrange
      const updateDto = {
        name: 'Updated Exception',
        description: 'Updated description',
      };

      // Act
      const result = await service.updateException(mockException.id, updateDto);

      // Assert
      expect(result.name).toBe(updateDto.name);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when exception not found', async () => {
      // Arrange
      (service as any).exceptions = [];

      // Act & Assert
      await expect(
        service.updateException('non-existent-id', { name: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteException', () => {
    beforeEach(() => {
      (service as any).exceptions = [{ ...mockException }];
    });

    it('should successfully delete an exception', async () => {
      // Act
      await service.deleteException(mockException.id);

      // Assert
      expect((service as any).exceptions.find((e: Exception) => e.id === mockException.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when exception not found', async () => {
      // Arrange
      (service as any).exceptions = [];

      // Act & Assert
      await expect(
        service.deleteException('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('approveException', () => {
    beforeEach(() => {
      (service as any).exceptions = [{ ...mockException, status: 'pending' }];
    });

    it('should successfully approve an exception', async () => {
      // Act
      const result = await service.approveException(mockException.id, 'approver-1', 'Approved notes');

      // Assert
      expect(result.status).toBe('approved');
      expect(result.approvedBy).toBe('approver-1');
      expect(result.approvedAt).toBeInstanceOf(Date);
      expect(result.notes).toBe('Approved notes');
    });

    it('should throw NotFoundException when exception not found', async () => {
      // Arrange
      (service as any).exceptions = [];

      // Act & Assert
      await expect(
        service.approveException('non-existent-id', 'approver-1')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('approveException - edge cases', () => {
    beforeEach(() => {
      (service as any).exceptions = [{ ...mockException, status: 'pending', notes: 'Original notes' }];
    });

    it('should preserve existing notes when notes not provided', async () => {
      // Act
      const result = await service.approveException(mockException.id, 'approver-1');

      // Assert
      expect(result.notes).toBe('Original notes');
    });
  });
});
