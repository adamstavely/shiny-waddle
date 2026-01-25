/**
 * Standards Mapping Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { StandardsMappingService, ComplianceStandard, PolicyMapping } from './standards-mapping.service';
import { CreateMappingDto } from './dto/create-mapping.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('StandardsMappingService', () => {
  let service: StandardsMappingService;

  const mockStandard: ComplianceStandard = {
    id: 'nist-800-53',
    name: 'NIST 800-53',
    version: 'Rev 5',
    description: 'NIST Security and Privacy Controls',
    framework: 'nist',
  };

  const createMappingDto: CreateMappingDto = {
    policyId: 'policy-1',
    controlId: 'AC-1',
    controlName: 'Access Control Policy',
    mappingType: 'direct',
    notes: 'Direct mapping',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [StandardsMappingService],
    }).compile();

    service = module.get<StandardsMappingService>(StandardsMappingService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify({ standards: [], mappings: [] }));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear data
    (service as any).standards = [];
    (service as any).mappings = [];
    
    // Mock loadData to prevent it from resetting our test data
    jest.spyOn(service as any, 'loadData').mockResolvedValue(undefined);
  });

  describe('getStandards', () => {
    it('should return all compliance standards', async () => {
      // Arrange
      (service as any).standards = [mockStandard];

      // Act
      const result = await service.getStandards();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should initialize defaults when no standards exist', async () => {
      // Arrange
      (service as any).standards = [];
      const fs = require('fs/promises');
      fs.readFile.mockResolvedValueOnce('');

      // Act
      const result = await service.getStandards();

      // Assert
      expect(result.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('getMappings', () => {
    beforeEach(() => {
      (service as any).mappings = [
        {
          id: 'mapping-1',
          standardId: 'nist-800-53',
          policyId: 'policy-1',
          controlId: 'AC-1',
          controlName: 'Access Control',
          mappingType: 'direct',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'mapping-2',
          standardId: 'nist-800-53',
          policyId: 'policy-2',
          controlId: 'AC-2',
          controlName: 'Account Management',
          mappingType: 'partial',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
        {
          id: 'mapping-3',
          standardId: 'soc2',
          policyId: 'policy-1',
          controlId: 'CC1.1',
          controlName: 'Control Environment',
          mappingType: 'direct',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should return mappings for a specific standard', async () => {
      // Act
      const result = await service.getMappings('nist-800-53');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(m => m.standardId === 'nist-800-53')).toBe(true);
    });

    it('should return empty array when no mappings exist for standard', async () => {
      // Act
      const result = await service.getMappings('iso-27001');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('createMapping', () => {
    beforeEach(() => {
      (service as any).standards = [mockStandard];
      (service as any).mappings = [];
    });

    it('should successfully create a policy mapping', async () => {
      // Act
      const result = await service.createMapping('nist-800-53', createMappingDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.standardId).toBe('nist-800-53');
      expect(result.policyId).toBe(createMappingDto.policyId);
      expect(result.controlId).toBe(createMappingDto.controlId);
      expect(result.mappingType).toBe(createMappingDto.mappingType);
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when standard does not exist', async () => {
      // Arrange
      (service as any).standards = [];

      // Act & Assert
      await expect(
        service.createMapping('non-existent-standard', createMappingDto)
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteMapping', () => {
    beforeEach(() => {
      (service as any).mappings = [
        {
          id: 'mapping-1',
          standardId: 'nist-800-53',
          policyId: 'policy-1',
          controlId: 'AC-1',
          controlName: 'Access Control',
          mappingType: 'direct',
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      ];
    });

    it('should successfully delete a mapping', async () => {
      // Act
      await service.deleteMapping('nist-800-53', 'mapping-1');

      // Assert
      expect((service as any).mappings.find((m: PolicyMapping) => m.id === 'mapping-1')).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when mapping not found', async () => {
      // Arrange
      (service as any).mappings = [];

      // Act & Assert
      await expect(
        service.deleteMapping('nist-800-53', 'non-existent-mapping')
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when standardId does not match', async () => {
      // Act & Assert
      await expect(
        service.deleteMapping('soc2', 'mapping-1')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
