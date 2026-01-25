/**
 * Compliance Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ComplianceService } from './compliance.service';
import { ViolationsService } from '../violations/violations.service';
import {
  ComplianceFramework,
  ControlStatus,
  ComplianceMapping,
  ComplianceAssessment,
  CreateComplianceMappingDto,
  CreateComplianceAssessmentDto,
} from './entities/compliance.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ComplianceService', () => {
  let service: ComplianceService;
  let violationsService: jest.Mocked<ViolationsService>;

  const mockMapping: ComplianceMapping = {
    id: 'mapping-1',
    framework: ComplianceFramework.NIST_800_53_REV_5,
    controlId: 'AC-1',
    status: ControlStatus.COMPLIANT,
    evidence: [],
    violations: [],
    policies: [],
    tests: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockViolationsService = {
      findAll: jest.fn(),
      findOne: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ComplianceService,
        {
          provide: ViolationsService,
          useValue: mockViolationsService,
        },
      ],
    }).compile();

    service = module.get<ComplianceService>(ComplianceService);
    violationsService = module.get(ViolationsService) as jest.Mocked<ViolationsService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear cached data
    (service as any).mappings = [];
    (service as any).assessments = [];
    (service as any).roadmaps = [];
  });

  describe('getAvailableFrameworks', () => {
    it('should return available frameworks', () => {
      // Act
      const result = service.getAvailableFrameworks();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('getControls', () => {
    it('should return controls for a framework', () => {
      // Act
      const result = service.getControls(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('getControl', () => {
    it('should return control when found', () => {
      // Act
      const result = service.getControl(ComplianceFramework.NIST_800_53_REV_5, 'AC-1');

      // Assert
      expect(result).toBeDefined();
    });

    it('should return null when control not found', () => {
      // Act
      const result = service.getControl(ComplianceFramework.NIST_800_53_REV_5, 'NON-EXISTENT');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('createMapping', () => {
    const createDto: CreateComplianceMappingDto = {
      framework: ComplianceFramework.NIST_800_53_REV_5,
      controlId: 'AC-1',
      status: ControlStatus.COMPLIANT,
      violations: [],
      policies: [],
      tests: [],
    };

    it('should successfully create a mapping', async () => {
      // Arrange
      jest.spyOn(service, 'getControl').mockReturnValue({
        id: 'control-1',
        framework: ComplianceFramework.NIST_800_53_REV_5,
        controlId: 'AC-1',
        title: 'Access Control Policy',
        description: 'Test control',
        priority: 'high' as any,
      });

      // Act
      const result = await service.createMapping(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.framework).toBe(createDto.framework);
      expect(result.controlId).toBe(createDto.controlId);
      expect(result.status).toBe(createDto.status);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when control does not exist', async () => {
      // Arrange
      jest.spyOn(service, 'getControl').mockReturnValue(null);

      // Act & Assert
      await expect(
        service.createMapping(createDto)
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('findAllMappings', () => {
    it('should return all mappings when no framework filter', async () => {
      // Arrange
      (service as any).mappings = [mockMapping];

      // Act
      const result = await service.findAllMappings();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should filter mappings by framework', async () => {
      // Arrange
      const otherMapping = { ...mockMapping, id: 'mapping-2', framework: ComplianceFramework.SOC_2 };
      (service as any).mappings = [mockMapping, otherMapping];

      // Act
      const result = await service.findAllMappings(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result.every(m => m.framework === ComplianceFramework.NIST_800_53_REV_5)).toBe(true);
    });
  });

  describe('findOneMapping', () => {
    it('should return mapping when found', async () => {
      // Arrange
      (service as any).mappings = [mockMapping];

      // Act
      const result = await service.findOneMapping(mockMapping.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockMapping.id);
    });

    it('should throw NotFoundException when mapping not found', async () => {
      // Arrange
      (service as any).mappings = [];

      // Act & Assert
      await expect(
        service.findOneMapping('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateMapping', () => {
    it('should successfully update a mapping', async () => {
      // Arrange
      (service as any).mappings = [{ ...mockMapping }];

      const updates = {
        status: ControlStatus.NON_COMPLIANT,
        notes: 'Updated notes',
      };

      // Act
      const result = await service.updateMapping(mockMapping.id, updates);

      // Assert
      expect(result.status).toBe(updates.status);
      expect(result.notes).toBe(updates.notes);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when mapping not found', async () => {
      // Arrange
      (service as any).mappings = [];

      // Act & Assert
      await expect(
        service.updateMapping('non-existent-id', {})
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('addEvidence', () => {
    it('should successfully add evidence to a mapping', async () => {
      // Arrange
      (service as any).mappings = [{ ...mockMapping }];

      const evidence = {
        type: 'policy' as const,
        title: 'Access Control Policy',
        description: 'Policy document',
        reference: 'policy-123',
        collectedBy: 'user-1',
      };

      // Act
      const result = await service.addEvidence(mockMapping.id, evidence);

      // Assert
      expect(result.evidence.length).toBe(1);
      expect(result.evidence[0].title).toBe(evidence.title);
      expect(result.evidence[0].id).toBeDefined();
      expect(result.evidence[0].collectedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when mapping not found', async () => {
      // Arrange
      (service as any).mappings = [];

      // Act & Assert
      await expect(
        service.addEvidence('non-existent-id', {
          type: 'policy',
          title: 'Test',
          reference: 'ref',
          collectedBy: 'user',
        })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('createAssessment', () => {
    const createDto: CreateComplianceAssessmentDto = {
      framework: ComplianceFramework.NIST_800_53_REV_5,
      name: 'Q1 2026 Assessment',
      description: 'Quarterly compliance assessment',
      mappings: [{
        framework: ComplianceFramework.NIST_800_53_REV_5,
        controlId: 'AC-1',
        status: ControlStatus.COMPLIANT,
        evidence: [],
        violations: [],
        policies: [],
        tests: [],
      }],
    };

    it('should successfully create an assessment', async () => {
      // Act
      const result = await service.createAssessment(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.framework).toBe(createDto.framework);
      expect(result.name).toBe(createDto.name);
      expect(result.mappings).toHaveLength(createDto.mappings.length);
      expect(result.summary).toBeDefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should calculate summary correctly', async () => {
      // Act
      const result = await service.createAssessment(createDto);

      // Assert
      expect(result.summary.totalControls).toBe(createDto.mappings.length);
      expect(result.summary.compliancePercentage).toBeGreaterThanOrEqual(0);
      expect(result.summary.compliancePercentage).toBeLessThanOrEqual(100);
    });
  });

  describe('findAllAssessments', () => {
    it('should return all assessments', async () => {
      // Arrange
      const mockAssessment: ComplianceAssessment = {
        id: 'assessment-1',
        framework: ComplianceFramework.NIST_800_53_REV_5,
        name: 'Test Assessment',
        mappings: [],
        summary: {
          totalControls: 0,
          compliant: 0,
          nonCompliant: 0,
          partiallyCompliant: 0,
          notApplicable: 0,
          notAssessed: 0,
          compliancePercentage: 0,
          criticalGaps: [],
          highPriorityGaps: [],
        },
        assessedAt: new Date(),
        assessedBy: 'user-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      (service as any).assessments = [mockAssessment];

      // Act
      const result = await service.findAllAssessments();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });

    it('should filter assessments by framework', async () => {
      // Arrange
      const assessment1 = {
        id: 'assessment-1',
        framework: ComplianceFramework.NIST_800_53_REV_5,
        name: 'NIST Assessment',
        mappings: [],
        summary: {
          totalControls: 0,
          compliant: 0,
          nonCompliant: 0,
          partiallyCompliant: 0,
          notApplicable: 0,
          notAssessed: 0,
          compliancePercentage: 0,
          criticalGaps: [],
          highPriorityGaps: [],
        },
        assessedAt: new Date(),
        assessedBy: 'user-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      const assessment2 = {
        ...assessment1,
        id: 'assessment-2',
        framework: ComplianceFramework.SOC_2,
        name: 'SOC 2 Assessment',
      };
      (service as any).assessments = [assessment1, assessment2];

      // Act
      const result = await service.findAllAssessments(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result.every(a => a.framework === ComplianceFramework.NIST_800_53_REV_5)).toBe(true);
    });
  });

  describe('findOneAssessment', () => {
    it('should return assessment when found', async () => {
      // Arrange
      const mockAssessment: ComplianceAssessment = {
        id: 'assessment-1',
        framework: ComplianceFramework.NIST_800_53_REV_5,
        name: 'Test Assessment',
        mappings: [],
        summary: {
          totalControls: 0,
          compliant: 0,
          nonCompliant: 0,
          partiallyCompliant: 0,
          notApplicable: 0,
          notAssessed: 0,
          compliancePercentage: 0,
          criticalGaps: [],
          highPriorityGaps: [],
        },
        assessedAt: new Date(),
        assessedBy: 'user-1',
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      (service as any).assessments = [mockAssessment];

      // Act
      const result = await service.findOneAssessment(mockAssessment.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockAssessment.id);
    });

    it('should throw NotFoundException when assessment not found', async () => {
      // Arrange
      (service as any).assessments = [];

      // Act & Assert
      await expect(
        service.findOneAssessment('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
