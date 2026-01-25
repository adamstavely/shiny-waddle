/**
 * Compliance Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './compliance.service';
import {
  ComplianceFramework,
  ComplianceControl,
  ComplianceMapping,
  ComplianceAssessment,
  ComplianceGap,
  ComplianceRoadmap,
  ComplianceFramework as FrameworkEnum,
  CreateComplianceMappingDto,
  CreateComplianceAssessmentDto,
} from './entities/compliance.entity';

describe('ComplianceController', () => {
  let controller: ComplianceController;
  let complianceService: jest.Mocked<ComplianceService>;

  const mockControl: ComplianceControl = {
    id: 'control-1',
    framework: ComplianceFramework.NIST_800_53_REV_5,
    controlId: 'AC-1',
    title: 'Access Control Policy',
    description: 'Test control description',
    priority: 'high' as any,
  };

  const mockMapping: ComplianceMapping = {
    id: 'mapping-1',
    framework: ComplianceFramework.NIST_800_53_REV_5,
    controlId: 'AC-1',
    status: 'compliant' as any,
    evidence: [],
    violations: [],
    policies: [],
    tests: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockAssessment: ComplianceAssessment = {
    id: 'assessment-1',
    framework: ComplianceFramework.NIST_800_53_REV_5,
    name: 'Test Assessment',
    assessedAt: new Date(),
    assessedBy: 'user-1',
    mappings: [mockMapping],
    summary: {
      totalControls: 100,
      compliant: 80,
      nonCompliant: 10,
      partiallyCompliant: 5,
      notApplicable: 3,
      notAssessed: 2,
      compliancePercentage: 80,
      criticalGaps: [],
      highPriorityGaps: [],
    },
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockGap: ComplianceGap = {
    controlId: 'AC-1',
    controlTitle: 'Access Control Policy',
    status: 'non_compliant' as any,
    priority: 'high' as any,
    violations: [],
    remediationSteps: ['Step 1', 'Step 2'],
  };

  const mockRoadmap: ComplianceRoadmap = {
    id: 'roadmap-1',
    framework: ComplianceFramework.NIST_800_53_REV_5,
    name: 'Test Roadmap',
    gaps: [mockGap],
    milestones: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockComplianceService = {
      getAvailableFrameworks: jest.fn(),
      getFrameworkMetadata: jest.fn(),
      getControls: jest.fn(),
      getControl: jest.fn(),
      createMapping: jest.fn(),
      findAllMappings: jest.fn(),
      findOneMapping: jest.fn(),
      updateMapping: jest.fn(),
      addEvidence: jest.fn(),
      createAssessment: jest.fn(),
      findAllAssessments: jest.fn(),
      findOneAssessment: jest.fn(),
      getCurrentAssessment: jest.fn(),
      performGapAnalysis: jest.fn(),
      createRoadmap: jest.fn(),
      findAllRoadmaps: jest.fn(),
      findOneRoadmap: jest.fn(),
      updateRoadmap: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ComplianceController],
      providers: [
        {
          provide: ComplianceService,
          useValue: mockComplianceService,
        },
      ],
    }).compile();

    controller = module.get<ComplianceController>(ComplianceController);
    complianceService = module.get(ComplianceService) as jest.Mocked<ComplianceService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAvailableFrameworks', () => {
    it('should return available frameworks', () => {
      // Arrange
      const frameworks = [ComplianceFramework.NIST_800_53_REV_5, ComplianceFramework.SOC_2];
      complianceService.getAvailableFrameworks.mockReturnValue(frameworks as any);

      // Act
      const result = controller.getAvailableFrameworks();

      // Assert
      expect(result).toEqual(frameworks);
      expect(complianceService.getAvailableFrameworks).toHaveBeenCalledTimes(1);
    });
  });

  describe('getFrameworkMetadata', () => {
    const mockMetadata = {
      name: 'NIST 800-53 Rev 5',
      version: '5.0',
      description: 'Test framework',
    };

    it('should return framework metadata', () => {
      // Arrange
      complianceService.getFrameworkMetadata.mockReturnValue(mockMetadata as any);

      // Act
      const result = controller.getFrameworkMetadata(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual(mockMetadata);
      expect(complianceService.getFrameworkMetadata).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('getControls', () => {
    it('should return controls for a framework', () => {
      // Arrange
      complianceService.getControls.mockReturnValue([mockControl]);

      // Act
      const result = controller.getControls(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual([mockControl]);
      expect(complianceService.getControls).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('getControl', () => {
    it('should return a specific control', () => {
      // Arrange
      complianceService.getControl.mockReturnValue(mockControl);

      // Act
      const result = controller.getControl(ComplianceFramework.NIST_800_53_REV_5, 'AC-1');

      // Assert
      expect(result).toEqual(mockControl);
      expect(complianceService.getControl).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5, 'AC-1');
    });

    it('should return null when control not found', () => {
      // Arrange
      complianceService.getControl.mockReturnValue(null);

      // Act
      const result = controller.getControl(ComplianceFramework.NIST_800_53_REV_5, 'NON-EXISTENT');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('createMapping', () => {
    const createDto: CreateComplianceMappingDto = {
      framework: ComplianceFramework.NIST_800_53_REV_5,
      controlId: 'AC-1',
      status: 'compliant' as any,
    };

    it('should create a compliance mapping', async () => {
      // Arrange
      complianceService.createMapping.mockResolvedValue(mockMapping);

      // Act
      const result = await controller.createMapping(createDto);

      // Assert
      expect(result).toEqual(mockMapping);
      expect(complianceService.createMapping).toHaveBeenCalledWith(createDto);
    });
  });

  describe('findAllMappings', () => {
    it('should return all mappings when no filter', async () => {
      // Arrange
      complianceService.findAllMappings.mockResolvedValue([mockMapping]);

      // Act
      const result = await controller.findAllMappings();

      // Assert
      expect(result).toEqual([mockMapping]);
      expect(complianceService.findAllMappings).toHaveBeenCalledWith(undefined);
    });

    it('should filter mappings by framework', async () => {
      // Arrange
      complianceService.findAllMappings.mockResolvedValue([mockMapping]);

      // Act
      const result = await controller.findAllMappings(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual([mockMapping]);
      expect(complianceService.findAllMappings).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('findOneMapping', () => {
    it('should return a mapping by id', async () => {
      // Arrange
      complianceService.findOneMapping.mockResolvedValue(mockMapping);

      // Act
      const result = await controller.findOneMapping('mapping-1');

      // Assert
      expect(result).toEqual(mockMapping);
      expect(complianceService.findOneMapping).toHaveBeenCalledWith('mapping-1');
    });
  });

  describe('updateMapping', () => {
    const updates = { status: 'non_compliant' as any };

    it('should update a mapping', async () => {
      // Arrange
      const updatedMapping = { ...mockMapping, ...updates };
      complianceService.updateMapping.mockResolvedValue(updatedMapping);

      // Act
      const result = await controller.updateMapping('mapping-1', updates);

      // Assert
      expect(result).toEqual(updatedMapping);
      expect(complianceService.updateMapping).toHaveBeenCalledWith('mapping-1', updates);
    });
  });

  describe('addEvidence', () => {
    const evidence = {
      type: 'policy' as any,
      title: 'Test Evidence',
      reference: 'policy-1',
    };

    it('should add evidence to a mapping', async () => {
      // Arrange
      const updatedMapping = {
        ...mockMapping,
        evidence: [evidence as any],
      };
      complianceService.addEvidence.mockResolvedValue(updatedMapping);

      // Act
      const result = await controller.addEvidence('mapping-1', evidence);

      // Assert
      expect(result).toEqual(updatedMapping);
      expect(complianceService.addEvidence).toHaveBeenCalledWith('mapping-1', evidence);
    });
  });

  describe('createAssessment', () => {
    const createDto: CreateComplianceAssessmentDto = {
      framework: ComplianceFramework.NIST_800_53_REV_5,
      name: 'New Assessment',
      mappings: [],
    };

    it('should create an assessment', async () => {
      // Arrange
      complianceService.createAssessment.mockResolvedValue(mockAssessment);

      // Act
      const result = await controller.createAssessment(createDto);

      // Assert
      expect(result).toEqual(mockAssessment);
      expect(complianceService.createAssessment).toHaveBeenCalledWith(createDto);
    });
  });

  describe('findAllAssessments', () => {
    it('should return all assessments when no filter', async () => {
      // Arrange
      complianceService.findAllAssessments.mockResolvedValue([mockAssessment]);

      // Act
      const result = await controller.findAllAssessments();

      // Assert
      expect(result).toEqual([mockAssessment]);
      expect(complianceService.findAllAssessments).toHaveBeenCalledWith(undefined);
    });

    it('should filter assessments by framework', async () => {
      // Arrange
      complianceService.findAllAssessments.mockResolvedValue([mockAssessment]);

      // Act
      const result = await controller.findAllAssessments(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual([mockAssessment]);
      expect(complianceService.findAllAssessments).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('findOneAssessment', () => {
    it('should return an assessment by id', async () => {
      // Arrange
      complianceService.findOneAssessment.mockResolvedValue(mockAssessment);

      // Act
      const result = await controller.findOneAssessment('assessment-1');

      // Assert
      expect(result).toEqual(mockAssessment);
      expect(complianceService.findOneAssessment).toHaveBeenCalledWith('assessment-1');
    });
  });

  describe('getCurrentAssessment', () => {
    it('should return current assessment for framework', async () => {
      // Arrange
      complianceService.getCurrentAssessment.mockResolvedValue(mockAssessment);

      // Act
      const result = await controller.getCurrentAssessment(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual(mockAssessment);
      expect(complianceService.getCurrentAssessment).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });

    it('should return null when no current assessment', async () => {
      // Arrange
      complianceService.getCurrentAssessment.mockResolvedValue(null);

      // Act
      const result = await controller.getCurrentAssessment(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('performGapAnalysis', () => {
    it('should perform gap analysis for a framework', async () => {
      // Arrange
      complianceService.performGapAnalysis.mockResolvedValue([mockGap]);

      // Act
      const result = await controller.performGapAnalysis(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual([mockGap]);
      expect(complianceService.performGapAnalysis).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('createRoadmap', () => {
    const roadmapBody = {
      name: 'New Roadmap',
      description: 'Test roadmap',
      targetDate: new Date(),
    };

    it('should create a roadmap', async () => {
      // Arrange
      complianceService.createRoadmap.mockResolvedValue(mockRoadmap);

      // Act
      const result = await controller.createRoadmap(ComplianceFramework.NIST_800_53_REV_5, roadmapBody);

      // Assert
      expect(result).toEqual(mockRoadmap);
      expect(complianceService.createRoadmap).toHaveBeenCalledWith(
        ComplianceFramework.NIST_800_53_REV_5,
        roadmapBody.name,
        roadmapBody.description,
        roadmapBody.targetDate
      );
    });
  });

  describe('findAllRoadmaps', () => {
    it('should return all roadmaps when no filter', async () => {
      // Arrange
      complianceService.findAllRoadmaps.mockResolvedValue([mockRoadmap]);

      // Act
      const result = await controller.findAllRoadmaps();

      // Assert
      expect(result).toEqual([mockRoadmap]);
      expect(complianceService.findAllRoadmaps).toHaveBeenCalledWith(undefined);
    });

    it('should filter roadmaps by framework', async () => {
      // Arrange
      complianceService.findAllRoadmaps.mockResolvedValue([mockRoadmap]);

      // Act
      const result = await controller.findAllRoadmaps(ComplianceFramework.NIST_800_53_REV_5);

      // Assert
      expect(result).toEqual([mockRoadmap]);
      expect(complianceService.findAllRoadmaps).toHaveBeenCalledWith(ComplianceFramework.NIST_800_53_REV_5);
    });
  });

  describe('findOneRoadmap', () => {
    it('should return a roadmap by id', async () => {
      // Arrange
      complianceService.findOneRoadmap.mockResolvedValue(mockRoadmap);

      // Act
      const result = await controller.findOneRoadmap('roadmap-1');

      // Assert
      expect(result).toEqual(mockRoadmap);
      expect(complianceService.findOneRoadmap).toHaveBeenCalledWith('roadmap-1');
    });
  });

  describe('updateRoadmap', () => {
    const updates = { name: 'Updated Roadmap' };

    it('should update a roadmap', async () => {
      // Arrange
      const updatedRoadmap = { ...mockRoadmap, ...updates };
      complianceService.updateRoadmap.mockResolvedValue(updatedRoadmap);

      // Act
      const result = await controller.updateRoadmap('roadmap-1', updates);

      // Assert
      expect(result).toEqual(updatedRoadmap);
      expect(complianceService.updateRoadmap).toHaveBeenCalledWith('roadmap-1', updates);
    });
  });
});
