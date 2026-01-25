/**
 * NIST 800-207 Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { NIST800207Controller } from './nist-800-207.controller';
import { NIST800207Service } from './nist-800-207.service';

describe('NIST800207Controller', () => {
  let controller: NIST800207Controller;
  let nist800207Service: jest.Mocked<NIST800207Service>;

  const mockAssessment = {
    identity: { compliant: true, score: 100 },
    device: { compliant: true, score: 95 },
    network: { compliant: true, score: 90 },
    application: { compliant: true, score: 85 },
    data: { compliant: true, score: 90 },
    overall: { compliant: true, score: 92 },
  };

  const mockReport = {
    assessment: mockAssessment,
    recommendations: [],
    generatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockNIST800207Service = {
      assessZTAPillars: jest.fn(),
      generateComplianceReport: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NIST800207Controller],
      providers: [
        {
          provide: NIST800207Service,
          useValue: mockNIST800207Service,
        },
      ],
    }).compile();

    controller = module.get<NIST800207Controller>(NIST800207Controller);
    nist800207Service = module.get(NIST800207Service) as jest.Mocked<NIST800207Service>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('assess', () => {
    it('should assess ZTA pillars with assessment data', async () => {
      // Arrange
      const dto = {
        assessment: {
          identity: {},
          device: {},
        },
      };
      nist800207Service.assessZTAPillars.mockResolvedValue(mockAssessment as any);

      // Act
      const result = await controller.assess(dto);

      // Assert
      expect(result).toEqual(mockAssessment);
      expect(nist800207Service.assessZTAPillars).toHaveBeenCalledWith(dto.assessment);
    });

    it('should assess ZTA pillars with empty assessment', async () => {
      // Arrange
      const dto = {};
      nist800207Service.assessZTAPillars.mockResolvedValue(mockAssessment as any);

      // Act
      const result = await controller.assess(dto);

      // Assert
      expect(result).toEqual(mockAssessment);
      expect(nist800207Service.assessZTAPillars).toHaveBeenCalledWith({});
    });
  });

  describe('generateReport', () => {
    it('should generate compliance report', async () => {
      // Arrange
      const dto = {
        assessment: mockAssessment,
      };
      nist800207Service.generateComplianceReport.mockResolvedValue(mockReport as any);

      // Act
      const result = await controller.generateReport(dto);

      // Assert
      expect(result).toEqual(mockReport);
      expect(nist800207Service.generateComplianceReport).toHaveBeenCalledWith(mockAssessment);
    });
  });
});
