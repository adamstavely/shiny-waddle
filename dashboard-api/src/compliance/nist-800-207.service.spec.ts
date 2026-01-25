/**
 * NIST 800-207 Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NIST800207Service } from './nist-800-207.service';
import { NIST800207Compliance } from '../../../heimdall-framework/services/nist-800-207-compliance';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/nist-800-207-compliance');

describe('NIST800207Service', () => {
  let service: NIST800207Service;
  let mockCompliance: jest.Mocked<NIST800207Compliance>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockCompliance = {
      assessZTAPillars: jest.fn(),
      generateComplianceReport: jest.fn(),
      getZTARecommendations: jest.fn(),
    } as any;

    // Mock the constructor
    (NIST800207Compliance as jest.Mock).mockImplementation(() => mockCompliance);

    const module: TestingModule = await Test.createTestingModule({
      providers: [NIST800207Service],
    }).compile();

    service = module.get<NIST800207Service>(NIST800207Service);
  });

  describe('assessZTAPillars', () => {
    it('should successfully assess ZTA pillars', async () => {
      const mockAssessment = {
        framework: 'NIST-800-207' as const,
        assessment: {
          id: 'assessment-1',
          timestamp: new Date(),
          pillars: [],
          overallScore: 85,
          gaps: [],
          recommendations: [],
        },
        compliancePercentage: 85,
        compliant: true,
      };

      mockCompliance.assessZTAPillars.mockResolvedValue(mockAssessment);

      const result = await service.assessZTAPillars({});

      expect(result).toEqual(mockAssessment);
    });

    it('should accept optional assessment parameter', async () => {
      const mockAssessment = {
        framework: 'NIST-800-207' as const,
        assessment: {
          id: 'assessment-1',
          timestamp: new Date(),
          pillars: [],
          overallScore: 85,
          gaps: [],
          recommendations: [],
        },
        compliancePercentage: 85,
        compliant: true,
      };

      mockCompliance.assessZTAPillars.mockResolvedValue(mockAssessment);

      const result = await service.assessZTAPillars();

      expect(result).toEqual(mockAssessment);
    });

    it('should throw ValidationException for non-object assessment', async () => {
      await expect(service.assessZTAPillars('invalid' as any)).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw InternalServerException on service error', async () => {
      mockCompliance.assessZTAPillars.mockRejectedValue(new Error('Service error'));

      await expect(service.assessZTAPillars({})).rejects.toThrow(InternalServerException);
    });
  });

  describe('generateComplianceReport', () => {
    it('should successfully generate compliance report', async () => {
      const mockReport = 'Compliance Report Content';

      mockCompliance.generateComplianceReport.mockResolvedValue(mockReport);

      const result = await service.generateComplianceReport({
        framework: 'NIST-800-207',
        assessment: {
          id: 'assessment-1',
          timestamp: new Date(),
          pillars: [],
          overallScore: 85,
          gaps: [],
          recommendations: [],
        },
        compliancePercentage: 85,
        compliant: true,
      });

      expect(result).toEqual(mockReport);
    });

    it('should throw ValidationException for missing assessment', async () => {
      await expect(service.generateComplianceReport(null as any)).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing framework', async () => {
      await expect(
        service.generateComplianceReport({
          assessment: {
            id: 'assessment-1',
            timestamp: new Date(),
            pillars: [],
            overallScore: 85,
            gaps: [],
            recommendations: [],
          },
          compliancePercentage: 85,
          compliant: true,
        } as any),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing assessment data', async () => {
      await expect(
        service.generateComplianceReport({
          framework: 'NIST-800-207',
          compliancePercentage: 85,
          compliant: true,
        } as any),
      ).rejects.toThrow(ValidationException);
    });
  });
});

