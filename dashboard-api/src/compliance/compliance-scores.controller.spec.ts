/**
 * Compliance Scores Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ComplianceScoresController } from './compliance-scores.controller';
import { ComplianceScoresService } from './compliance-scores.service';

describe('ComplianceScoresController', () => {
  let controller: ComplianceScoresController;
  let service: jest.Mocked<ComplianceScoresService>;

  const mockHistory = [
    { date: '2024-01-01', score: 85 },
    { date: '2024-01-02', score: 87 },
    { date: '2024-01-03', score: 90 },
  ];

  beforeEach(async () => {
    const mockService = {
      getHistory: jest.fn().mockResolvedValue(mockHistory),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ComplianceScoresController],
      providers: [
        {
          provide: ComplianceScoresService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<ComplianceScoresController>(ComplianceScoresController);
    service = module.get(ComplianceScoresService) as jest.Mocked<ComplianceScoresService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getHistory', () => {
    it('should call service.getHistory with no filters when no query params', async () => {
      // Act
      await controller.getHistory();

      // Assert
      expect(service.getHistory).toHaveBeenCalledWith({});
      expect(service.getHistory).toHaveBeenCalledTimes(1);
    });

    it('should call service.getHistory with applicationId filter', async () => {
      // Act
      await controller.getHistory('app-1', undefined, undefined, undefined, undefined);

      // Assert
      expect(service.getHistory).toHaveBeenCalledWith({
        applicationId: 'app-1',
        startDate: undefined,
        endDate: undefined,
        days: undefined,
        domain: undefined,
      });
    });

    it('should parse startDate and endDate from query strings', async () => {
      // Arrange
      const startDate = '2024-01-01';
      const endDate = '2024-01-31';

      // Act
      await controller.getHistory(undefined, startDate, endDate, undefined, undefined);

      // Assert
      expect(service.getHistory).toHaveBeenCalledWith({
        applicationId: undefined,
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        days: undefined,
        domain: undefined,
      });
    });

    it('should parse days as integer', async () => {
      // Act
      await controller.getHistory(undefined, undefined, undefined, '30', undefined);

      // Assert
      expect(service.getHistory).toHaveBeenCalledWith({
        applicationId: undefined,
        startDate: undefined,
        endDate: undefined,
        days: 30,
        domain: undefined,
      });
    });

    it('should pass domain filter', async () => {
      // Act
      await controller.getHistory(undefined, undefined, undefined, undefined, 'api-security');

      // Assert
      expect(service.getHistory).toHaveBeenCalledWith({
        applicationId: undefined,
        startDate: undefined,
        endDate: undefined,
        days: undefined,
        domain: 'api-security',
      });
    });

    it('should return history array', async () => {
      // Act
      const result = await controller.getHistory();

      // Assert
      expect(result).toEqual(mockHistory);
    });
  });
});
