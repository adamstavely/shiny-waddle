/**
 * Scheduled Reports Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import { ScheduledReportsController } from './scheduled-reports.controller';
import { ScheduledReportsService } from './scheduled-reports.service';
import { CreateScheduledReportDto } from './dto/create-scheduled-report.dto';
import { UpdateScheduledReportDto } from './dto/update-scheduled-report.dto';

describe('ScheduledReportsController', () => {
  let controller: ScheduledReportsController;
  let service: jest.Mocked<ScheduledReportsService>;

  const mockReport = {
    id: 'report-1',
    name: 'Daily Report',
    enabled: true,
    frequency: 'daily',
    format: 'html',
    deliveryMethod: 'email' as const,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockService = {
      getAllScheduledReports: jest.fn().mockResolvedValue([mockReport]),
      getScheduledReportById: jest.fn().mockResolvedValue(mockReport),
      createScheduledReport: jest.fn().mockResolvedValue(mockReport),
      updateScheduledReport: jest.fn().mockResolvedValue(mockReport),
      toggleScheduledReport: jest.fn().mockResolvedValue(mockReport),
      deleteScheduledReport: jest.fn().mockResolvedValue(undefined),
      runScheduledReportNow: jest.fn().mockResolvedValue({ id: 'execution-1' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ScheduledReportsController],
      providers: [
        {
          provide: ScheduledReportsService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<ScheduledReportsController>(ScheduledReportsController);
    service = module.get(ScheduledReportsService) as jest.Mocked<ScheduledReportsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getAllScheduledReports', () => {
    it('should call service.getAllScheduledReports', async () => {
      // Act
      await controller.getAllScheduledReports();

      // Assert
      expect(service.getAllScheduledReports).toHaveBeenCalledTimes(1);
    });

    it('should return reports array', async () => {
      // Act
      const result = await controller.getAllScheduledReports();

      // Assert
      expect(result).toEqual([mockReport]);
    });
  });

  describe('getScheduledReportById', () => {
    it('should call service.getScheduledReportById with id', async () => {
      // Act
      await controller.getScheduledReportById('report-1');

      // Assert
      expect(service.getScheduledReportById).toHaveBeenCalledWith('report-1');
    });

    it('should throw HttpException when report not found', async () => {
      // Arrange
      service.getScheduledReportById.mockResolvedValue(null);

      // Act & Assert
      await expect(
        controller.getScheduledReportById('non-existent-id')
      ).rejects.toThrow(HttpException);
    });
  });

  describe('createScheduledReport', () => {
    it('should call service.createScheduledReport with DTO', async () => {
      // Arrange
      const dto: CreateScheduledReportDto = {
        name: 'Test Report',
        frequency: 'daily',
        format: 'html',
        enabled: true,
        deliveryMethod: 'email',
      };

      // Act
      await controller.createScheduledReport(dto);

      // Assert
      expect(service.createScheduledReport).toHaveBeenCalledWith(dto);
    });

    it('should throw HttpException on error', async () => {
      // Arrange
      const dto: CreateScheduledReportDto = {
        name: 'Test Report',
        frequency: 'daily',
        format: 'html',
        enabled: true,
        deliveryMethod: 'email',
      };
      service.createScheduledReport.mockRejectedValue(new Error('Validation failed'));

      // Act & Assert
      await expect(
        controller.createScheduledReport(dto)
      ).rejects.toThrow(HttpException);
    });
  });

  describe('updateScheduledReport', () => {
    it('should call service.updateScheduledReport with id and DTO', async () => {
      // Arrange
      const dto: UpdateScheduledReportDto = { name: 'Updated Report' };

      // Act
      await controller.updateScheduledReport('report-1', dto);

      // Assert
      expect(service.updateScheduledReport).toHaveBeenCalledWith('report-1', dto);
    });
  });

  describe('toggleScheduledReport', () => {
    it('should call service.toggleScheduledReport with id and enabled', async () => {
      // Act
      await controller.toggleScheduledReport('report-1', { enabled: false });

      // Assert
      expect(service.toggleScheduledReport).toHaveBeenCalledWith('report-1', false);
    });
  });

  describe('deleteScheduledReport', () => {
    it('should call service.deleteScheduledReport with id', async () => {
      // Act
      await controller.deleteScheduledReport('report-1');

      // Assert
      expect(service.deleteScheduledReport).toHaveBeenCalledWith('report-1');
    });

    it('should return success object', async () => {
      // Act
      const result = await controller.deleteScheduledReport('report-1');

      // Assert
      expect(result).toEqual({ success: true });
    });
  });
});
