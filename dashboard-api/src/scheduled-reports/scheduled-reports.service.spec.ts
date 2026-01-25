/**
 * Scheduled Reports Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ScheduledReportsService } from './scheduled-reports.service';
import { SchedulerService } from './scheduler.service';
import { ReportsService } from '../reports/reports.service';
import { CreateScheduledReportDto } from './dto/create-scheduled-report.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');

describe('ScheduledReportsService', () => {
  let service: ScheduledReportsService;
  let schedulerService: jest.Mocked<SchedulerService>;
  let reportsService: jest.Mocked<ReportsService>;

  const createDto: CreateScheduledReportDto = {
    name: 'Daily Report',
    frequency: 'daily',
    format: 'html',
    reportType: 'custom',
    enabled: true,
    recipients: ['user@example.com'],
    deliveryMethod: 'email',
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockSchedulerService = {
      registerSchedule: jest.fn(),
      unregisterSchedule: jest.fn(),
    };

    const mockReportsService = {
      generateReport: jest.fn().mockResolvedValue({ id: 'report-1', content: 'Report content' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScheduledReportsService,
        {
          provide: SchedulerService,
          useValue: mockSchedulerService,
        },
        {
          provide: ReportsService,
          useValue: mockReportsService,
        },
      ],
    }).compile();

    service = module.get<ScheduledReportsService>(ScheduledReportsService);
    schedulerService = module.get(SchedulerService) as jest.Mocked<SchedulerService>;
    reportsService = module.get(ReportsService) as jest.Mocked<ReportsService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Mock onModuleInit/onModuleDestroy - don't call them automatically
    jest.spyOn(service as any, 'loadScheduledReports').mockResolvedValue(undefined);
    jest.spyOn(service as any, 'startScheduler').mockImplementation(() => {});
  });

  describe('createScheduledReport', () => {
    it('should successfully create a scheduled report', async () => {
      // Act
      const result = await service.createScheduledReport(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.name).toBe(createDto.name);
      expect(result.frequency).toBe(createDto.frequency);
      expect(result.enabled).toBe(createDto.enabled);
      expect(result.nextRun).toBeInstanceOf(Date);
      expect(schedulerService.registerSchedule).toHaveBeenCalled();
    });

    it('should default enabled to true when not provided', async () => {
      // Arrange
      const dtoWithoutEnabled = { ...createDto, enabled: undefined };

      // Act
      const result = await service.createScheduledReport(dtoWithoutEnabled);

      // Assert
      expect(result.enabled).toBe(true);
    });
  });

  describe('getAllScheduledReports', () => {
    it('should return all scheduled reports', async () => {
      // Act
      const result = await service.getAllScheduledReports();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('getScheduledReportById', () => {
    beforeEach(() => {
      const fs = require('fs/promises');
      fs.readFile.mockResolvedValue(JSON.stringify([
        {
          id: 'report-1',
          name: 'Test Report',
          frequency: 'daily',
          enabled: true,
          nextRun: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ]));
    });

    it('should return report when found', async () => {
      // Act
      const result = await service.getScheduledReportById('report-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('report-1');
    });

    it('should return null when report not found', async () => {
      // Act
      const result = await service.getScheduledReportById('non-existent-id');

      // Assert
      expect(result).toBeNull();
    });
  });
});
