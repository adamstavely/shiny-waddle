/**
 * Scheduler Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SchedulerService } from './scheduler.service';
import { ScheduledReport } from './entities/scheduled-report.entity';

describe('SchedulerService', () => {
  let service: SchedulerService;

  const mockScheduledReport: ScheduledReport = {
    id: 'schedule-1',
    name: 'Weekly Compliance Report',
    reportType: 'executive',
    frequency: 'weekly',
    format: 'pdf',
    deliveryMethod: 'email',
    nextRun: new Date('2026-01-26'),
    runCount: 0,
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SchedulerService],
    }).compile();

    service = module.get<SchedulerService>(SchedulerService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('registerSchedule', () => {
    it('should register a schedule', () => {
      // Act
      service.registerSchedule(mockScheduledReport);

      // Assert
      const schedule = service.getSchedule('schedule-1');
      expect(schedule).toBeDefined();
      expect(schedule?.id).toBe('schedule-1');
      expect(schedule?.name).toBe('Weekly Compliance Report');
    });

    it('should overwrite existing schedule with same id', () => {
      // Arrange
      service.registerSchedule(mockScheduledReport);
      const updatedReport = { ...mockScheduledReport, name: 'Updated Report' };

      // Act
      service.registerSchedule(updatedReport);

      // Assert
      const schedule = service.getSchedule('schedule-1');
      expect(schedule?.name).toBe('Updated Report');
    });
  });

  describe('unregisterSchedule', () => {
    it('should unregister a schedule', () => {
      // Arrange
      service.registerSchedule(mockScheduledReport);

      // Act
      service.unregisterSchedule('schedule-1');

      // Assert
      const schedule = service.getSchedule('schedule-1');
      expect(schedule).toBeUndefined();
    });

    it('should not throw when unregistering non-existent schedule', () => {
      // Act & Assert
      expect(() => {
        service.unregisterSchedule('non-existent');
      }).not.toThrow();
    });
  });

  describe('getSchedule', () => {
    it('should return schedule by id', () => {
      // Arrange
      service.registerSchedule(mockScheduledReport);

      // Act
      const schedule = service.getSchedule('schedule-1');

      // Assert
      expect(schedule).toBeDefined();
      expect(schedule?.id).toBe('schedule-1');
    });

    it('should return undefined for non-existent schedule', () => {
      // Act
      const schedule = service.getSchedule('non-existent');

      // Assert
      expect(schedule).toBeUndefined();
    });
  });

  describe('getAllSchedules', () => {
    it('should return all registered schedules', () => {
      // Arrange
      const report2 = { ...mockScheduledReport, id: 'schedule-2', name: 'Report 2' };
      service.registerSchedule(mockScheduledReport);
      service.registerSchedule(report2);

      // Act
      const schedules = service.getAllSchedules();

      // Assert
      expect(schedules).toHaveLength(2);
      expect(schedules.map(s => s.id)).toContain('schedule-1');
      expect(schedules.map(s => s.id)).toContain('schedule-2');
    });

    it('should return empty array when no schedules registered', () => {
      // Act
      const schedules = service.getAllSchedules();

      // Assert
      expect(schedules).toEqual([]);
    });
  });
});
