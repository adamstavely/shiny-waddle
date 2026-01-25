/**
 * Applications Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { ApplicationsController } from './applications.controller';
import { ApplicationsService } from './applications.service';
import { CreateApplicationDto, ApplicationStatus, ApplicationType } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { ToggleValidatorDto } from './dto/toggle-validator.dto';
import { BulkToggleDto } from './dto/bulk-toggle.dto';
import { Application } from './entities/application.entity';
import { AccessControlGuard } from '../security/guards/access-control.guard';

describe('ApplicationsController', () => {
  let controller: ApplicationsController;
  let applicationsService: jest.Mocked<ApplicationsService>;

  const mockApplication: Application = {
    id: 'app-1',
    name: 'Test Application',
    type: ApplicationType.API,
    status: ApplicationStatus.ACTIVE,
    baseUrl: 'https://api.example.com',
    team: 'team-1',
    description: 'Test application description',
    infrastructure: {},
    registeredAt: new Date(),
    updatedAt: new Date(),
  };

  const mockApplications: Application[] = [
    mockApplication,
    {
      ...mockApplication,
      id: 'app-2',
      name: 'Another Application',
      status: ApplicationStatus.INACTIVE,
    },
  ];

  const mockRequest = {
    user: {
      id: 'user-1',
      userId: 'user-1',
      username: 'testuser',
      email: 'test@example.com',
    },
  };

  beforeEach(async () => {
    const mockApplicationsService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findByTeam: jest.fn(),
      findByStatus: jest.fn(),
      findByType: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
      getAssignedTestHarnesses: jest.fn(),
      getAssignedTestBatteries: jest.fn(),
      getRuns: jest.fn(),
      getIssues: jest.fn(),
      getAllIssues: jest.fn(),
      getComplianceScore: jest.fn(),
      updateLastTestAt: jest.fn(),
      runTests: jest.fn(),
      toggleValidator: jest.fn(),
      getValidatorStatus: jest.fn(),
      bulkToggleValidators: jest.fn(),
      removeValidatorOverride: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApplicationsController],
      providers: [
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
      ],
    })
      .overrideGuard(AccessControlGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<ApplicationsController>(ApplicationsController);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createApplicationDto: CreateApplicationDto = {
      id: 'app-3',
      name: 'New Application',
      type: ApplicationType.WEB,
      status: ApplicationStatus.ACTIVE,
      team: 'team-1',
    };

    it('should create an application successfully', async () => {
      // Arrange
      applicationsService.create.mockResolvedValue(mockApplication);

      // Act
      const result = await controller.create(createApplicationDto);

      // Assert
      expect(result).toEqual(mockApplication);
      expect(applicationsService.create).toHaveBeenCalledTimes(1);
      expect(applicationsService.create).toHaveBeenCalledWith(createApplicationDto);
    });
  });

  describe('findAll', () => {
    it('should return all applications when no filters provided', async () => {
      // Arrange
      applicationsService.findAll.mockResolvedValue(mockApplications);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockApplications);
      expect(applicationsService.findAll).toHaveBeenCalledTimes(1);
    });

    it('should filter by team', async () => {
      // Arrange
      applicationsService.findByTeam.mockResolvedValue([mockApplication]);

      // Act
      const result = await controller.findAll('team-1');

      // Assert
      expect(result).toEqual([mockApplication]);
      expect(applicationsService.findByTeam).toHaveBeenCalledWith('team-1');
      expect(applicationsService.findAll).not.toHaveBeenCalled();
    });

    it('should filter by status', async () => {
      // Arrange
      applicationsService.findByStatus.mockResolvedValue([mockApplication]);

      // Act
      const result = await controller.findAll(undefined, ApplicationStatus.ACTIVE);

      // Assert
      expect(result).toEqual([mockApplication]);
      expect(applicationsService.findByStatus).toHaveBeenCalledWith(ApplicationStatus.ACTIVE);
    });

    it('should filter by type', async () => {
      // Arrange
      applicationsService.findByType.mockResolvedValue([mockApplication]);

      // Act
      const result = await controller.findAll(undefined, undefined, ApplicationType.API);

      // Assert
      expect(result).toEqual([mockApplication]);
      expect(applicationsService.findByType).toHaveBeenCalledWith(ApplicationType.API);
    });
  });

  describe('getAllIssues', () => {
    const mockIssues = [
      { id: 'issue-1', severity: 'high' },
      { id: 'issue-2', severity: 'medium' },
    ];

    it('should return all issues without filters', async () => {
      // Arrange
      applicationsService.getAllIssues.mockResolvedValue(mockIssues);

      // Act
      const result = await controller.getAllIssues();

      // Assert
      expect(result).toEqual(mockIssues);
      expect(applicationsService.getAllIssues).toHaveBeenCalledWith(undefined, undefined);
    });

    it('should return all issues with limit', async () => {
      // Arrange
      applicationsService.getAllIssues.mockResolvedValue([mockIssues[0]]);

      // Act
      const result = await controller.getAllIssues('1');

      // Assert
      expect(result).toEqual([mockIssues[0]]);
      expect(applicationsService.getAllIssues).toHaveBeenCalledWith(1, undefined);
    });

    it('should return all issues with priority filter', async () => {
      // Arrange
      applicationsService.getAllIssues.mockResolvedValue([mockIssues[0]]);

      // Act
      const result = await controller.getAllIssues(undefined, 'high');

      // Assert
      expect(result).toEqual([mockIssues[0]]);
      expect(applicationsService.getAllIssues).toHaveBeenCalledWith(undefined, 'high');
    });
  });

  describe('findOne', () => {
    it('should return an application by id', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue(mockApplication);

      // Act
      const result = await controller.findOne('app-1');

      // Assert
      expect(result).toEqual(mockApplication);
      expect(applicationsService.findOne).toHaveBeenCalledWith('app-1');
    });

    it('should propagate NotFoundException when application not found', async () => {
      // Arrange
      applicationsService.findOne.mockRejectedValue(new NotFoundException('Application not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateApplicationDto: UpdateApplicationDto = {
      name: 'Updated Application',
      status: ApplicationStatus.MAINTENANCE,
    };

    it('should update an application successfully', async () => {
      // Arrange
      const updatedApp = { ...mockApplication, ...updateApplicationDto };
      applicationsService.update.mockResolvedValue(updatedApp);

      // Act
      const result = await controller.update('app-1', updateApplicationDto);

      // Assert
      expect(result).toEqual(updatedApp);
      expect(applicationsService.update).toHaveBeenCalledWith('app-1', updateApplicationDto);
    });
  });

  describe('remove', () => {
    it('should delete an application successfully', async () => {
      // Arrange
      applicationsService.remove.mockResolvedValue(undefined);

      // Act
      await controller.remove('app-1');

      // Assert
      expect(applicationsService.remove).toHaveBeenCalledWith('app-1');
    });
  });

  describe('getTestHarnesses', () => {
    const mockHarnesses = [{ id: 'harness-1', name: 'Harness 1' }];

    it('should return test harnesses for an application', async () => {
      // Arrange
      applicationsService.getAssignedTestHarnesses.mockResolvedValue(mockHarnesses);

      // Act
      const result = await controller.getTestHarnesses('app-1');

      // Assert
      expect(result).toEqual(mockHarnesses);
      expect(applicationsService.getAssignedTestHarnesses).toHaveBeenCalledWith('app-1');
    });
  });

  describe('getTestBatteries', () => {
    const mockBatteries = [{ id: 'battery-1', name: 'Battery 1' }];

    it('should return test batteries for an application', async () => {
      // Arrange
      applicationsService.getAssignedTestBatteries.mockResolvedValue(mockBatteries);

      // Act
      const result = await controller.getTestBatteries('app-1');

      // Assert
      expect(result).toEqual(mockBatteries);
      expect(applicationsService.getAssignedTestBatteries).toHaveBeenCalledWith('app-1');
    });
  });

  describe('getRuns', () => {
    const mockRuns = [{ id: 'run-1', status: 'passed' }];

    it('should return runs for an application', async () => {
      // Arrange
      applicationsService.getRuns.mockResolvedValue(mockRuns);

      // Act
      const result = await controller.getRuns('app-1');

      // Assert
      expect(result).toEqual(mockRuns);
      expect(applicationsService.getRuns).toHaveBeenCalledWith('app-1', undefined);
    });

    it('should return runs with limit', async () => {
      // Arrange
      applicationsService.getRuns.mockResolvedValue([mockRuns[0]]);

      // Act
      const result = await controller.getRuns('app-1', '1');

      // Assert
      expect(result).toEqual([mockRuns[0]]);
      expect(applicationsService.getRuns).toHaveBeenCalledWith('app-1', 1);
    });
  });

  describe('getIssues', () => {
    const mockIssues = [{ id: 'issue-1', severity: 'high' }];

    it('should return issues for an application', async () => {
      // Arrange
      applicationsService.getIssues.mockResolvedValue(mockIssues);

      // Act
      const result = await controller.getIssues('app-1');

      // Assert
      expect(result).toEqual(mockIssues);
      expect(applicationsService.getIssues).toHaveBeenCalledWith('app-1', undefined, undefined);
    });

    it('should return issues with limit and priority', async () => {
      // Arrange
      applicationsService.getIssues.mockResolvedValue(mockIssues);

      // Act
      const result = await controller.getIssues('app-1', '10', 'high');

      // Assert
      expect(result).toEqual(mockIssues);
      expect(applicationsService.getIssues).toHaveBeenCalledWith('app-1', 10, 'high');
    });
  });

  describe('getComplianceScore', () => {
    it('should return compliance score for an application', async () => {
      // Arrange
      applicationsService.getComplianceScore.mockResolvedValue({ score: 85 });

      // Act
      const result = await controller.getComplianceScore('app-1');

      // Assert
      expect(result).toEqual({ score: 85 });
      expect(applicationsService.getComplianceScore).toHaveBeenCalledWith('app-1');
    });
  });

  describe('updateLastTest', () => {
    it('should update last test timestamp', async () => {
      // Arrange
      const updatedApp = { ...mockApplication, lastTestAt: new Date() };
      applicationsService.updateLastTestAt.mockResolvedValue(updatedApp);

      // Act
      const result = await controller.updateLastTest('app-1');

      // Assert
      expect(result).toEqual(updatedApp);
      expect(applicationsService.updateLastTestAt).toHaveBeenCalledWith('app-1', expect.any(Date));
    });
  });

  describe('getInfrastructure', () => {
    it('should return application infrastructure', async () => {
      // Arrange
      const appWithInfra = {
        ...mockApplication,
        infrastructure: { databases: [] },
      };
      applicationsService.findOne.mockResolvedValue(appWithInfra);

      // Act
      const result = await controller.getInfrastructure('app-1');

      // Assert
      expect(result).toEqual({ databases: [] });
      expect(applicationsService.findOne).toHaveBeenCalledWith('app-1');
    });

    it('should return empty object when infrastructure is undefined', async () => {
      // Arrange
      applicationsService.findOne.mockResolvedValue(mockApplication);

      // Act
      const result = await controller.getInfrastructure('app-1');

      // Assert
      expect(result).toEqual({});
    });
  });

  describe('runTests', () => {
    const mockRunResult = {
      status: 'passed' as const,
      totalTests: 10,
      passed: 10,
      failed: 0,
      results: [],
    };

    it('should run tests without context', async () => {
      // Arrange
      applicationsService.runTests.mockResolvedValue(mockRunResult);

      // Act
      const result = await controller.runTests('app-1');

      // Assert
      expect(result).toEqual(mockRunResult);
      expect(applicationsService.runTests).toHaveBeenCalledWith('app-1', {});
    });

    it('should run tests with context', async () => {
      // Arrange
      applicationsService.runTests.mockResolvedValue(mockRunResult);

      // Act
      const result = await controller.runTests('app-1', 'build-123', 'run-456', 'abc123', 'main');

      // Assert
      expect(result).toEqual(mockRunResult);
      expect(applicationsService.runTests).toHaveBeenCalledWith('app-1', {
        buildId: 'build-123',
        runId: 'run-456',
        commitSha: 'abc123',
        branch: 'main',
      });
    });
  });

  describe('toggleValidator', () => {
    const toggleDto: ToggleValidatorDto = {
      enabled: true,
      reason: 'Testing',
    };

    it('should toggle a validator', async () => {
      // Arrange
      const updatedApp = { ...mockApplication };
      applicationsService.toggleValidator.mockResolvedValue(updatedApp);

      // Act
      const result = await controller.toggleValidator('app-1', 'validator-1', toggleDto, mockRequest as any);

      // Assert
      expect(result).toEqual(updatedApp);
      expect(applicationsService.toggleValidator).toHaveBeenCalledWith(
        'app-1',
        'validator-1',
        true,
        'Testing',
        'user-1',
        'testuser'
      );
    });
  });

  describe('getValidatorStatus', () => {
    const mockStatus = [
      {
        validatorId: 'validator-1',
        name: 'Validator 1',
        testType: 'access-control',
        enabled: true,
      },
    ];

    it('should return validator status', async () => {
      // Arrange
      applicationsService.getValidatorStatus.mockResolvedValue(mockStatus);

      // Act
      const result = await controller.getValidatorStatus('app-1');

      // Assert
      expect(result).toEqual(mockStatus);
      expect(applicationsService.getValidatorStatus).toHaveBeenCalledWith('app-1');
    });
  });

  describe('bulkToggleValidators', () => {
    const bulkToggleDto: BulkToggleDto = {
      items: [
        { id: 'validator-1', enabled: true, reason: 'Test' },
      ],
    };

    it('should bulk toggle validators', async () => {
      // Arrange
      const updatedApp = { ...mockApplication };
      applicationsService.bulkToggleValidators.mockResolvedValue(updatedApp);

      // Act
      const result = await controller.bulkToggleValidators('app-1', bulkToggleDto, mockRequest as any);

      // Assert
      expect(result).toEqual(updatedApp);
      expect(applicationsService.bulkToggleValidators).toHaveBeenCalledWith(
        'app-1',
        bulkToggleDto.items,
        'user-1',
        'testuser'
      );
    });
  });

  describe('removeValidatorOverride', () => {
    it('should remove validator override', async () => {
      // Arrange
      const updatedApp = { ...mockApplication };
      applicationsService.removeValidatorOverride.mockResolvedValue(updatedApp);

      // Act
      const result = await controller.removeValidatorOverride('app-1', 'validator-1', mockRequest as any);

      // Assert
      expect(result).toEqual(updatedApp);
      expect(applicationsService.removeValidatorOverride).toHaveBeenCalledWith(
        'app-1',
        'validator-1',
        'user-1',
        'testuser'
      );
    });
  });
});
