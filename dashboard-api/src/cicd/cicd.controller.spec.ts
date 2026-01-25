/**
 * CICD Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, HttpException } from '@nestjs/common';
import { CICDController } from './cicd.controller';
import { CICDService, GitHubConfig, JenkinsConfig, CICDRun } from './cicd.service';

describe('CICDController', () => {
  let controller: CICDController;
  let service: jest.Mocked<CICDService>;

  const mockGitHubConfig: GitHubConfig = {
    enabled: true,
    repository: 'owner/repo',
    workflowFile: '.github/workflows/compliance.yml',
    complianceThreshold: 100,
    blockMerges: true,
    prComments: true,
    tokenSecret: 'secret-token',
  };

  const mockJenkinsConfig: JenkinsConfig = {
    enabled: true,
    url: 'https://jenkins.example.com',
    jobName: 'compliance-test',
    complianceThreshold: 100,
    blockBuilds: true,
    username: 'admin',
    apiToken: 'jenkins-token',
    pipelineScript: 'pipeline { ... }',
  };

  const mockGitHubRun: CICDRun = {
    id: 'github-run-1',
    name: 'Compliance Tests',
    status: 'success',
    complianceScore: 95,
    compliancePassed: true,
    blocked: false,
    duration: 120,
    startedAt: new Date(),
    completedAt: new Date(),
    prNumber: 123,
    branch: 'main',
    commit: 'abc123',
  };

  const mockJenkinsBuild: CICDRun = {
    id: 'jenkins-build-1',
    name: 'Compliance Tests',
    status: 'success',
    complianceScore: 98,
    compliancePassed: true,
    blocked: false,
    duration: 180,
    startedAt: new Date(),
    completedAt: new Date(),
    buildNumber: 456,
    branch: 'main',
    commit: 'def456',
  };

  const mockSettings = {
    minComplianceScore: 100,
    blockOnFailure: true,
    blockOnThreshold: true,
    requireApproval: false,
    notifyOnFailure: true,
    notifyOnBlock: true,
    notificationChannels: [],
  };

  beforeEach(async () => {
    const mockService = {
      getGitHubConfig: jest.fn(),
      saveGitHubConfig: jest.fn(),
      getGitHubRuns: jest.fn(),
      getGitHubRun: jest.fn(),
      getJenkinsConfig: jest.fn(),
      saveJenkinsConfig: jest.fn(),
      getJenkinsBuilds: jest.fn(),
      getJenkinsBuild: jest.fn(),
      getSettings: jest.fn(),
      saveSettings: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [CICDController],
      providers: [
        {
          provide: CICDService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<CICDController>(CICDController);
    service = module.get(CICDService) as jest.Mocked<CICDService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GitHub Actions', () => {
    describe('getGitHubConfig', () => {
      it('should return GitHub configuration', async () => {
        // Arrange
        service.getGitHubConfig.mockResolvedValue(mockGitHubConfig);

        // Act
        const result = await controller.getGitHubConfig();

        // Assert
        expect(result).toEqual(mockGitHubConfig);
        expect(service.getGitHubConfig).toHaveBeenCalledTimes(1);
        expect(service.getGitHubConfig).toHaveBeenCalledWith();
      });

      it('should return null when no GitHub config exists', async () => {
        // Arrange
        service.getGitHubConfig.mockResolvedValue(null);

        // Act
        const result = await controller.getGitHubConfig();

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('saveGitHubConfig', () => {
      it('should save GitHub configuration', async () => {
        // Arrange
        service.saveGitHubConfig.mockResolvedValue(mockGitHubConfig);

        // Act
        const result = await controller.saveGitHubConfig(mockGitHubConfig);

        // Assert
        expect(result).toEqual(mockGitHubConfig);
        expect(service.saveGitHubConfig).toHaveBeenCalledTimes(1);
        expect(service.saveGitHubConfig).toHaveBeenCalledWith(mockGitHubConfig);
      });
    });

    describe('getGitHubRuns', () => {
      it('should return all GitHub runs', async () => {
        // Arrange
        const runs = [mockGitHubRun];
        service.getGitHubRuns.mockResolvedValue(runs);

        // Act
        const result = await controller.getGitHubRuns();

        // Assert
        expect(result).toEqual(runs);
        expect(service.getGitHubRuns).toHaveBeenCalledTimes(1);
        expect(service.getGitHubRuns).toHaveBeenCalledWith();
      });

      it('should return empty array when no runs exist', async () => {
        // Arrange
        service.getGitHubRuns.mockResolvedValue([]);

        // Act
        const result = await controller.getGitHubRuns();

        // Assert
        expect(result).toEqual([]);
      });
    });

    describe('getGitHubRun', () => {
      it('should return a GitHub run by id', async () => {
        // Arrange
        const runId = 'github-run-1';
        service.getGitHubRun.mockResolvedValue(mockGitHubRun);

        // Act
        const result = await controller.getGitHubRun(runId);

        // Assert
        expect(result).toEqual(mockGitHubRun);
        expect(service.getGitHubRun).toHaveBeenCalledTimes(1);
        expect(service.getGitHubRun).toHaveBeenCalledWith(runId);
      });

      it('should throw HttpException when run not found', async () => {
        // Arrange
        const runId = 'non-existent';
        service.getGitHubRun.mockResolvedValue(null);

        // Act & Assert
        await expect(controller.getGitHubRun(runId)).rejects.toThrow(HttpException);
        await expect(controller.getGitHubRun(runId)).rejects.toThrow('Run not found');
        const error = await controller.getGitHubRun(runId).catch(e => e);
        expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
      });
    });
  });

  describe('Jenkins', () => {
    describe('getJenkinsConfig', () => {
      it('should return Jenkins configuration', async () => {
        // Arrange
        service.getJenkinsConfig.mockResolvedValue(mockJenkinsConfig);

        // Act
        const result = await controller.getJenkinsConfig();

        // Assert
        expect(result).toEqual(mockJenkinsConfig);
        expect(service.getJenkinsConfig).toHaveBeenCalledTimes(1);
        expect(service.getJenkinsConfig).toHaveBeenCalledWith();
      });

      it('should return null when no Jenkins config exists', async () => {
        // Arrange
        service.getJenkinsConfig.mockResolvedValue(null);

        // Act
        const result = await controller.getJenkinsConfig();

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('saveJenkinsConfig', () => {
      it('should save Jenkins configuration', async () => {
        // Arrange
        service.saveJenkinsConfig.mockResolvedValue(mockJenkinsConfig);

        // Act
        const result = await controller.saveJenkinsConfig(mockJenkinsConfig);

        // Assert
        expect(result).toEqual(mockJenkinsConfig);
        expect(service.saveJenkinsConfig).toHaveBeenCalledTimes(1);
        expect(service.saveJenkinsConfig).toHaveBeenCalledWith(mockJenkinsConfig);
      });
    });

    describe('getJenkinsBuilds', () => {
      it('should return all Jenkins builds', async () => {
        // Arrange
        const builds = [mockJenkinsBuild];
        service.getJenkinsBuilds.mockResolvedValue(builds);

        // Act
        const result = await controller.getJenkinsBuilds();

        // Assert
        expect(result).toEqual(builds);
        expect(service.getJenkinsBuilds).toHaveBeenCalledTimes(1);
        expect(service.getJenkinsBuilds).toHaveBeenCalledWith();
      });

      it('should return empty array when no builds exist', async () => {
        // Arrange
        service.getJenkinsBuilds.mockResolvedValue([]);

        // Act
        const result = await controller.getJenkinsBuilds();

        // Assert
        expect(result).toEqual([]);
      });
    });

    describe('getJenkinsBuild', () => {
      it('should return a Jenkins build by id', async () => {
        // Arrange
        const buildId = 'jenkins-build-1';
        service.getJenkinsBuild.mockResolvedValue(mockJenkinsBuild);

        // Act
        const result = await controller.getJenkinsBuild(buildId);

        // Assert
        expect(result).toEqual(mockJenkinsBuild);
        expect(service.getJenkinsBuild).toHaveBeenCalledTimes(1);
        expect(service.getJenkinsBuild).toHaveBeenCalledWith(buildId);
      });

      it('should throw HttpException when build not found', async () => {
        // Arrange
        const buildId = 'non-existent';
        service.getJenkinsBuild.mockResolvedValue(null);

        // Act & Assert
        await expect(controller.getJenkinsBuild(buildId)).rejects.toThrow(HttpException);
        await expect(controller.getJenkinsBuild(buildId)).rejects.toThrow('Build not found');
        const error = await controller.getJenkinsBuild(buildId).catch(e => e);
        expect(error.getStatus()).toBe(HttpStatus.NOT_FOUND);
      });
    });
  });

  describe('Global Settings', () => {
    describe('getSettings', () => {
      it('should return global settings', async () => {
        // Arrange
        service.getSettings.mockResolvedValue(mockSettings);

        // Act
        const result = await controller.getSettings();

        // Assert
        expect(result).toEqual(mockSettings);
        expect(service.getSettings).toHaveBeenCalledTimes(1);
        expect(service.getSettings).toHaveBeenCalledWith();
      });
    });

    describe('saveSettings', () => {
      it('should save global settings', async () => {
        // Arrange
        const updatedSettings = { ...mockSettings, minComplianceScore: 95 };
        service.saveSettings.mockResolvedValue(updatedSettings);

        // Act
        const result = await controller.saveSettings({ minComplianceScore: 95 });

        // Assert
        expect(result).toEqual(updatedSettings);
        expect(service.saveSettings).toHaveBeenCalledTimes(1);
        expect(service.saveSettings).toHaveBeenCalledWith({ minComplianceScore: 95 });
      });

      it('should merge partial settings with existing settings', async () => {
        // Arrange
        const partialSettings = { blockOnFailure: false };
        const mergedSettings = { ...mockSettings, ...partialSettings };
        service.saveSettings.mockResolvedValue(mergedSettings);

        // Act
        const result = await controller.saveSettings(partialSettings);

        // Assert
        expect(result).toEqual(mergedSettings);
        expect(service.saveSettings).toHaveBeenCalledWith(partialSettings);
      });
    });
  });
});
