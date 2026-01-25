/**
 * CICD Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { CICDService, GitHubConfig, JenkinsConfig, CICDRun } from './cicd.service';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock dependencies
jest.mock('fs/promises');

describe('CICDService', () => {
  let service: CICDService;

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
    url: 'http://jenkins.example.com',
    jobName: 'compliance-tests',
    complianceThreshold: 100,
    blockBuilds: true,
    username: 'jenkins-user',
    apiToken: 'api-token',
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CICDService],
    }).compile();

    service = module.get<CICDService>(CICDService);
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GitHub Config', () => {
    it('should get GitHub config', async () => {
      // Arrange
      (service as any).githubConfig = mockGitHubConfig;

      // Act
      const result = await service.getGitHubConfig();

      // Assert
      expect(result).toEqual(mockGitHubConfig);
    });

    it('should return null when GitHub config not set', async () => {
      // Act
      const result = await service.getGitHubConfig();

      // Assert
      expect(result).toBeNull();
    });

    it('should save GitHub config', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.saveGitHubConfig(mockGitHubConfig);

      // Assert
      expect(result).toEqual(mockGitHubConfig);
      expect(await service.getGitHubConfig()).toEqual(mockGitHubConfig);
    });
  });

  describe('GitHub Runs', () => {
    it('should get GitHub runs', async () => {
      // Arrange
      const mockRuns: CICDRun[] = [
        {
          id: 'github-1',
          name: 'Test Run',
          status: 'success',
          complianceScore: 100,
          compliancePassed: true,
          blocked: false,
          duration: 1000,
          startedAt: new Date(),
        },
      ];
      (service as any).githubRuns = mockRuns;

      // Act
      const result = await service.getGitHubRuns();

      // Assert
      expect(result).toEqual(mockRuns);
    });

    it('should get GitHub run by id', async () => {
      // Arrange
      const mockRun: CICDRun = {
        id: 'github-1',
        name: 'Test Run',
        status: 'success',
        complianceScore: 100,
        compliancePassed: true,
        blocked: false,
        duration: 1000,
        startedAt: new Date(),
      };
      (service as any).githubRuns = [mockRun];

      // Act
      const result = await service.getGitHubRun('github-1');

      // Assert
      expect(result).toEqual(mockRun);
    });

    it('should return null for non-existent GitHub run', async () => {
      // Act
      const result = await service.getGitHubRun('non-existent');

      // Assert
      expect(result).toBeNull();
    });

    it('should create GitHub run', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (service as any).githubConfig = mockGitHubConfig;

      // Act
      const result = await service.createGitHubRun({
        name: 'New Run',
        complianceScore: 95,
      });

      // Assert
      expect(result.id).toContain('github-');
      expect(result.name).toBe('New Run');
      expect(result.complianceScore).toBe(95);
      expect(result.compliancePassed).toBe(false); // Below threshold
      expect(result.blocked).toBe(true); // blockMerges is true
    });

    it('should not block when compliance passed', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (service as any).githubConfig = mockGitHubConfig;

      // Act
      const result = await service.createGitHubRun({
        name: 'New Run',
        complianceScore: 100,
      });

      // Assert
      expect(result.compliancePassed).toBe(true);
      expect(result.blocked).toBe(false);
    });
  });

  describe('Jenkins Config', () => {
    it('should get Jenkins config', async () => {
      // Arrange
      (service as any).jenkinsConfig = mockJenkinsConfig;

      // Act
      const result = await service.getJenkinsConfig();

      // Assert
      expect(result).toEqual(mockJenkinsConfig);
    });

    it('should return null when Jenkins config not set', async () => {
      // Act
      const result = await service.getJenkinsConfig();

      // Assert
      expect(result).toBeNull();
    });

    it('should save Jenkins config', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.saveJenkinsConfig(mockJenkinsConfig);

      // Assert
      expect(result).toEqual(mockJenkinsConfig);
      expect(await service.getJenkinsConfig()).toEqual(mockJenkinsConfig);
    });
  });

  describe('Jenkins Builds', () => {
    it('should get Jenkins builds', async () => {
      // Arrange
      const mockBuilds: CICDRun[] = [
        {
          id: 'jenkins-1',
          name: 'Test Build',
          status: 'success',
          complianceScore: 100,
          compliancePassed: true,
          blocked: false,
          duration: 2000,
          startedAt: new Date(),
        },
      ];
      (service as any).jenkinsBuilds = mockBuilds;

      // Act
      const result = await service.getJenkinsBuilds();

      // Assert
      expect(result).toEqual(mockBuilds);
    });

    it('should get Jenkins build by id', async () => {
      // Arrange
      const mockBuild: CICDRun = {
        id: 'jenkins-1',
        name: 'Test Build',
        status: 'success',
        complianceScore: 100,
        compliancePassed: true,
        blocked: false,
        duration: 2000,
        startedAt: new Date(),
      };
      (service as any).jenkinsBuilds = [mockBuild];

      // Act
      const result = await service.getJenkinsBuild('jenkins-1');

      // Assert
      expect(result).toEqual(mockBuild);
    });

    it('should return null for non-existent Jenkins build', async () => {
      // Act
      const result = await service.getJenkinsBuild('non-existent');

      // Assert
      expect(result).toBeNull();
    });

    it('should create Jenkins build', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (service as any).jenkinsConfig = mockJenkinsConfig;

      // Act
      const result = await service.createJenkinsBuild({
        name: 'New Build',
        complianceScore: 95,
      });

      // Assert
      expect(result.id).toContain('jenkins-');
      expect(result.name).toBe('New Build');
      expect(result.complianceScore).toBe(95);
      expect(result.compliancePassed).toBe(false);
      expect(result.blocked).toBe(true);
    });
  });

  describe('Global Settings', () => {
    it('should get settings', async () => {
      // Act
      const result = await service.getSettings();

      // Assert
      expect(result).toBeDefined();
      expect(result.minComplianceScore).toBe(100);
      expect(result.blockOnFailure).toBe(true);
    });

    it('should save settings', async () => {
      // Arrange
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      const newSettings = {
        minComplianceScore: 90,
        notifyOnFailure: false,
      };

      // Act
      const result = await service.saveSettings(newSettings);

      // Assert
      expect(result.minComplianceScore).toBe(90);
      expect(result.notifyOnFailure).toBe(false);
      expect(result.blockOnFailure).toBe(true); // Preserved from defaults
    });
  });
});
