/**
 * Context Detector Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ContextDetectorService, ExecutionContext } from './context-detector.service';

describe('ContextDetectorService', () => {
  let service: ContextDetectorService;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ContextDetectorService],
    }).compile();

    service = module.get<ContextDetectorService>(ContextDetectorService);
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('detectContext', () => {
    it('should detect GitHub Actions context', () => {
      // Arrange
      process.env.GITHUB_ACTIONS = 'true';
      process.env.GITHUB_RUN_ID = '123456';
      process.env.GITHUB_SHA = 'abc123';
      process.env.GITHUB_REF = 'refs/heads/main';
      process.env.GITHUB_WORKFLOW = 'test-workflow';
      process.env.GITHUB_ACTOR = 'test-user';
      process.env.GITHUB_REPOSITORY = 'owner/repo';
      process.env.GITHUB_JOB = 'test-job';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBe('github-actions');
      expect(context.buildId).toBe('123456');
      expect(context.runId).toBe('123456');
      expect(context.commitSha).toBe('abc123');
      expect(context.branch).toBe('main');
      expect(context.workflowName).toBe('test-workflow');
      expect(context.actor).toBe('test-user');
      expect(context.repository).toBe('owner/repo');
      expect(context.jobName).toBe('test-job');
    });

    it('should detect GitLab CI context', () => {
      // Arrange
      process.env.GITLAB_CI = 'true';
      process.env.CI_PIPELINE_ID = '789';
      process.env.CI_JOB_ID = '456';
      process.env.CI_COMMIT_SHA = 'def456';
      process.env.CI_COMMIT_REF_NAME = 'feature-branch';
      process.env.CI_JOB_NAME = 'test';
      process.env.GITLAB_USER_LOGIN = 'gitlab-user';
      process.env.CI_PROJECT_PATH = 'group/project';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBe('gitlab-ci');
      expect(context.buildId).toBe('789');
      expect(context.runId).toBe('456');
      expect(context.commitSha).toBe('def456');
      expect(context.branch).toBe('feature-branch');
      expect(context.jobName).toBe('test');
      expect(context.actor).toBe('gitlab-user');
      expect(context.repository).toBe('group/project');
    });

    it('should detect Jenkins context', () => {
      // Arrange
      process.env.JENKINS_URL = 'http://jenkins.example.com';
      process.env.BUILD_NUMBER = '100';
      process.env.BUILD_ID = 'build-100';
      process.env.GIT_COMMIT = 'ghi789';
      process.env.GIT_BRANCH = 'origin/main';
      process.env.JOB_NAME = 'test-job';
      process.env.BUILD_USER_ID = 'jenkins-user';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBe('jenkins');
      expect(context.buildId).toBe('100');
      expect(context.runId).toBe('build-100');
      expect(context.commitSha).toBe('ghi789');
      expect(context.branch).toBe('main');
      expect(context.jobName).toBe('test-job');
      expect(context.actor).toBe('jenkins-user');
    });

    it('should detect CircleCI context', () => {
      // Arrange
      process.env.CIRCLECI = 'true';
      process.env.CIRCLE_BUILD_NUM = '200';
      process.env.CIRCLE_WORKFLOW_ID = 'workflow-200';
      process.env.CIRCLE_SHA1 = 'jkl012';
      process.env.CIRCLE_BRANCH = 'develop';
      process.env.CIRCLE_JOB = 'build';
      process.env.CIRCLE_USERNAME = 'circle-user';
      process.env.CIRCLE_PROJECT_USERNAME = 'owner';
      process.env.CIRCLE_PROJECT_REPONAME = 'repo';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBe('circleci');
      expect(context.buildId).toBe('200');
      expect(context.runId).toBe('workflow-200');
      expect(context.commitSha).toBe('jkl012');
      expect(context.branch).toBe('develop');
      expect(context.jobName).toBe('build');
      expect(context.actor).toBe('circle-user');
      expect(context.repository).toBe('owner/repo');
    });

    it('should detect Azure DevOps context', () => {
      // Arrange
      process.env.SYSTEM_TEAMFOUNDATIONCOLLECTIONURI = 'https://dev.azure.com';
      process.env.BUILD_BUILDID = '300';
      process.env.BUILD_SOURCEVERSION = 'mno345';
      process.env.BUILD_SOURCEBRANCH = 'refs/heads/master';
      process.env.AGENT_JOBNAME = 'azure-job';
      process.env.BUILD_REQUESTEDFOR = 'azure-user';
      process.env.BUILD_REPOSITORY_NAME = 'azure-repo';
      process.env.BUILD_DEFINITIONNAME = 'azure-pipeline';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBe('azure-devops');
      expect(context.buildId).toBe('300');
      expect(context.runId).toBe('300');
      expect(context.commitSha).toBe('mno345');
      expect(context.branch).toBe('master');
      expect(context.jobName).toBe('azure-job');
      expect(context.actor).toBe('azure-user');
      expect(context.repository).toBe('azure-repo');
      expect(context.workflowName).toBe('azure-pipeline');
    });

    it('should return undefined platform when not in CI', () => {
      // Arrange - clear CI environment
      delete process.env.CI;
      delete process.env.GITHUB_ACTIONS;
      delete process.env.GITLAB_CI;
      delete process.env.JENKINS_URL;
      delete process.env.CIRCLECI;
      delete process.env.TRAVIS;
      delete process.env.SYSTEM_TEAMFOUNDATIONCOLLECTIONURI;

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.ciPlatform).toBeUndefined();
    });

    it('should set timestamp', () => {
      // Act
      const context = service.detectContext();

      // Assert
      expect(context.timestamp).toBeInstanceOf(Date);
    });

    it('should set environment from NODE_ENV', () => {
      // Arrange
      process.env.NODE_ENV = 'production';

      // Act
      const context = service.detectContext();

      // Assert
      expect(context.environment).toBe('production');
    });
  });

  describe('validateContext', () => {
    it('should validate valid context', () => {
      // Arrange
      const context: ExecutionContext = {
        ciPlatform: 'github-actions',
        commitSha: 'abc123',
        timestamp: new Date(),
      };

      // Act
      const result = service.validateContext(context);

      // Assert
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should invalidate context without platform', () => {
      // Arrange
      const context: ExecutionContext = {
        commitSha: 'abc123',
        timestamp: new Date(),
      };

      // Act
      const result = service.validateContext(context);

      // Assert
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('CI/CD platform not detected');
    });

    it('should invalidate context without commit SHA or build ID', () => {
      // Arrange
      const context: ExecutionContext = {
        ciPlatform: 'github-actions',
        timestamp: new Date(),
      };

      // Act
      const result = service.validateContext(context);

      // Assert
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Neither commit SHA nor build ID is available');
    });

    it('should validate context with build ID but no commit SHA', () => {
      // Arrange
      const context: ExecutionContext = {
        ciPlatform: 'github-actions',
        buildId: '123',
        timestamp: new Date(),
      };

      // Act
      const result = service.validateContext(context);

      // Assert
      expect(result.valid).toBe(true);
    });
  });

  describe('mergeContext', () => {
    it('should merge provided context with detected context', () => {
      // Arrange
      const detected: ExecutionContext = {
        ciPlatform: 'github-actions',
        commitSha: 'detected-sha',
        branch: 'detected-branch',
        timestamp: new Date('2026-01-01'),
      };
      const provided: Partial<ExecutionContext> = {
        commitSha: 'provided-sha',
        buildId: 'provided-build',
      };

      // Act
      const merged = service.mergeContext(provided, detected);

      // Assert
      expect(merged.ciPlatform).toBe('github-actions'); // From detected
      expect(merged.commitSha).toBe('provided-sha'); // From provided (overrides)
      expect(merged.buildId).toBe('provided-build'); // From provided
      expect(merged.branch).toBe('detected-branch'); // From detected
    });

    it('should use provided timestamp if available', () => {
      // Arrange
      const detected: ExecutionContext = {
        timestamp: new Date('2026-01-01'),
      };
      const provided: Partial<ExecutionContext> = {
        timestamp: new Date('2026-01-02'),
      };

      // Act
      const merged = service.mergeContext(provided, detected);

      // Assert
      expect(merged.timestamp).toEqual(new Date('2026-01-02'));
    });

    it('should use detected timestamp if provided timestamp not available', () => {
      // Arrange
      const detected: ExecutionContext = {
        timestamp: new Date('2026-01-01'),
      };
      const provided: Partial<ExecutionContext> = {};

      // Act
      const merged = service.mergeContext(provided, detected);

      // Assert
      expect(merged.timestamp).toEqual(new Date('2026-01-01'));
    });

    it('should create new timestamp if neither provided', () => {
      // Arrange
      const detected: ExecutionContext = {};
      const provided: Partial<ExecutionContext> = {};
      const beforeTime = new Date();

      // Act
      const merged = service.mergeContext(provided, detected);

      // Assert
      expect(merged.timestamp).toBeInstanceOf(Date);
      expect(merged.timestamp!.getTime()).toBeGreaterThanOrEqual(beforeTime.getTime());
    });
  });
});
