import { Injectable, Logger } from '@nestjs/common';

export interface ExecutionContext {
  buildId?: string;
  runId?: string;
  commitSha?: string;
  branch?: string;
  tag?: string;
  pullRequestNumber?: number;
  ciPlatform?: 'github-actions' | 'gitlab-ci' | 'jenkins' | 'circleci' | 'travis-ci' | 'azure-devops' | 'unknown';
  jobName?: string;
  workflowName?: string;
  actor?: string;
  repository?: string;
  environment?: string;
  timestamp?: Date;
}

@Injectable()
export class ContextDetectorService {
  private readonly logger = new Logger(ContextDetectorService.name);

  /**
   * Automatically detect CI/CD execution context from environment variables
   */
  detectContext(): ExecutionContext {
    const context: ExecutionContext = {
      timestamp: new Date(),
    };

    // Detect CI/CD platform
    context.ciPlatform = this.detectPlatform();

    // Extract context based on platform
    switch (context.ciPlatform) {
      case 'github-actions':
        context.buildId = process.env.GITHUB_RUN_ID;
        context.runId = process.env.GITHUB_RUN_ID;
        context.commitSha = process.env.GITHUB_SHA;
        context.branch = process.env.GITHUB_REF?.replace('refs/heads/', '') || process.env.GITHUB_REF;
        context.tag = process.env.GITHUB_REF?.startsWith('refs/tags/') ? process.env.GITHUB_REF.replace('refs/tags/', '') : undefined;
        context.pullRequestNumber = process.env.GITHUB_EVENT_NAME === 'pull_request' 
          ? parseInt(process.env.GITHUB_EVENT_PATH ? require(process.env.GITHUB_EVENT_PATH)?.pull_request?.number : '0', 10) || undefined
          : undefined;
        context.workflowName = process.env.GITHUB_WORKFLOW;
        context.actor = process.env.GITHUB_ACTOR;
        context.repository = process.env.GITHUB_REPOSITORY;
        context.jobName = process.env.GITHUB_JOB;
        break;

      case 'gitlab-ci':
        context.buildId = process.env.CI_PIPELINE_ID;
        context.runId = process.env.CI_JOB_ID;
        context.commitSha = process.env.CI_COMMIT_SHA;
        context.branch = process.env.CI_COMMIT_REF_NAME;
        context.tag = process.env.CI_COMMIT_TAG;
        context.jobName = process.env.CI_JOB_NAME;
        context.actor = process.env.GITLAB_USER_LOGIN;
        context.repository = process.env.CI_PROJECT_PATH;
        break;

      case 'jenkins':
        context.buildId = process.env.BUILD_NUMBER;
        context.runId = process.env.BUILD_ID;
        context.commitSha = process.env.GIT_COMMIT;
        context.branch = process.env.GIT_BRANCH?.replace('origin/', '');
        context.jobName = process.env.JOB_NAME;
        context.actor = process.env.BUILD_USER_ID || process.env.CHANGE_AUTHOR;
        context.repository = process.env.GIT_URL;
        context.pullRequestNumber = process.env.CHANGE_ID ? parseInt(process.env.CHANGE_ID, 10) : undefined;
        break;

      case 'circleci':
        context.buildId = process.env.CIRCLE_BUILD_NUM;
        context.runId = process.env.CIRCLE_WORKFLOW_ID;
        context.commitSha = process.env.CIRCLE_SHA1;
        context.branch = process.env.CIRCLE_BRANCH;
        context.tag = process.env.CIRCLE_TAG;
        context.pullRequestNumber = process.env.CIRCLE_PULL_REQUEST ? 
          parseInt(process.env.CIRCLE_PULL_REQUEST.split('/').pop() || '0', 10) || undefined 
          : undefined;
        context.jobName = process.env.CIRCLE_JOB;
        context.actor = process.env.CIRCLE_USERNAME;
        context.repository = `${process.env.CIRCLE_PROJECT_USERNAME}/${process.env.CIRCLE_PROJECT_REPONAME}`;
        break;

      case 'travis-ci':
        context.buildId = process.env.TRAVIS_BUILD_NUMBER;
        context.runId = process.env.TRAVIS_BUILD_ID;
        context.commitSha = process.env.TRAVIS_COMMIT;
        context.branch = process.env.TRAVIS_BRANCH;
        context.tag = process.env.TRAVIS_TAG;
        context.pullRequestNumber = process.env.TRAVIS_PULL_REQUEST !== 'false' 
          ? parseInt(process.env.TRAVIS_PULL_REQUEST, 10) || undefined 
          : undefined;
        context.jobName = process.env.TRAVIS_JOB_NAME;
        context.actor = process.env.TRAVIS_COMMIT_AUTHOR;
        context.repository = process.env.TRAVIS_REPO_SLUG;
        break;

      case 'azure-devops':
        context.buildId = process.env.BUILD_BUILDID;
        context.runId = process.env.BUILD_BUILDID;
        context.commitSha = process.env.BUILD_SOURCEVERSION;
        context.branch = process.env.BUILD_SOURCEBRANCH?.replace('refs/heads/', '');
        context.tag = process.env.BUILD_SOURCEBRANCH?.startsWith('refs/tags/') 
          ? process.env.BUILD_SOURCEBRANCH.replace('refs/tags/', '') 
          : undefined;
        context.pullRequestNumber = process.env.SYSTEM_PULLREQUEST_PULLREQUESTID 
          ? parseInt(process.env.SYSTEM_PULLREQUEST_PULLREQUESTID, 10) 
          : undefined;
        context.jobName = process.env.AGENT_JOBNAME;
        context.actor = process.env.BUILD_REQUESTEDFOR;
        context.repository = process.env.BUILD_REPOSITORY_NAME;
        context.workflowName = process.env.BUILD_DEFINITIONNAME;
        break;

      default:
        // Try to extract common environment variables
        context.buildId = process.env.CI_BUILD_ID || process.env.BUILD_ID || process.env.BUILD_NUMBER;
        context.runId = process.env.CI_RUN_ID || process.env.RUN_ID;
        context.commitSha = process.env.CI_COMMIT_SHA || process.env.COMMIT_SHA || process.env.GIT_COMMIT;
        context.branch = process.env.CI_BRANCH || process.env.BRANCH || process.env.GIT_BRANCH?.replace('origin/', '');
        context.tag = process.env.CI_TAG || process.env.TAG;
        context.jobName = process.env.CI_JOB_NAME || process.env.JOB_NAME;
        context.actor = process.env.CI_ACTOR || process.env.ACTOR;
        context.repository = process.env.CI_REPOSITORY || process.env.REPOSITORY;
        break;
    }

    // Set environment if available
    context.environment = process.env.NODE_ENV || process.env.ENVIRONMENT || 'development';

    // Log detected context
    this.logger.debug(`Detected CI/CD context: ${JSON.stringify(context, null, 2)}`);

    return context;
  }

  /**
   * Detect CI/CD platform from environment variables
   */
  private detectPlatform(): ExecutionContext['ciPlatform'] {
    if (process.env.GITHUB_ACTIONS === 'true' || process.env.GITHUB_RUN_ID) {
      return 'github-actions';
    }
    if (process.env.GITLAB_CI === 'true' || process.env.CI_PIPELINE_ID) {
      return 'gitlab-ci';
    }
    if (process.env.JENKINS_URL || process.env.BUILD_NUMBER) {
      return 'jenkins';
    }
    if (process.env.CIRCLECI === 'true' || process.env.CIRCLE_BUILD_NUM) {
      return 'circleci';
    }
    if (process.env.TRAVIS === 'true' || process.env.TRAVIS_BUILD_ID) {
      return 'travis-ci';
    }
    if (process.env.SYSTEM_TEAMFOUNDATIONCOLLECTIONURI || process.env.BUILD_BUILDID) {
      return 'azure-devops';
    }
    if (process.env.CI === 'true') {
      return 'unknown'; // Generic CI detected
    }
    return undefined; // Not in CI/CD environment
  }

  /**
   * Validate execution context
   */
  validateContext(context: ExecutionContext): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!context.ciPlatform) {
      errors.push('CI/CD platform not detected');
    }

    if (!context.commitSha && !context.buildId) {
      errors.push('Neither commit SHA nor build ID is available');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Merge provided context with detected context (provided takes precedence)
   */
  mergeContext(provided: Partial<ExecutionContext>, detected: ExecutionContext): ExecutionContext {
    return {
      ...detected,
      ...provided,
      // Special handling for timestamp
      timestamp: provided.timestamp || detected.timestamp || new Date(),
    };
  }
}

