import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface GitHubConfig {
  enabled: boolean;
  repository: string;
  workflowFile: string;
  complianceThreshold: number;
  blockMerges: boolean;
  prComments: boolean;
  tokenSecret?: string;
}

export interface JenkinsConfig {
  enabled: boolean;
  url: string;
  jobName: string;
  complianceThreshold: number;
  blockBuilds: boolean;
  username?: string;
  apiToken?: string;
  pipelineScript?: string;
}

export interface CICDRun {
  id: string;
  name: string;
  status: 'success' | 'failure' | 'pending';
  complianceScore: number;
  compliancePassed: boolean;
  blocked: boolean;
  duration: number;
  startedAt: Date;
  completedAt?: Date;
  prNumber?: number;
  buildNumber?: number;
  branch?: string;
  commit?: string;
  testResults?: any[];
  logs?: string;
}

@Injectable()
export class CICDService {
  private readonly configPath = path.join(process.cwd(), '..', '..', 'cicd-config.json');
  private githubConfig: GitHubConfig | null = null;
  private jenkinsConfig: JenkinsConfig | null = null;
  private githubRuns: CICDRun[] = [];
  private jenkinsBuilds: CICDRun[] = [];
  private globalSettings: any = {
    minComplianceScore: 100,
    blockOnFailure: true,
    blockOnThreshold: true,
    requireApproval: false,
    notifyOnFailure: true,
    notifyOnBlock: true,
    notificationChannels: [],
  };

  constructor() {
    this.loadConfig();
  }

  private async loadConfig() {
    try {
      const data = await fs.readFile(this.configPath, 'utf-8');
      const config = JSON.parse(data);
      this.githubConfig = config.github || null;
      this.jenkinsConfig = config.jenkins || null;
      this.githubRuns = (config.githubRuns || []).map((r: any) => ({
        ...r,
        startedAt: new Date(r.startedAt),
        completedAt: r.completedAt ? new Date(r.completedAt) : undefined,
      }));
      this.jenkinsBuilds = (config.jenkinsBuilds || []).map((b: any) => ({
        ...b,
        startedAt: new Date(b.startedAt),
        completedAt: b.completedAt ? new Date(b.completedAt) : undefined,
      }));
      this.globalSettings = { ...this.globalSettings, ...(config.settings || {}) };
    } catch (error) {
      // Config file doesn't exist, use defaults
    }
  }

  private async saveConfig() {
    try {
      await fs.writeFile(
        this.configPath,
        JSON.stringify({
          github: this.githubConfig,
          jenkins: this.jenkinsConfig,
          githubRuns: this.githubRuns,
          jenkinsBuilds: this.jenkinsBuilds,
          settings: this.globalSettings,
        }, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Failed to save config:', error);
    }
  }

  // GitHub Actions
  async getGitHubConfig(): Promise<GitHubConfig | null> {
    return this.githubConfig;
  }

  async saveGitHubConfig(config: GitHubConfig): Promise<GitHubConfig> {
    this.githubConfig = config;
    await this.saveConfig();
    return config;
  }

  async getGitHubRuns(): Promise<CICDRun[]> {
    return this.githubRuns;
  }

  async getGitHubRun(id: string): Promise<CICDRun | null> {
    return this.githubRuns.find(r => r.id === id) || null;
  }

  // Jenkins
  async getJenkinsConfig(): Promise<JenkinsConfig | null> {
    return this.jenkinsConfig;
  }

  async saveJenkinsConfig(config: JenkinsConfig): Promise<JenkinsConfig> {
    this.jenkinsConfig = config;
    await this.saveConfig();
    return config;
  }

  async getJenkinsBuilds(): Promise<CICDRun[]> {
    return this.jenkinsBuilds;
  }

  async getJenkinsBuild(id: string): Promise<CICDRun | null> {
    return this.jenkinsBuilds.find(b => b.id === id) || null;
  }

  // Global Settings
  async getSettings(): Promise<any> {
    return this.globalSettings;
  }

  async saveSettings(settings: any): Promise<any> {
    this.globalSettings = { ...this.globalSettings, ...settings };
    await this.saveConfig();
    return this.globalSettings;
  }

  // Simulate run creation (in real implementation, this would be triggered by webhooks)
  async createGitHubRun(run: Partial<CICDRun>): Promise<CICDRun> {
    const newRun: CICDRun = {
      id: `github-${Date.now()}`,
      name: run.name || 'Compliance Tests',
      status: run.status || 'pending',
      complianceScore: run.complianceScore || 0,
      compliancePassed: (run.complianceScore || 0) >= (this.githubConfig?.complianceThreshold || 100),
      blocked: false,
      duration: run.duration || 0,
      startedAt: run.startedAt || new Date(),
      ...run,
    };
    newRun.blocked = !newRun.compliancePassed && (this.githubConfig?.blockMerges || false);
    this.githubRuns.unshift(newRun);
    await this.saveConfig();
    return newRun;
  }

  async createJenkinsBuild(build: Partial<CICDRun>): Promise<CICDRun> {
    const newBuild: CICDRun = {
      id: `jenkins-${Date.now()}`,
      name: build.name || 'Compliance Tests',
      status: build.status || 'pending',
      complianceScore: build.complianceScore || 0,
      compliancePassed: (build.complianceScore || 0) >= (this.jenkinsConfig?.complianceThreshold || 100),
      blocked: false,
      duration: build.duration || 0,
      startedAt: build.startedAt || new Date(),
      ...build,
    };
    newBuild.blocked = !newBuild.compliancePassed && (this.jenkinsConfig?.blockBuilds || false);
    this.jenkinsBuilds.unshift(newBuild);
    await this.saveConfig();
    return newBuild;
  }
}

