import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { CICDService, GitHubConfig, JenkinsConfig } from './cicd.service';

@Controller('api/cicd')
export class CICDController {
  constructor(private readonly service: CICDService) {}

  // GitHub Actions
  @Get('github/config')
  async getGitHubConfig() {
    return this.service.getGitHubConfig();
  }

  @Post('github/config')
  async saveGitHubConfig(@Body() config: GitHubConfig) {
    return this.service.saveGitHubConfig(config);
  }

  @Get('github/runs')
  async getGitHubRuns() {
    return this.service.getGitHubRuns();
  }

  @Get('github/runs/:id')
  async getGitHubRun(@Param('id') id: string) {
    const run = await this.service.getGitHubRun(id);
    if (!run) {
      throw new HttpException('Run not found', HttpStatus.NOT_FOUND);
    }
    return run;
  }

  // Jenkins
  @Get('jenkins/config')
  async getJenkinsConfig() {
    return this.service.getJenkinsConfig();
  }

  @Post('jenkins/config')
  async saveJenkinsConfig(@Body() config: JenkinsConfig) {
    return this.service.saveJenkinsConfig(config);
  }

  @Get('jenkins/builds')
  async getJenkinsBuilds() {
    return this.service.getJenkinsBuilds();
  }

  @Get('jenkins/builds/:id')
  async getJenkinsBuild(@Param('id') id: string) {
    const build = await this.service.getJenkinsBuild(id);
    if (!build) {
      throw new HttpException('Build not found', HttpStatus.NOT_FOUND);
    }
    return build;
  }

  // Global Settings
  @Get('settings')
  async getSettings() {
    return this.service.getSettings();
  }

  @Post('settings')
  async saveSettings(@Body() settings: any) {
    return this.service.saveSettings(settings);
  }
}

