import { Controller, Get, Post, Put, Delete, Param, Body, HttpStatus, HttpException } from '@nestjs/common';
import { CloudProviderService } from './cloud-provider.service';
import { CloudProviderConfig, MultiCloudFinding } from '../../../../heimdall-framework/services/multi-cloud-integration';

@Controller('api/integrations/cloud-providers')
export class CloudProviderController {
  constructor(private readonly service: CloudProviderService) {}

  @Post()
  async createProvider(@Body() config: CloudProviderConfig) {
    return this.service.createProvider(config);
  }

  @Get()
  async findAllProviders() {
    return this.service.findAllProviders();
  }

  @Get(':provider')
  async findOneProvider(@Param('provider') provider: string) {
    return this.service.findOneProvider(provider);
  }

  @Put(':provider')
  async updateProvider(@Param('provider') provider: string, @Body() updates: Partial<CloudProviderConfig>) {
    return this.service.updateProvider(provider, updates);
  }

  @Delete(':provider')
  async deleteProvider(@Param('provider') provider: string) {
    await this.service.deleteProvider(provider);
    return { message: 'Provider deleted' };
  }

  @Post(':provider/normalize')
  async normalizeFindings(@Param('provider') provider: string, @Body() rawFindings: any[]) {
    return this.service.normalizeFindings(provider, rawFindings);
  }

  @Post('aggregate')
  async aggregateFindings(@Body() providerFindings: Record<string, any[]>) {
    return this.service.aggregateFindings(providerFindings);
  }

  @Post('summaries')
  async getProviderSummaries(@Body() findings: MultiCloudFinding[]) {
    const summaries = await this.service.getProviderSummaries(findings);
    return Object.fromEntries(summaries);
  }

  @Post('duplicates')
  async findCrossCloudDuplicates(@Body() findings: MultiCloudFinding[]) {
    const duplicates = await this.service.findCrossCloudDuplicates(findings);
    return Object.fromEntries(duplicates);
  }
}

