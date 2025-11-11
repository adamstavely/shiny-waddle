import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { DistributedSystemsService, RegionConfig, DistributedTestRequest } from './distributed-systems.service';

@Controller('api/distributed-systems')
export class DistributedSystemsController {
  constructor(private readonly service: DistributedSystemsService) {}

  // Region endpoints
  @Get('regions')
  async getRegions() {
    return this.service.getRegions();
  }

  @Get('regions/:id')
  async getRegion(@Param('id') id: string) {
    const region = await this.service.getRegion(id);
    if (!region) {
      throw new HttpException('Region not found', HttpStatus.NOT_FOUND);
    }
    return region;
  }

  @Post('regions')
  async createRegion(@Body() region: RegionConfig) {
    return this.service.createRegion(region);
  }

  @Patch('regions/:id')
  async updateRegion(@Param('id') id: string, @Body() region: Partial<RegionConfig>) {
    return this.service.updateRegion(id, region);
  }

  @Delete('regions/:id')
  async deleteRegion(@Param('id') id: string) {
    await this.service.deleteRegion(id);
    return { success: true };
  }

  // Test endpoints
  @Get('tests')
  async getTestResults() {
    return this.service.getTestResults();
  }

  @Get('tests/:id')
  async getTestResult(@Param('id') id: string) {
    const result = await this.service.getTestResult(id);
    if (!result) {
      throw new HttpException('Test result not found', HttpStatus.NOT_FOUND);
    }
    return result;
  }

  @Post('tests/run')
  async runTest(@Body() request: DistributedTestRequest) {
    return this.service.runTest(request);
  }

  @Delete('tests/:id')
  async deleteTestResult(@Param('id') id: string) {
    await this.service.deleteTestResult(id);
    return { success: true };
  }
}

