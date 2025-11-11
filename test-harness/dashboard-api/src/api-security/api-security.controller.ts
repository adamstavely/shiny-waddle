import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import {
  CreateAPISecurityConfigDto,
  CreateAPIEndpointDto,
  CreateAPISecurityTestDto,
  UpdateAPISecurityConfigDto,
} from './dto/create-api-security.dto';
import {
  APISecurityTestConfigEntity,
  APIEndpointEntity,
  APISecurityTestResultEntity,
} from './entities/api-security.entity';

@Controller('api/api-security')
export class ApiSecurityController {
  constructor(private readonly apiSecurityService: ApiSecurityService) {}

  @Get()
  async getSummary() {
    const [configs, endpoints, results] = await Promise.all([
      this.apiSecurityService.findAllConfigs(),
      this.apiSecurityService.findAllEndpoints(),
      this.apiSecurityService.findAllResults(),
    ]);
    return {
      configs: configs.length,
      endpoints: endpoints.length,
      results: results.length,
    };
  }

  // Configs
  @Post('configs')
  @HttpCode(HttpStatus.CREATED)
  async createConfig(
    @Body(ValidationPipe) dto: CreateAPISecurityConfigDto,
  ): Promise<APISecurityTestConfigEntity> {
    return this.apiSecurityService.createConfig(dto);
  }

  @Get('configs')
  async findAllConfigs(): Promise<APISecurityTestConfigEntity[]> {
    return this.apiSecurityService.findAllConfigs();
  }

  @Get('configs/:id')
  async findOneConfig(@Param('id') id: string): Promise<APISecurityTestConfigEntity> {
    return this.apiSecurityService.findOneConfig(id);
  }

  @Patch('configs/:id')
  async updateConfig(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateAPISecurityConfigDto,
  ): Promise<APISecurityTestConfigEntity> {
    return this.apiSecurityService.updateConfig(id, dto);
  }

  @Delete('configs/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeConfig(@Param('id') id: string): Promise<void> {
    return this.apiSecurityService.removeConfig(id);
  }

  // Endpoints
  @Post('endpoints')
  @HttpCode(HttpStatus.CREATED)
  async createEndpoint(
    @Body(ValidationPipe) dto: CreateAPIEndpointDto,
  ): Promise<APIEndpointEntity> {
    return this.apiSecurityService.createEndpoint(dto);
  }

  @Get('endpoints')
  async findAllEndpoints(
    @Query('configId') configId?: string,
  ): Promise<APIEndpointEntity[]> {
    return this.apiSecurityService.findAllEndpoints(configId);
  }

  @Get('endpoints/:id')
  async findOneEndpoint(@Param('id') id: string): Promise<APIEndpointEntity> {
    return this.apiSecurityService.findOneEndpoint(id);
  }

  @Delete('endpoints/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeEndpoint(@Param('id') id: string): Promise<void> {
    return this.apiSecurityService.removeEndpoint(id);
  }

  // Test Results
  @Post('tests')
  @HttpCode(HttpStatus.CREATED)
  async createTestResult(
    @Body(ValidationPipe) dto: CreateAPISecurityTestDto,
  ): Promise<APISecurityTestResultEntity> {
    return this.apiSecurityService.createTestResult(dto);
  }

  @Get('results')
  async findAllResults(
    @Query('configId') configId?: string,
    @Query('endpointId') endpointId?: string,
    @Query('testType') testType?: string,
    @Query('status') status?: string,
  ): Promise<APISecurityTestResultEntity[]> {
    return this.apiSecurityService.findAllResults(configId, endpointId, testType, status);
  }

  @Get('results/:id')
  async findOneResult(@Param('id') id: string): Promise<APISecurityTestResultEntity> {
    return this.apiSecurityService.findOneResult(id);
  }
}

