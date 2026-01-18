import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  Req,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { TestsService } from './tests.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { TestEntity } from './entities/test.entity';
import { Public } from '../auth/decorators/public.decorator';

/**
 * Route alias controller to support /api/tests (without version prefix)
 * for backward compatibility. Forwards all requests to TestsService.
 */
@Controller('api/tests')
export class TestsAliasController {
  private readonly logger = new Logger(TestsAliasController.name);
  
  constructor(private readonly testsService: TestsService) {}

  @Public()
  @Get()
  async findAll(
    @Query('testType') testType?: string,
    @Query('policyId') policyId?: string,
    @Query('domain') domain?: string,
  ): Promise<TestEntity[]> {
    return this.testsService.findAll({ testType, policyId, domain });
  }

  @Public()
  @Get('by-policy/:policyId')
  async findByPolicy(@Param('policyId') policyId: string): Promise<TestEntity[]> {
    return this.testsService.findByPolicy(policyId);
  }

  @Public()
  @Get('*/versions/:version')
  async findOneVersion(
    @Req() req: any,
    @Param('version') version: string,
  ): Promise<TestEntity> {
    const path = req.url.replace('/api/tests/', '').split('?')[0];
    const testId = path.split('/versions')[0];
    return this.testsService.findOneVersion(testId, parseInt(version, 10));
  }

  @Public()
  @Get('*/versions')
  async getVersionHistory(@Req() req: any) {
    const path = req.url.replace('/api/tests/', '').split('?')[0];
    const testId = path.split('/versions')[0];
    const test = await this.testsService.findOne(testId);
    return test.versionHistory || [];
  }

  @Public()
  @Get('*/used-in-suites')
  @HttpCode(HttpStatus.OK)
  async getUsedInSuites(@Req() req: any): Promise<any[]> {
    const path = req.url.replace('/api/tests/', '').split('?')[0];
    const testId = path.split('/used-in-suites')[0];
    return this.testsService.getUsedInSuites(testId);
  }

  // Regular :id route for normal IDs (UUIDs, etc.) - this should match first
  @Public()
  @Get(':id')
  async findOneById(@Param('id') id: string): Promise<TestEntity> {
    this.logger.debug(`Finding test by ID: ${id}`);
    return this.testsService.findOne(id);
  }

  // Fallback wildcard route for IDs with dots (like test.idp.service_conforms_to_golden_template)
  // This will only match if :id doesn't match (which happens when Express treats dots as file extensions)
  @Public()
  @Get('*')
  async findOneByWildcard(@Req() req: any): Promise<TestEntity> {
    // Handle IDs with dots - extract test ID from the request path
    let path = req.path || req.url;
    this.logger.debug(`Wildcard route matched. Path: ${path}, URL: ${req.url}`);
    
    // Remove query string and the /api/tests prefix
    path = path.replace(/^\/api\/tests\//, '').split('?')[0];
    // Get the first segment (the test ID) - everything before the first slash
    const testId = path.split('/')[0];
    
    this.logger.debug(`Extracted test ID: ${testId}`);
    
    if (!testId || testId === '') {
      throw new Error('Test ID not found in path');
    }
    
    return this.testsService.findOne(testId);
  }


  @Public()
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) createTestDto: CreateTestDto,
  ): Promise<TestEntity> {
    return this.testsService.create(createTestDto);
  }

  @Public()
  @Put('*')
  async update(
    @Req() req: any,
    @Body(ValidationPipe) updateTestDto: UpdateTestDto,
  ): Promise<TestEntity> {
    const path = req.url.replace('/api/tests/', '').split('?')[0];
    const testId = path.split('/')[0];
    const changeReason = 'changeReason' in updateTestDto ? updateTestDto.changeReason : undefined;
    return this.testsService.update(testId, updateTestDto, undefined, changeReason);
  }

  @Public()
  @Delete('*')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Req() req: any): Promise<void> {
    const path = req.url.replace('/api/tests/', '').split('?')[0];
    const testId = path.split('/')[0];
    return this.testsService.remove(testId);
  }
}
