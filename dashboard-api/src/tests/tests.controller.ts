import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { TestsService } from './tests.service';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { TestEntity } from './entities/test.entity';
import { Public } from '../auth/decorators/public.decorator';

@Controller('api/v1/tests')
export class TestsController {
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
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestEntity> {
    return this.testsService.findOne(id);
  }

  @Public()
  @Get(':id/versions')
  async getVersionHistory(@Param('id') id: string) {
    const test = await this.testsService.findOne(id);
    return test.versionHistory || [];
  }

  @Public()
  @Get(':id/versions/:version')
  async findOneVersion(
    @Param('id') id: string,
    @Param('version') version: string,
  ): Promise<TestEntity> {
    return this.testsService.findOneVersion(id, parseInt(version, 10));
  }

  @Public()
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) createTestDto: CreateTestDto,
    // @User() user?: any, // Uncomment when auth is implemented
  ): Promise<TestEntity> {
    // const createdBy = user?.id || user?.email;
    return this.testsService.create(createTestDto);
  }

  @Public()
  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updateTestDto: UpdateTestDto,
    // @User() user?: any, // Uncomment when auth is implemented
  ): Promise<TestEntity> {
    // const changedBy = user?.id || user?.email;
    const changeReason = 'changeReason' in updateTestDto ? updateTestDto.changeReason : undefined;
    return this.testsService.update(id, updateTestDto, undefined, changeReason);
  }

  @Public()
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.testsService.remove(id);
  }

  @Public()
  @Get(':id/used-in-suites')
  @HttpCode(HttpStatus.OK)
  async getUsedInSuites(@Param('id') id: string): Promise<any[]> {
    return this.testsService.getUsedInSuites(id);
  }
}

