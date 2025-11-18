import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  Query,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { ComplianceSnapshotsService } from './compliance-snapshots.service';

@Controller('api/v1/compliance-snapshots')
export class ComplianceSnapshotsController {
  private readonly logger = new Logger(ComplianceSnapshotsController.name);

  constructor(private readonly complianceSnapshotsService: ComplianceSnapshotsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Query('applicationId') applicationId?: string,
    @Query('limit') limit?: string,
  ) {
    return this.complianceSnapshotsService.findAll({
      applicationId,
      limit: limit ? parseInt(limit, 10) : undefined,
    });
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() dto: { name?: string; applicationIds?: string[] }) {
    this.logger.log(`Creating compliance snapshot: ${dto.name || 'Unnamed'}`);
    return this.complianceSnapshotsService.create(dto);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(@Param('id') id: string) {
    return this.complianceSnapshotsService.findOne(id);
  }

  @Get('compare/:id1/:id2')
  @HttpCode(HttpStatus.OK)
  async compare(@Param('id1') id1: string, @Param('id2') id2: string) {
    return this.complianceSnapshotsService.compare(id1, id2);
  }
}

