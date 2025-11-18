import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
  ValidationPipe,
} from '@nestjs/common';
import { StandardsMappingService } from './standards-mapping.service';
import { CreateMappingDto } from './dto/create-mapping.dto';

@Controller('api/v1/standards')
export class StandardsMappingController {
  private readonly logger = new Logger(StandardsMappingController.name);

  constructor(private readonly standardsMappingService: StandardsMappingService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getStandards() {
    this.logger.log('Fetching all compliance standards');
    return this.standardsMappingService.getStandards();
  }

  @Get(':id/mappings')
  @HttpCode(HttpStatus.OK)
  async getMappings(@Param('id') id: string) {
    this.logger.log(`Fetching mappings for standard: ${id}`);
    return this.standardsMappingService.getMappings(id);
  }

  @Post(':id/mappings')
  @HttpCode(HttpStatus.CREATED)
  async createMapping(@Param('id') id: string, @Body(ValidationPipe) dto: CreateMappingDto) {
    this.logger.log(`Creating mapping for standard ${id} to policy ${dto.policyId}`);
    return this.standardsMappingService.createMapping(id, dto);
  }

  @Delete(':id/mappings/:mappingId')
  @HttpCode(HttpStatus.OK)
  async deleteMapping(@Param('id') id: string, @Param('mappingId') mappingId: string) {
    this.logger.log(`Deleting mapping ${mappingId} for standard ${id}`);
    return this.standardsMappingService.deleteMapping(id, mappingId);
  }

  @Get('policies/:policyId')
  @HttpCode(HttpStatus.OK)
  async getStandardsForPolicy(@Param('policyId') policyId: string) {
    this.logger.log(`Fetching standards for policy: ${policyId}`);
    return this.standardsMappingService.getStandardsForPolicy(policyId);
  }
}

