import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Query,
} from '@nestjs/common';
import { SLAService } from './sla.service';
import { SLAPolicy, SLAViolation, CreateSLAPolicyDto, SLASeverity } from './entities/sla.entity';

@Controller('api/sla')
export class SLAController {
  constructor(private readonly slaService: SLAService) {}

  // Policy Management
  @Post('policies')
  @HttpCode(HttpStatus.CREATED)
  async createPolicy(@Body(ValidationPipe) dto: CreateSLAPolicyDto): Promise<SLAPolicy> {
    return this.slaService.createPolicy(dto);
  }

  @Get('policies')
  async findAllPolicies(): Promise<SLAPolicy[]> {
    return this.slaService.findAllPolicies();
  }

  @Get('policies/:id')
  async findOnePolicy(@Param('id') id: string): Promise<SLAPolicy> {
    return this.slaService.findOnePolicy(id);
  }

  @Patch('policies/:id')
  async updatePolicy(
    @Param('id') id: string,
    @Body() updates: Partial<SLAPolicy>
  ): Promise<SLAPolicy> {
    return this.slaService.updatePolicy(id, updates);
  }

  @Delete('policies/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deletePolicy(@Param('id') id: string): Promise<void> {
    return this.slaService.deletePolicy(id);
  }

  // SLA Violation Management
  @Post('violations')
  @HttpCode(HttpStatus.CREATED)
  async createSLAViolation(
    @Body() body: { violationId: string; severity: SLASeverity }
  ): Promise<SLAViolation> {
    return this.slaService.createSLAViolation(body.violationId, body.severity);
  }

  @Get('violations')
  async findAllSLAViolations(@Query('violationId') violationId?: string): Promise<SLAViolation[]> {
    return this.slaService.findAllSLAViolations(violationId);
  }

  @Get('violations/:id')
  async findOneSLAViolation(@Param('id') id: string): Promise<SLAViolation> {
    return this.slaService.findOneSLAViolation(id);
  }

  @Post('violations/:id/resolve')
  async resolveSLAViolation(@Param('id') id: string): Promise<SLAViolation> {
    return this.slaService.resolveSLAViolation(id);
  }

  @Get('stats')
  async getSLAStats() {
    return this.slaService.getSLAStats();
  }
}

