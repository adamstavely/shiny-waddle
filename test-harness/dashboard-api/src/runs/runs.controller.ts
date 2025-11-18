import {
  Controller,
  Get,
  Param,
  Query,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { RunsService } from './runs.service';
import { Public } from '../auth/decorators/public.decorator';

@Controller('api/v1/runs')
export class RunsController {
  constructor(private readonly runsService: RunsService) {}

  @Public()
  @Get()
  @HttpCode(HttpStatus.OK)
  async findAll(
    @Query('applicationId') applicationId?: string,
    @Query('batteryId') batteryId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
  ) {
    return this.runsService.findAll({
      applicationId,
      batteryId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      limit: limit ? parseInt(limit) : undefined,
    });
  }

  @Public()
  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async findOne(@Param('id') id: string) {
    return this.runsService.findOne(id);
  }
}

