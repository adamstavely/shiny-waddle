import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Patch,
  Param,
  Body,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { ScheduledReportsService } from './scheduled-reports.service';
import { CreateScheduledReportDto } from './dto/create-scheduled-report.dto';
import { UpdateScheduledReportDto } from './dto/update-scheduled-report.dto';

@Controller('api/scheduled-reports')
export class ScheduledReportsController {
  constructor(
    private readonly scheduledReportsService: ScheduledReportsService,
  ) {}

  @Get()
  async getAllScheduledReports() {
    return this.scheduledReportsService.getAllScheduledReports();
  }

  @Get(':id')
  async getScheduledReportById(@Param('id') id: string) {
    const report = await this.scheduledReportsService.getScheduledReportById(id);
    if (!report) {
      throw new HttpException('Scheduled report not found', HttpStatus.NOT_FOUND);
    }
    return report;
  }

  @Post()
  async createScheduledReport(@Body() dto: CreateScheduledReportDto) {
    try {
      return await this.scheduledReportsService.createScheduledReport(dto);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to create scheduled report',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Put(':id')
  async updateScheduledReport(
    @Param('id') id: string,
    @Body() dto: UpdateScheduledReportDto,
  ) {
    try {
      return await this.scheduledReportsService.updateScheduledReport(id, dto);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to update scheduled report',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Patch(':id/toggle')
  async toggleScheduledReport(
    @Param('id') id: string,
    @Body() body: { enabled: boolean },
  ) {
    try {
      return await this.scheduledReportsService.toggleScheduledReport(id, body.enabled);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to toggle scheduled report',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Delete(':id')
  async deleteScheduledReport(@Param('id') id: string) {
    try {
      await this.scheduledReportsService.deleteScheduledReport(id);
      return { success: true };
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to delete scheduled report',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Post(':id/run-now')
  async runScheduledReportNow(@Param('id') id: string) {
    try {
      const report = await this.scheduledReportsService.getScheduledReportById(id);
      if (!report) {
        throw new HttpException('Scheduled report not found', HttpStatus.NOT_FOUND);
      }

      // Execute immediately
      await this.scheduledReportsService.executeScheduledReportNow(report);
      
      return { success: true, message: 'Report executed successfully' };
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to run scheduled report',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }
}

