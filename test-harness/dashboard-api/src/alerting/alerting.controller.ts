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
  Logger,
} from '@nestjs/common';
import { AlertingService } from './alerting.service';
import { CreateAlertRuleDto } from './dto/create-alert-rule.dto';
import { UpdateAlertRuleDto } from './dto/update-alert-rule.dto';
import { CreateAlertChannelDto } from './dto/create-alert-channel.dto';
import { UpdateAlertChannelDto } from './dto/update-alert-channel.dto';
import { AlertQueryDto } from './dto/alert-query.dto';
import { UnifiedFinding } from '../../../../core/unified-finding-schema';

@Controller('api/alerting')
export class AlertingController {
  private readonly logger = new Logger(AlertingController.name);

  constructor(private readonly alertingService: AlertingService) {}

  // Alert Rules

  @Post('rules')
  @HttpCode(HttpStatus.CREATED)
  async createRule(@Body() dto: CreateAlertRuleDto) {
    return this.alertingService.createRule(dto);
  }

  @Get('rules')
  async getRules() {
    return this.alertingService.getRules();
  }

  @Get('rules/:id')
  async getRule(@Param('id') id: string) {
    return this.alertingService.getRuleById(id);
  }

  @Put('rules/:id')
  async updateRule(@Param('id') id: string, @Body() dto: UpdateAlertRuleDto) {
    return this.alertingService.updateRule(id, dto);
  }

  @Delete('rules/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteRule(@Param('id') id: string) {
    await this.alertingService.deleteRule(id);
  }

  @Post('rules/:id/test')
  async testRule(@Param('id') id: string, @Body() finding: UnifiedFinding) {
    return this.alertingService.testRule(id, finding);
  }

  // Alert Channels

  @Post('channels')
  @HttpCode(HttpStatus.CREATED)
  async createChannel(@Body() dto: CreateAlertChannelDto) {
    return this.alertingService.createChannel(dto);
  }

  @Get('channels')
  async getChannels() {
    return this.alertingService.getChannels();
  }

  @Get('channels/:id')
  async getChannel(@Param('id') id: string) {
    return this.alertingService.getChannelById(id);
  }

  @Put('channels/:id')
  async updateChannel(@Param('id') id: string, @Body() dto: UpdateAlertChannelDto) {
    return this.alertingService.updateChannel(id, dto);
  }

  @Delete('channels/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteChannel(@Param('id') id: string) {
    await this.alertingService.deleteChannel(id);
  }

  // Alerts

  @Get('alerts')
  async getAlerts(@Query() query: AlertQueryDto) {
    return this.alertingService.queryAlerts(query);
  }

  @Get('alerts/:id')
  async getAlert(@Param('id') id: string) {
    return this.alertingService.getAlertById(id);
  }

  @Post('alerts/:id/retry')
  async retryAlert(@Param('id') id: string) {
    return this.alertingService.retryAlert(id);
  }
}
