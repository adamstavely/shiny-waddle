import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { RealtimeService } from './realtime.service';
import { WebhookPayload } from '../../../heimdall-framework/services/realtime-ingestion';

@Controller('api/v1/realtime')
export class RealtimeController {
  private readonly logger = new Logger(RealtimeController.name);

  constructor(private readonly realtimeService: RealtimeService) {}

  /**
   * Receive webhook payload from scanner
   * POST /api/v1/realtime/webhook
   */
  @Post('webhook')
  @HttpCode(HttpStatus.OK)
  async receiveWebhook(@Body() payload: WebhookPayload) {
    this.logger.log(`Received webhook from scanner: ${payload.scannerId}`);
    
    try {
      const findings = await this.realtimeService.processWebhook(payload);
      return {
        success: true,
        findingsCount: findings.length,
        findings: findings.map(f => ({
          id: f.id,
          title: f.title,
          severity: f.severity,
          riskScore: f.riskScore,
        })),
      };
    } catch (error: any) {
      this.logger.error(`Failed to process webhook:`, error);
      throw error;
    }
  }

  /**
   * Get ingestion statistics
   * GET /api/v1/realtime/stats
   */
  @Get('stats')
  getStats() {
    return this.realtimeService.getStats();
  }

  /**
   * Start ingestion service
   * POST /api/v1/realtime/start
   */
  @Post('start')
  @HttpCode(HttpStatus.OK)
  start() {
    this.realtimeService.start();
    return {
      success: true,
      message: 'Real-time ingestion service started',
      stats: this.realtimeService.getStats(),
    };
  }

  /**
   * Stop ingestion service
   * POST /api/v1/realtime/stop
   */
  @Post('stop')
  @HttpCode(HttpStatus.OK)
  stop() {
    this.realtimeService.stop();
    return {
      success: true,
      message: 'Real-time ingestion service stopped',
      stats: this.realtimeService.getStats(),
    };
  }

  /**
   * Get service status
   * GET /api/v1/realtime/status
   */
  @Get('status')
  getStatus() {
    return {
      isRunning: this.realtimeService.isServiceRunning(),
      stats: this.realtimeService.getStats(),
    };
  }
}
