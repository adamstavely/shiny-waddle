import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
  ValidationPipe,
} from '@nestjs/common';
import { PlatformConfigService } from './platform-config.service';
import { CreateBaselineDto } from './dto/create-baseline.dto';

@Controller('api/v1/platform-config')
export class PlatformConfigController {
  private readonly logger = new Logger(PlatformConfigController.name);

  constructor(private readonly platformConfigService: PlatformConfigService) {}

  @Get('baselines')
  @HttpCode(HttpStatus.OK)
  async getBaselines() {
    this.logger.log('Fetching all platform config baselines');
    return this.platformConfigService.getBaselines();
  }

  @Post('baselines')
  @HttpCode(HttpStatus.CREATED)
  async createBaseline(@Body(ValidationPipe) dto: CreateBaselineDto) {
    this.logger.log(`Creating platform config baseline: ${dto.name}`);
    return this.platformConfigService.createBaseline(dto);
  }

  @Get('baselines/:id')
  @HttpCode(HttpStatus.OK)
  async getBaseline(@Param('id') id: string) {
    this.logger.log(`Fetching baseline: ${id}`);
    return this.platformConfigService.getBaseline(id);
  }

  @Put('baselines/:id')
  @HttpCode(HttpStatus.OK)
  async updateBaseline(@Param('id') id: string, @Body(ValidationPipe) dto: Partial<CreateBaselineDto>) {
    this.logger.log(`Updating baseline: ${id}`);
    return this.platformConfigService.updateBaseline(id, dto);
  }

  @Delete('baselines/:id')
  @HttpCode(HttpStatus.OK)
  async deleteBaseline(@Param('id') id: string) {
    this.logger.log(`Deleting baseline: ${id}`);
    return this.platformConfigService.deleteBaseline(id);
  }

  @Post('baselines/:id/compare')
  @HttpCode(HttpStatus.OK)
  async compareBaseline(@Param('id') id: string, @Body() currentConfig: any) {
    this.logger.log(`Comparing baseline ${id} with current config`);
    return this.platformConfigService.compareBaseline(id, currentConfig);
  }

  @Post('baselines/:id/detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(@Param('id') id: string, @Body() currentConfig: any) {
    this.logger.log(`Detecting drift for baseline ${id}`);
    return this.platformConfigService.detectDrift(id, currentConfig);
  }
}

