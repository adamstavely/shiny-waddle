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
import { IDPKubernetesBaselinesService } from './idp-kubernetes-baselines.service';
import { CreateIDPBaselineDto } from './dto/create-idp-baseline.dto';
import { UpdateIDPBaselineDto } from './dto/update-idp-baseline.dto';
import { CompareBaselineDto } from './dto/compare-baseline.dto';

@Controller('api/v1/idp-kubernetes/baselines')
export class IDPKubernetesBaselinesController {
  private readonly logger = new Logger(IDPKubernetesBaselinesController.name);

  constructor(private readonly idpKubernetesBaselinesService: IDPKubernetesBaselinesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getBaselines() {
    this.logger.log('Fetching all IDP/Kubernetes data protection baselines');
    return this.idpKubernetesBaselinesService.getBaselines();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createBaseline(@Body(ValidationPipe) dto: CreateIDPBaselineDto) {
    this.logger.log(`Creating IDP/Kubernetes data protection baseline: ${dto.name}`);
    return this.idpKubernetesBaselinesService.createBaseline(dto);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getBaseline(@Param('id') id: string) {
    this.logger.log(`Fetching IDP/Kubernetes baseline: ${id}`);
    return this.idpKubernetesBaselinesService.getBaseline(id);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateIDPBaselineDto
  ) {
    this.logger.log(`Updating IDP/Kubernetes baseline: ${id}`);
    return this.idpKubernetesBaselinesService.updateBaseline(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteBaseline(@Param('id') id: string) {
    this.logger.log(`Deleting IDP/Kubernetes baseline: ${id}`);
    return this.idpKubernetesBaselinesService.deleteBaseline(id);
  }

  @Post(':id/compare')
  @HttpCode(HttpStatus.OK)
  async compareBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Comparing IDP/Kubernetes baseline ${id} with current config`);
    return this.idpKubernetesBaselinesService.compareBaseline(id, dto.currentConfig);
  }

  @Post(':id/detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Detecting drift for IDP/Kubernetes baseline ${id}`);
    return this.idpKubernetesBaselinesService.detectDrift(id, dto.currentConfig);
  }
}
