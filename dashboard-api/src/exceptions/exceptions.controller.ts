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
  Query,
} from '@nestjs/common';
import { ExceptionsService } from './exceptions.service';
import { CreateExceptionDto } from './dto/create-exception.dto';
import { CreateAllowlistDto } from './dto/create-allowlist.dto';

@Controller('api/v1/exceptions')
export class ExceptionsController {
  private readonly logger = new Logger(ExceptionsController.name);

  constructor(private readonly exceptionsService: ExceptionsService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getExceptions(
    @Query('policyId') policyId?: string,
    @Query('status') status?: string,
  ) {
    this.logger.log(`Fetching exceptions: policyId=${policyId}, status=${status}`);
    return this.exceptionsService.getExceptions(policyId, status);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createException(@Body(ValidationPipe) dto: CreateExceptionDto) {
    this.logger.log(`Creating exception: ${dto.name}`);
    return this.exceptionsService.createException(dto);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateException(@Param('id') id: string, @Body(ValidationPipe) dto: Partial<CreateExceptionDto>) {
    this.logger.log(`Updating exception: ${id}`);
    return this.exceptionsService.updateException(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteException(@Param('id') id: string) {
    this.logger.log(`Deleting exception: ${id}`);
    return this.exceptionsService.deleteException(id);
  }

  @Post(':id/approve')
  @HttpCode(HttpStatus.OK)
  async approveException(@Param('id') id: string, @Body() body: { approver: string; notes?: string }) {
    this.logger.log(`Approving exception: ${id}`);
    return this.exceptionsService.approveException(id, body.approver, body.notes);
  }

  @Get('allowlists')
  @HttpCode(HttpStatus.OK)
  async getAllowlists() {
    this.logger.log('Fetching all allowlists');
    return this.exceptionsService.getAllowlists();
  }

  @Post('allowlists')
  @HttpCode(HttpStatus.CREATED)
  async createAllowlist(@Body(ValidationPipe) dto: CreateAllowlistDto) {
    this.logger.log(`Creating allowlist: ${dto.name}`);
    return this.exceptionsService.createAllowlist(dto);
  }

  @Put('allowlists/:id')
  @HttpCode(HttpStatus.OK)
  async updateAllowlist(@Param('id') id: string, @Body(ValidationPipe) dto: Partial<CreateAllowlistDto>) {
    this.logger.log(`Updating allowlist: ${id}`);
    return this.exceptionsService.updateAllowlist(id, dto);
  }

  @Delete('allowlists/:id')
  @HttpCode(HttpStatus.OK)
  async deleteAllowlist(@Param('id') id: string) {
    this.logger.log(`Deleting allowlist: ${id}`);
    return this.exceptionsService.deleteAllowlist(id);
  }
}

