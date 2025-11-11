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
  Query,
  ValidationPipe,
} from '@nestjs/common';
import { ViolationsService } from './violations.service';
import { CreateViolationDto } from './dto/create-violation.dto';
import { UpdateViolationDto } from './dto/update-violation.dto';
import { ViolationEntity, ViolationComment } from './entities/violation.entity';

@Controller('api/violations')
export class ViolationsController {
  constructor(private readonly violationsService: ViolationsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body(ValidationPipe) createViolationDto: CreateViolationDto): Promise<ViolationEntity> {
    return this.violationsService.create(createViolationDto);
  }

  @Get()
  async findAll(
    @Query('severity') severity?: string,
    @Query('type') type?: string,
    @Query('status') status?: string,
    @Query('application') application?: string,
    @Query('team') team?: string,
  ): Promise<ViolationEntity[]> {
    return this.violationsService.findAll(severity, type, status, application, team);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ViolationEntity> {
    return this.violationsService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updateViolationDto: UpdateViolationDto,
  ): Promise<ViolationEntity> {
    return this.violationsService.update(id, updateViolationDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.violationsService.remove(id);
  }

  @Post(':id/comments')
  @HttpCode(HttpStatus.CREATED)
  async addComment(
    @Param('id') id: string,
    @Body('author') author: string,
    @Body('content') content: string,
  ): Promise<ViolationComment> {
    return this.violationsService.addComment(id, author, content);
  }

  @Patch(':id/comments/:commentId')
  async updateComment(
    @Param('id') violationId: string,
    @Param('commentId') commentId: string,
    @Body('content') content: string,
  ): Promise<ViolationComment> {
    return this.violationsService.updateComment(violationId, commentId, content);
  }

  @Delete(':id/comments/:commentId')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteComment(
    @Param('id') violationId: string,
    @Param('commentId') commentId: string,
  ): Promise<void> {
    return this.violationsService.deleteComment(violationId, commentId);
  }
}

