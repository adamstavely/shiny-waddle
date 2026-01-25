import {
  Controller,
  Get,
  Post,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { TemplatesService } from './templates.service';
import { CreateFromTemplateDto } from './dto/create-from-template.dto';

@Controller('api/templates')
export class TemplatesController {
  constructor(private readonly templatesService: TemplatesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async listTemplates() {
    return this.templatesService.listTemplates();
  }

  @Get(':name')
  @HttpCode(HttpStatus.OK)
  async getTemplate(@Param('name') name: string) {
    return this.templatesService.getTemplate(name);
  }

  @Post(':name/create')
  @HttpCode(HttpStatus.CREATED)
  async createFromTemplate(
    @Param('name') name: string,
    @Body(ValidationPipe) dto: Omit<CreateFromTemplateDto, 'templateName'>,
  ) {
    return this.templatesService.createFromTemplate({
      ...dto,
      templateName: name,
    });
  }
}
