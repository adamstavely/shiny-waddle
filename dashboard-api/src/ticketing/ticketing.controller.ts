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
import { TicketingService } from './ticketing.service';
import { CreateTicketingIntegrationDto } from './dto/create-ticketing-integration.dto';
import { TicketingIntegration, Ticket, CreateTicketDto } from './entities/ticketing.entity';

@Controller('api/ticketing')
export class TicketingController {
  constructor(private readonly ticketingService: TicketingService) {}

  // Integration Management
  @Post('integrations')
  @HttpCode(HttpStatus.CREATED)
  async createIntegration(
    @Body(ValidationPipe) dto: CreateTicketingIntegrationDto
  ): Promise<TicketingIntegration> {
    return this.ticketingService.createIntegration(dto);
  }

  @Get('integrations')
  async findAllIntegrations(): Promise<TicketingIntegration[]> {
    return this.ticketingService.findAllIntegrations();
  }

  @Get('integrations/:id')
  async findOneIntegration(@Param('id') id: string): Promise<TicketingIntegration> {
    return this.ticketingService.findOneIntegration(id);
  }

  @Patch('integrations/:id')
  async updateIntegration(
    @Param('id') id: string,
    @Body() updates: Partial<TicketingIntegration>
  ): Promise<TicketingIntegration> {
    return this.ticketingService.updateIntegration(id, updates);
  }

  @Delete('integrations/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async deleteIntegration(@Param('id') id: string): Promise<void> {
    return this.ticketingService.deleteIntegration(id);
  }

  @Post('integrations/:id/test')
  async testConnection(@Param('id') id: string): Promise<{ success: boolean }> {
    const integration = await this.ticketingService.findOneIntegration(id);
    const success = await this.ticketingService.testConnection(integration);
    return { success };
  }

  // Ticket Management
  @Post('integrations/:integrationId/tickets')
  @HttpCode(HttpStatus.CREATED)
  async createTicket(
    @Param('integrationId') integrationId: string,
    @Body(ValidationPipe) dto: CreateTicketDto
  ): Promise<Ticket> {
    return this.ticketingService.createTicket(integrationId, dto);
  }

  @Get('tickets')
  async findAllTickets(@Query('violationId') violationId?: string): Promise<Ticket[]> {
    return this.ticketingService.findAllTickets(violationId);
  }

  @Get('tickets/:id')
  async findOneTicket(@Param('id') id: string): Promise<Ticket> {
    return this.ticketingService.findOneTicket(id);
  }

  @Post('tickets/:id/sync')
  async syncTicketStatus(@Param('id') id: string): Promise<Ticket> {
    return this.ticketingService.syncTicketStatus(id);
  }
}

