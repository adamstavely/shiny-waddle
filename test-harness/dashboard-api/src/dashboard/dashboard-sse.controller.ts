import { Controller, Get, Res, Req, UseGuards, Query } from '@nestjs/common';
import { Response, Request } from 'express';
import { DashboardSSEGateway } from './dashboard-sse.gateway';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { v4 as uuidv4 } from 'uuid';

@Controller('api/v1/dashboard')
export class DashboardSSEController {
  constructor(private readonly sseGateway: DashboardSSEGateway) {}

  @Get('stream')
  async streamDashboard(
    @Res() res: Response,
    @Req() req: Request,
    @Query('filters') filters?: string,
    @Query('token') token?: string,
  ): Promise<void> {
    // Note: EventSource doesn't support custom headers, so we accept token in query string
    // In production, consider using a more secure method or WebSocket with proper auth
    if (token) {
      // Validate token here if needed
      // For now, we'll rely on the JWT guard being applied at a different level
    }
    const clientId = uuidv4();
    
    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable nginx buffering
    
    // Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connected', clientId, timestamp: new Date() })}\n\n`);

    // Register client
    const send = (data: string) => {
      try {
        res.write(data);
      } catch (error) {
        // Client disconnected
        this.sseGateway.unregisterClient(clientId);
      }
    };

    this.sseGateway.registerClient(clientId, send);

    // Send heartbeat every 30 seconds to keep connection alive
    const heartbeatInterval = setInterval(() => {
      try {
        res.write(`: heartbeat\n\n`);
      } catch (error) {
        clearInterval(heartbeatInterval);
        this.sseGateway.unregisterClient(clientId);
      }
    }, 30000);

    // Handle client disconnect
    req.on('close', () => {
      clearInterval(heartbeatInterval);
      this.sseGateway.unregisterClient(clientId);
      res.end();
    });

    // Subscribe to updates
    const subscription = this.sseGateway.getUpdates().subscribe((update) => {
      // Apply filters if provided
      if (filters) {
        try {
          const filterObj = JSON.parse(filters);
          if (filterObj.applicationId && update.data?.applicationId !== filterObj.applicationId) {
            return;
          }
          if (filterObj.teamId && update.data?.teamId !== filterObj.teamId) {
            return;
          }
        } catch (e) {
          // Invalid filters, send all updates
        }
      }

      send(`data: ${JSON.stringify(update)}\n\n`);
    });

    // Cleanup on disconnect
    req.on('close', () => {
      subscription.unsubscribe();
    });
  }
}

