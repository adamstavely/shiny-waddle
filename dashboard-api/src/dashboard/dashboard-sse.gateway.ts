import { Injectable, Logger } from '@nestjs/common';
import { Subject, Observable } from 'rxjs';

export interface DashboardUpdate {
  type: 'dashboard' | 'test-result' | 'compliance-score' | 'violation' | 'notification';
  data: any;
  timestamp: Date;
}

@Injectable()
export class DashboardSSEGateway {
  private readonly logger = new Logger(DashboardSSEGateway.name);
  private readonly updateSubject = new Subject<DashboardUpdate>();
  private readonly clients = new Map<string, (data: string) => void>();

  /**
   * Get observable for dashboard updates
   */
  getUpdates(): Observable<DashboardUpdate> {
    return this.updateSubject.asObservable();
  }

  /**
   * Broadcast update to all connected clients
   */
  broadcast(update: DashboardUpdate): void {
    this.logger.debug(`Broadcasting update: ${update.type}`);
    this.updateSubject.next(update);
    
    // Send to all connected SSE clients
    const message = `data: ${JSON.stringify(update)}\n\n`;
    this.clients.forEach((send, clientId) => {
      try {
        send(message);
      } catch (error) {
        this.logger.error(`Error sending to client ${clientId}:`, error);
        this.clients.delete(clientId);
      }
    });
  }

  /**
   * Register a new SSE client
   */
  registerClient(clientId: string, send: (data: string) => void): void {
    this.clients.set(clientId, send);
    this.logger.debug(`Client ${clientId} registered. Total clients: ${this.clients.size}`);
  }

  /**
   * Unregister a client
   */
  unregisterClient(clientId: string): void {
    this.clients.delete(clientId);
    this.logger.debug(`Client ${clientId} unregistered. Total clients: ${this.clients.size}`);
  }

  /**
   * Get number of connected clients
   */
  getClientCount(): number {
    return this.clients.size;
  }
}

