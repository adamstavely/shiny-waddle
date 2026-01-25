import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { Application, ApplicationType, ApplicationStatus } from '../applications/entities/application.entity';
import * as fs from 'fs/promises';
import * as path from 'path';

/**
 * ApplicationDataService - Read-only service for accessing application data
 * 
 * This service provides read-only access to application data without dependencies
 * on other services, breaking circular dependencies. Services that only need to
 * read application data should use this service instead of ApplicationsService.
 */
@Injectable()
export class ApplicationDataService {
  private readonly logger = new Logger(ApplicationDataService.name);
  private readonly applicationsFile = path.join(process.cwd(), 'data', 'applications.json');
  private applications: Application[] = [];
  private loadPromise: Promise<void> | null = null;

  constructor() {
    // Load applications asynchronously
    this.loadPromise = this.loadApplications().catch(err => {
      this.logger.error('Error loading applications on startup:', err);
      this.applications = [];
    });
  }

  private async loadApplications(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.applicationsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.applicationsFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.applications = [];
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Applications file does not contain an array, starting with empty array');
          this.applications = [];
          return;
        }
        this.applications = parsed.map((app: any) => ({
          ...app,
          registeredAt: app.registeredAt ? new Date(app.registeredAt) : new Date(),
          lastTestAt: app.lastTestAt ? new Date(app.lastTestAt) : undefined,
          updatedAt: app.updatedAt ? new Date(app.updatedAt) : new Date(),
          validatorOverrides: app.validatorOverrides || {},
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.applications = [];
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error in applications file, starting with empty array:', readError.message);
          this.applications = [];
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading applications:', error);
      this.applications = [];
    }
  }

  /**
   * Ensure data is loaded before returning
   */
  private async ensureLoaded(): Promise<void> {
    if (this.loadPromise) {
      await this.loadPromise;
      this.loadPromise = null;
    }
    if (this.applications.length === 0) {
      await this.loadApplications();
    }
  }

  /**
   * Get all applications
   */
  async findAll(): Promise<Application[]> {
    try {
      await this.ensureLoaded();
      return this.applications;
    } catch (error) {
      this.logger.error('Error in findAll:', error);
      throw error;
    }
  }

  /**
   * Find application by ID
   */
  async findOne(id: string): Promise<Application> {
    await this.ensureLoaded();
    const application = this.applications.find(app => app.id === id);
    if (!application) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }
    return application;
  }

  /**
   * Find applications by team
   */
  async findByTeam(team: string): Promise<Application[]> {
    try {
      await this.ensureLoaded();
      return this.applications.filter(app => app.team === team);
    } catch (error) {
      this.logger.error('Error in findByTeam:', error);
      throw error;
    }
  }

  /**
   * Find applications by status
   */
  async findByStatus(status: ApplicationStatus): Promise<Application[]> {
    try {
      await this.ensureLoaded();
      return this.applications.filter(app => app.status === status);
    } catch (error) {
      this.logger.error('Error in findByStatus:', error);
      throw error;
    }
  }

  /**
   * Find applications by type
   */
  async findByType(type: ApplicationType): Promise<Application[]> {
    try {
      await this.ensureLoaded();
      return this.applications.filter(app => app.type === type);
    } catch (error) {
      this.logger.error('Error in findByType:', error);
      throw error;
    }
  }
}
