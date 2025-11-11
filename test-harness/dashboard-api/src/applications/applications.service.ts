import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { CreateApplicationDto, ApplicationType, ApplicationStatus } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { Application } from './entities/application.entity';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ApplicationsService {
  private readonly applicationsFile = path.join(process.cwd(), '..', '..', 'data', 'applications.json');
  private applications: Application[] = [];

  constructor() {
    // Load applications asynchronously
    this.loadApplications().catch(err => {
      console.error('Error loading applications on startup:', err);
    });
  }

  private async loadApplications(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.applicationsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.applicationsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.applications = (Array.isArray(parsed) ? parsed : []).map((app: any) => ({
          ...app,
          registeredAt: new Date(app.registeredAt),
          lastTestAt: app.lastTestAt ? new Date(app.lastTestAt) : undefined,
          updatedAt: new Date(app.updatedAt),
        }));
      } catch (readError: any) {
        // File doesn't exist or is invalid, start with empty array
        if (readError.code === 'ENOENT') {
          this.applications = [];
          await this.saveApplications();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading applications:', error);
      // Start with empty array if there's an error
      this.applications = [];
    }
  }

  private async saveApplications() {
    try {
      await fs.mkdir(path.dirname(this.applicationsFile), { recursive: true });
      await fs.writeFile(
        this.applicationsFile,
        JSON.stringify(this.applications, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving applications:', error);
      throw error;
    }
  }

  async create(createApplicationDto: CreateApplicationDto): Promise<Application> {
    // Check if application with this ID already exists
    const existing = this.applications.find(app => app.id === createApplicationDto.id);
    if (existing) {
      throw new ConflictException(`Application with ID "${createApplicationDto.id}" already exists`);
    }

    const application: Application = {
      id: createApplicationDto.id,
      name: createApplicationDto.name,
      type: createApplicationDto.type,
      status: createApplicationDto.status || ApplicationStatus.ACTIVE,
      baseUrl: createApplicationDto.baseUrl,
      team: createApplicationDto.team,
      description: createApplicationDto.description,
      config: createApplicationDto.config || {},
      registeredAt: new Date(),
      updatedAt: new Date(),
    };

    this.applications.push(application);
    await this.saveApplications();

    return application;
  }

  async findAll(): Promise<Application[]> {
    return this.applications;
  }

  async findOne(id: string): Promise<Application> {
    const application = this.applications.find(app => app.id === id);
    if (!application) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }
    return application;
  }

  async update(id: string, updateApplicationDto: UpdateApplicationDto): Promise<Application> {
    const index = this.applications.findIndex(app => app.id === id);
    if (index === -1) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }

    // Don't allow updating the ID
    const { id: _, ...updateData } = updateApplicationDto;

    this.applications[index] = {
      ...this.applications[index],
      ...updateData,
      updatedAt: new Date(),
    };

    await this.saveApplications();

    return this.applications[index];
  }

  async remove(id: string): Promise<void> {
    const index = this.applications.findIndex(app => app.id === id);
    if (index === -1) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }

    this.applications.splice(index, 1);
    await this.saveApplications();
  }

  async updateLastTestAt(id: string, testDate: Date): Promise<Application> {
    const application = await this.findOne(id);
    application.lastTestAt = testDate;
    application.updatedAt = new Date();
    await this.saveApplications();
    return application;
  }

  async findByTeam(team: string): Promise<Application[]> {
    return this.applications.filter(app => app.team === team);
  }

  async findByStatus(status: ApplicationStatus): Promise<Application[]> {
    return this.applications.filter(app => app.status === status);
  }

  async findByType(type: ApplicationType): Promise<Application[]> {
    return this.applications.filter(app => app.type === type);
  }
}

