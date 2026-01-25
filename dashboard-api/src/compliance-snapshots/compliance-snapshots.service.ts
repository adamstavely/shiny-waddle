import { Injectable, NotFoundException, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { ApplicationDataService } from '../shared/application-data.service';
import { ApplicationsService } from '../applications/applications.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

export interface ComplianceSnapshot {
  id: string;
  name: string;
  timestamp: Date;
  applicationIds: string[];
  applications: Array<{
    id: string;
    name: string;
    score: number;
  }>;
  overallScore: number;
  metadata?: Record<string, any>;
  createdAt: Date;
}

@Injectable()
export class ComplianceSnapshotsService {
  private readonly logger = new Logger(ComplianceSnapshotsService.name);
  private readonly snapshotsFile = path.join(process.cwd(), 'data', 'compliance-snapshots.json');
  private snapshots: ComplianceSnapshot[] = [];

  constructor(
    private readonly applicationDataService: ApplicationDataService,
    private readonly moduleRef: ModuleRef,
  ) {
    this.loadSnapshots().catch(err => {
      this.logger.error('Error loading compliance snapshots on startup:', err);
    });
  }

  private async loadSnapshots(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.snapshotsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.snapshotsFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.snapshots = [];
          await this.saveSnapshots();
          return;
        }
        const parsed = JSON.parse(data);
        this.snapshots = (Array.isArray(parsed) ? parsed : []).map((s: any) => ({
          ...s,
          timestamp: new Date(s.timestamp),
          createdAt: new Date(s.createdAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.snapshots = [];
          await this.saveSnapshots();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading snapshots:', error);
      this.snapshots = [];
    }
  }

  private async saveSnapshots(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.snapshotsFile), { recursive: true });
      await fs.writeFile(this.snapshotsFile, JSON.stringify(this.snapshots, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving snapshots:', error);
      throw error;
    }
  }

  async findAll(filters: { applicationId?: string; limit?: number }): Promise<ComplianceSnapshot[]> {
    await this.loadSnapshots();
    let filtered = [...this.snapshots];

    if (filters.applicationId) {
      filtered = filtered.filter(s => s.applicationIds.includes(filters.applicationId!));
    }

    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (filters.limit) {
      filtered = filtered.slice(0, filters.limit);
    }

    return filtered;
  }

  async findOne(id: string): Promise<ComplianceSnapshot> {
    await this.loadSnapshots();
    const snapshot = this.snapshots.find(s => s.id === id);
    if (!snapshot) {
      throw new NotFoundException(`Snapshot with ID ${id} not found`);
    }
    return snapshot;
  }

  async create(dto: { name?: string; applicationIds?: string[] }): Promise<ComplianceSnapshot> {
    await this.loadSnapshots();

    // Get all applications or filter by provided IDs
    const allApplications = await this.applicationDataService.findAll();
    const targetApplications = dto.applicationIds
      ? allApplications.filter(app => dto.applicationIds!.includes(app.id))
      : allApplications;

    // Get compliance scores for each application
    const applications = await Promise.all(
      targetApplications.map(async (app) => {
        try {
          const applicationsService = this.moduleRef.get(ApplicationsService, { strict: false });
          if (!applicationsService) {
            throw new Error('ApplicationsService not available');
          }
          const scoreResponse = await applicationsService.getComplianceScore(app.id);
          return {
            id: app.id,
            name: app.name,
            score: scoreResponse.score,
          };
        } catch (err) {
          this.logger.warn(`Could not get score for application ${app.id}`);
          return {
            id: app.id,
            name: app.name,
            score: 0,
          };
        }
      })
    );

    // Calculate overall score
    const overallScore = applications.length > 0
      ? Math.round(applications.reduce((sum, app) => sum + app.score, 0) / applications.length)
      : 0;

    const snapshot: ComplianceSnapshot = {
      id: uuidv4(),
      name: dto.name || `Snapshot ${new Date().toLocaleString()}`,
      timestamp: new Date(),
      applicationIds: applications.map(app => app.id),
      applications,
      overallScore,
      createdAt: new Date(),
    };

    this.snapshots.push(snapshot);
    await this.saveSnapshots();

    this.logger.log(`Created compliance snapshot: ${snapshot.id}`);
    return snapshot;
  }

  async compare(id1: string, id2: string): Promise<{
    snapshot1: ComplianceSnapshot;
    snapshot2: ComplianceSnapshot;
    differences: Array<{
      applicationId: string;
      applicationName: string;
      score1: number;
      score2: number;
      change: number;
    }>;
    overallChange: number;
  }> {
    const snapshot1 = await this.findOne(id1);
    const snapshot2 = await this.findOne(id2);

    const differences: Array<{
      applicationId: string;
      applicationName: string;
      score1: number;
      score2: number;
      change: number;
    }> = [];

    // Compare applications
    const allAppIds = new Set([
      ...snapshot1.applicationIds,
      ...snapshot2.applicationIds,
    ]);

    for (const appId of allAppIds) {
      const app1 = snapshot1.applications.find(a => a.id === appId);
      const app2 = snapshot2.applications.find(a => a.id === appId);
      const score1 = app1?.score || 0;
      const score2 = app2?.score || 0;
      const change = score2 - score1;

      if (change !== 0 || !app1 || !app2) {
        differences.push({
          applicationId: appId,
          applicationName: app1?.name || app2?.name || 'Unknown',
          score1,
          score2,
          change,
        });
      }
    }

    return {
      snapshot1,
      snapshot2,
      differences,
      overallChange: snapshot2.overallScore - snapshot1.overallScore,
    };
  }
}

