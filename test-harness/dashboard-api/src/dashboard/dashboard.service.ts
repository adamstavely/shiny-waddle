import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface DashboardData {
  overallCompliance: number;
  scoresByApplication: Record<string, any>;
  scoresByTeam: Record<string, any>;
  scoresByDataset: Record<string, any>;
  recentTestResults: any[];
  trends: any[];
}

@Injectable()
export class DashboardService {
  private readonly reportsDir = path.join(process.cwd(), '..', '..', 'reports');

  async getDashboardData(): Promise<DashboardData> {
    try {
      // Try to find the most recent dashboard-data.json
      let dashboardData = null;
      try {
        const files = await fs.readdir(this.reportsDir);
        const dashboardFiles = files.filter((f: string) =>
          f.startsWith('dashboard-data'),
        );

        if (dashboardFiles.length > 0) {
          // Sort by modification time and get the most recent
          const fileStats = await Promise.all(
            dashboardFiles.map(async (file: string) => {
              const filePath = path.join(this.reportsDir, file);
              const stats = await fs.stat(filePath);
              return { file, mtime: stats.mtime, path: filePath };
            }),
          );

          fileStats.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
          const mostRecent = fileStats[0];
          const data = await fs.readFile(mostRecent.path, 'utf-8');
          dashboardData = JSON.parse(data);
        }
      } catch (error) {
        console.warn('No dashboard data found, using sample data:', error);
      }

      // If no data found, return sample data
      if (!dashboardData) {
        dashboardData = {
          overallCompliance: 85.5,
          scoresByApplication: {
            'my-app': {
              application: 'my-app',
              team: 'my-team',
              overallScore: 85.5,
              scoresByCategory: {
                accessControl: 90,
                dataBehavior: 85,
                contracts: 80,
                datasetHealth: 87,
              },
              testResults: [],
              lastUpdated: new Date(),
            },
          },
          scoresByTeam: {
            'my-team': {
              application: 'my-app',
              team: 'my-team',
              overallScore: 85.5,
              scoresByCategory: {
                accessControl: 90,
                dataBehavior: 85,
                contracts: 80,
                datasetHealth: 87,
              },
              testResults: [],
              lastUpdated: new Date(),
            },
          },
          scoresByDataset: {},
          recentTestResults: [],
          trends: [],
        };
      }

      return dashboardData;
    } catch (error) {
      console.error('Error loading dashboard data:', error);
      throw error;
    }
  }

  async getReports(): Promise<any[]> {
    try {
      const files = await fs.readdir(this.reportsDir);
      const reportFiles = files.filter(
        (f: string) =>
          f.startsWith('compliance-report') && f.endsWith('.json'),
      );

      const reports = await Promise.all(
        reportFiles.map(async (file: string) => {
          const filePath = path.join(this.reportsDir, file);
          const stats = await fs.stat(filePath);
          const data = await fs.readFile(filePath, 'utf-8');
          return {
            filename: file,
            generatedAt: stats.mtime,
            data: JSON.parse(data),
          };
        }),
      );

      reports.sort(
        (a, b) => b.generatedAt.getTime() - a.generatedAt.getTime(),
      );
      return reports;
    } catch (error) {
      console.error('Error loading reports:', error);
      return [];
    }
  }
}

