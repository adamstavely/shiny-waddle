#!/usr/bin/env ts-node

/**
 * Heimdall Dashboard Server
 * 
 * Web server to display the compliance dashboard UI
 */

import express, { Request, Response } from 'express';
import * as path from 'path';
import * as fs from 'fs/promises';

const app = express();
const PORT = process.env.PORT || 3001;

// Serve static files
app.use(express.static(path.join(__dirname, '../public')));

// API endpoint to get dashboard data
app.get('/api/dashboard-data', async (req: Request, res: Response) => {
  try {
    const reportsDir = path.join(__dirname, '../reports');
    
    // Try to find the most recent dashboard-data.json
    let dashboardData = null;
    try {
      const files = await fs.readdir(reportsDir);
      const dashboardFiles = files.filter((f: string) => f.startsWith('dashboard-data'));
      
      if (dashboardFiles.length > 0) {
        // Sort by modification time and get the most recent
        const fileStats = await Promise.all(
          dashboardFiles.map(async (file: string) => {
            const filePath = path.join(reportsDir, file);
            const stats = await fs.stat(filePath);
            return { file, mtime: stats.mtime, path: filePath };
          })
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
    
    res.json(dashboardData);
  } catch (error) {
    console.error('Error loading dashboard data:', error);
    res.status(500).json({ error: 'Failed to load dashboard data' });
  }
});

// API endpoint to get compliance reports
app.get('/api/reports', async (req: Request, res: Response) => {
  try {
    const reportsDir = path.join(__dirname, '../reports');
    const files = await fs.readdir(reportsDir);
    const reportFiles = files.filter((f: string) => f.startsWith('compliance-report') && f.endsWith('.json'));
    
    const reports = await Promise.all(
      reportFiles.map(async (file: string) => {
        const filePath = path.join(reportsDir, file);
        const stats = await fs.stat(filePath);
        const data = await fs.readFile(filePath, 'utf-8');
        return {
          filename: file,
          generatedAt: stats.mtime,
          data: JSON.parse(data),
        };
      })
    );
    
    reports.sort((a, b) => b.generatedAt.getTime() - a.generatedAt.getTime());
    res.json(reports);
  } catch (error) {
    console.error('Error loading reports:', error);
    res.status(500).json({ error: 'Failed to load reports' });
  }
});

// Serve dashboard HTML
app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Heimdall Dashboard running on http://localhost:${PORT}`);
  console.log(`📊 Open your browser to view the dashboard`);
});

