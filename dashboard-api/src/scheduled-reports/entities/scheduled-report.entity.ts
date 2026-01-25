export interface ScheduledReport {
  id: string;
  name: string;
  enabled: boolean;
  
  // Schedule configuration
  frequency: 'daily' | 'weekly' | 'monthly' | 'custom';
  cronExpression?: string; // For custom schedules
  time?: string; // Time of day (HH:mm format) for daily/weekly/monthly
  dayOfWeek?: number; // 0-6 for weekly (0 = Sunday)
  dayOfMonth?: number; // 1-31 for monthly
  
  // Report configuration
  format: 'json' | 'html' | 'xml' | 'pdf' | 'excel';
  reportType: 'executive' | 'regulatory' | 'technical' | 'custom';
  template?: string;
  
  // Filters
  applicationIds?: string[];
  teamIds?: string[];
  validatorIds?: string[];
  dateRange?: {
    type: 'relative' | 'absolute';
    days?: number; // For relative (e.g., last 30 days)
    from?: string; // For absolute
    to?: string; // For absolute
  };
  
  // Options
  includeCharts?: boolean;
  includeDetails?: boolean;
  includeTrends?: boolean;
  includeRiskScores?: boolean;
  
  // Delivery
  recipients?: string[]; // Email addresses
  deliveryMethod: 'email' | 'webhook' | 'storage';
  webhookUrl?: string;
  
  // Metadata
  lastRun?: Date;
  nextRun: Date;
  runCount: number;
  lastError?: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
}

