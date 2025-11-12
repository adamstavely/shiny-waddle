export class UpdateScheduledReportDto {
  name?: string;
  enabled?: boolean;
  frequency?: 'daily' | 'weekly' | 'monthly' | 'custom';
  cronExpression?: string;
  time?: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
  format?: 'json' | 'html' | 'xml' | 'pdf' | 'excel';
  reportType?: 'executive' | 'regulatory' | 'technical' | 'custom';
  template?: string;
  applicationIds?: string[];
  teamIds?: string[];
  validatorIds?: string[];
  dateRange?: {
    type: 'relative' | 'absolute';
    days?: number;
    from?: string;
    to?: string;
  };
  includeCharts?: boolean;
  includeDetails?: boolean;
  includeTrends?: boolean;
  includeRiskScores?: boolean;
  recipients?: string[];
  deliveryMethod?: 'email' | 'webhook' | 'storage';
  webhookUrl?: string;
}

