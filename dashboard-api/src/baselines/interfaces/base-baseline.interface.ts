/**
 * Base interface for all platform-specific data protection baselines
 */
export interface BaseBaseline {
  id: string;
  name: string;
  description: string;
  environment: string; // production, staging, development
  version: string;
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes';
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  tags?: string[];
  isActive: boolean;
}

/**
 * Baseline comparison result
 */
export interface BaselineComparison {
  baselineId: string;
  baselineName: string;
  differences: BaselineDifference[];
  hasChanges: boolean;
  riskScore?: number; // 0-100, higher = more risk
  complianceScore?: number; // 0-100, higher = more compliant
}

/**
 * Individual difference found during comparison
 */
export interface BaselineDifference {
  type: 'added' | 'removed' | 'modified' | 'encryption_gap' | 'access_control_issue' | 'retention_policy_violation';
  path: string; // JSON path to the difference
  key: string;
  baselineValue?: any;
  currentValue?: any;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  hipaaImpact?: {
    rule?: string; // HIPAA rule reference
    requirement?: string; // Specific requirement
  };
}

/**
 * Drift detection result
 */
export interface DriftDetectionResult {
  baselineId: string;
  baselineName: string;
  hasDrift: boolean;
  driftScore: number; // 0-100, higher = more drift
  complianceScore: number; // 0-100, higher = more compliant
  drifts: BaselineDifference[];
  hipaaCompliance?: {
    securityRuleScore: number;
    privacyRuleScore: number;
    breachNotificationScore: number;
    overallScore: number;
    violations: Array<{
      rule: string;
      requirement: string;
      severity: string;
      description: string;
    }>;
  };
  recommendations?: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    action: string;
    description: string;
  }>;
}
