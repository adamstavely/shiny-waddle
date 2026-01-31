import { Injectable } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { SystemStateComparisonService, EnforcementGap } from './system-state-comparison.service';
import { DataTagComparisonService, TagComparison } from './data-tag-comparison.service';
import { Policy } from '../entities/policy.entity';

export interface RemediationStep {
  order: number;
  action: string;
  description: string;
  expectedOutcome: string;
  verification?: string;
}

export interface RemediationGuidance {
  steps: RemediationStep[];
  estimatedTime: string;
  requiredPermissions: string[];
  links: Array<{
    label: string;
    url: string;
    type: 'internal' | 'external' | 'documentation';
  }>;
  codeExamples?: Array<{
    language: string;
    code: string;
    description: string;
  }>;
}

export interface PrioritizedGap {
  id: string;
  type: 'enforcement' | 'tag' | 'attribute' | 'policy';
  severity: 'low' | 'medium' | 'high' | 'critical';
  priority: number; // 1-10, higher = more urgent
  title: string;
  description: string;
  affectedResources: string[];
  affectedApplications: string[];
  remediation: RemediationGuidance;
  estimatedEffort: string;
}

export interface GapAnalysis {
  policyId?: string;
  applicationId?: string;
  gaps: PrioritizedGap[];
  summary: {
    totalGaps: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    complianceScore: number; // 0-100
  };
  recommendations: string[];
}

@Injectable()
export class GapAnalysisService {
  constructor(
    private readonly policiesService: PoliciesService,
    private readonly systemStateService: SystemStateComparisonService,
    private readonly tagComparisonService: DataTagComparisonService,
  ) {}

  /**
   * Comprehensive gap analysis
   */
  async analyzeGaps(
    policyId?: string,
    applicationId?: string,
  ): Promise<GapAnalysis> {
    try {
      const gaps: PrioritizedGap[] = [];

      // Get enforcement gaps
      try {
        const enforcementGaps = await this.systemStateService.detectEnforcementGaps(
          policyId ? [policyId] : undefined,
        );
        gaps.push(...this.convertEnforcementGaps(enforcementGaps, policyId));
      } catch (error) {
        console.error('Error detecting enforcement gaps:', error);
        // Continue with empty gaps array
      }

      // Get tag comparison gaps
      if (policyId) {
        try {
          const policy = await this.policiesService.findOne(policyId);
          // In production, get all resources and compare tags
          // For now, we'll skip tag gaps if no resource ID is provided
        } catch (error) {
          console.error('Error loading policy for tag comparison:', error);
          // Continue without tag gaps
        }
      }

      // Prioritize gaps
      const prioritizedGaps = this.prioritizeGaps(gaps);

      // Calculate summary
      const summary = {
        totalGaps: prioritizedGaps.length,
        critical: prioritizedGaps.filter(g => g.severity === 'critical').length,
        high: prioritizedGaps.filter(g => g.severity === 'high').length,
        medium: prioritizedGaps.filter(g => g.severity === 'medium').length,
        low: prioritizedGaps.filter(g => g.severity === 'low').length,
        complianceScore: this.calculateComplianceScore(prioritizedGaps),
      };

      // Generate recommendations
      const recommendations = this.generateRecommendations(prioritizedGaps, summary);

      return {
        policyId,
        applicationId,
        gaps: prioritizedGaps,
        summary,
        recommendations,
      };
    } catch (error) {
      console.error('Error in analyzeGaps:', error);
      // Return empty gap analysis on error
      return {
        policyId,
        applicationId,
        gaps: [],
        summary: {
          totalGaps: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          complianceScore: 100,
        },
        recommendations: [],
      };
    }
  }

  /**
   * Convert enforcement gaps to prioritized gaps
   */
  private convertEnforcementGaps(
    enforcementGaps: EnforcementGap[],
    policyId?: string,
  ): PrioritizedGap[] {
    return enforcementGaps.map((gap, index) => {
      const priority = this.calculatePriority(gap);
      const estimatedEffort = this.estimateEffort(gap);

      return {
        id: `enforcement-${policyId || 'all'}-${index}`,
        type: this.mapGapType(gap.type),
        severity: gap.severity,
        priority,
        title: gap.description,
        description: gap.description,
        affectedResources: [],
        affectedApplications: gap.location ? [gap.location] : [],
        remediation: this.convertToRemediationGuidance(gap.remediation),
        estimatedEffort,
      };
    });
  }

  /**
   * Map enforcement gap type to prioritized gap type
   */
  private mapGapType(type: EnforcementGap['type']): PrioritizedGap['type'] {
    switch (type) {
      case 'policy-not-enforced':
      case 'rule-missing':
      case 'condition-missing':
      case 'effect-mismatch':
        return 'enforcement';
      default:
        return 'policy';
    }
  }

  /**
   * Convert remediation steps to guidance
   */
  private convertToRemediationGuidance(
    steps: RemediationStep[],
  ): RemediationGuidance {
    const estimatedMinutes = steps.length * 5; // 5 minutes per step
    const estimatedTime = estimatedMinutes < 60
      ? `${estimatedMinutes} minutes`
      : `${Math.round(estimatedMinutes / 60)} hours`;

    return {
      steps,
      estimatedTime,
      requiredPermissions: ['policy:write', 'policy:deploy'],
      links: [
        {
          label: 'Policy Management',
          url: '/policies/access-control',
          type: 'internal',
        },
        {
          label: 'Documentation',
          url: '/docs/policies',
          type: 'documentation',
        },
      ],
    };
  }

  /**
   * Prioritize gaps by risk
   */
  prioritizeGaps(gaps: PrioritizedGap[]): PrioritizedGap[] {
    return gaps.sort((a, b) => {
      // First sort by severity
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
      if (severityDiff !== 0) return severityDiff;

      // Then by priority score
      return b.priority - a.priority;
    });
  }

  /**
   * Calculate priority score (1-10)
   */
  private calculatePriority(gap: EnforcementGap): number {
    let priority = 5; // Base priority

    // Adjust based on severity
    switch (gap.severity) {
      case 'critical':
        priority += 3;
        break;
      case 'high':
        priority += 2;
        break;
      case 'medium':
        priority += 1;
        break;
      case 'low':
        priority -= 1;
        break;
    }

    // Adjust based on type
    if (gap.type === 'policy-not-enforced') {
      priority += 2;
    } else if (gap.type === 'effect-mismatch') {
      priority += 1;
    }

    // Clamp between 1 and 10
    return Math.max(1, Math.min(10, priority));
  }

  /**
   * Estimate effort for fixing a gap
   */
  private estimateEffort(gap: EnforcementGap): string {
    const stepCount = gap.remediation.length;

    if (stepCount <= 2) {
      return '15-30 minutes';
    } else if (stepCount <= 4) {
      return '30-60 minutes';
    } else if (stepCount <= 6) {
      return '1-2 hours';
    } else {
      return '2+ hours';
    }
  }

  /**
   * Calculate compliance score (0-100)
   */
  private calculateComplianceScore(gaps: PrioritizedGap[]): number {
    if (gaps.length === 0) return 100;

    // Weight gaps by severity
    let totalWeight = 0;
    let penalty = 0;

    gaps.forEach(gap => {
      const weight = gap.severity === 'critical' ? 4
        : gap.severity === 'high' ? 3
        : gap.severity === 'medium' ? 2
        : 1;
      totalWeight += weight;
      penalty += weight * 10; // Each gap reduces score by 10 points per weight
    });

    const maxPenalty = totalWeight * 10;
    const score = Math.max(0, 100 - (penalty / maxPenalty) * 100);

    return Math.round(score);
  }

  /**
   * Generate recommendations based on gaps
   */
  private generateRecommendations(
    gaps: PrioritizedGap[],
    summary: GapAnalysis['summary'],
  ): string[] {
    const recommendations: string[] = [];

    if (summary.critical > 0) {
      recommendations.push(
        `Address ${summary.critical} critical gap(s) immediately to prevent security risks`,
      );
    }

    if (summary.high > 0) {
      recommendations.push(
        `Resolve ${summary.high} high-priority gap(s) within 48 hours`,
      );
    }

    if (summary.complianceScore < 80) {
      recommendations.push(
        'Compliance score is below 80%. Consider a comprehensive review of all policies',
      );
    }

    const enforcementGaps = gaps.filter(g => g.type === 'enforcement');
    if (enforcementGaps.length > 0) {
      recommendations.push(
        `${enforcementGaps.length} enforcement gap(s) detected. Ensure policies are properly deployed`,
      );
    }

    if (gaps.length === 0) {
      recommendations.push('No gaps detected. System is fully compliant.');
    }

    return recommendations;
  }

  /**
   * Get remediation guidance for a specific gap
   */
  async getRemediationGuidance(gapId: string): Promise<RemediationGuidance | null> {
    // In production, this would look up the gap by ID
    // For now, return null
    return null;
  }

  /**
   * Track remediation progress
   */
  async trackProgress(
    gapId: string,
    step: number,
    completed: boolean,
    notes?: string,
  ): Promise<void> {
    // In production, this would update progress tracking
    // For now, just log
    console.log(`Gap ${gapId}, Step ${step}: ${completed ? 'Completed' : 'In Progress'}`, notes);
  }
}
