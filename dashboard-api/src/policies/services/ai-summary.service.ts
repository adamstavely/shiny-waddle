import { Injectable } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { Policy } from '../entities/policy.entity';
import { GapAnalysis } from './gap-analysis.service';
import { ComplianceAnalysis } from './system-state-comparison.service';
import { LLMIntegrationService } from './llm-integration.service';
import { CacheService } from './cache.service';

export interface ExecutiveSummary {
  summary: string;
  keyMetrics: {
    policiesCreated: number;
    policiesModified: number;
    policiesDeleted: number;
    complianceScore: number;
    totalGaps: number;
    criticalGaps: number;
  };
  keyChanges: string[];
  impact: {
    resourcesAffected: number;
    applicationsAffected: number;
    estimatedEffort: string;
  };
  recommendations: string[];
}

export interface DetailedSummary {
  policyChanges: Array<{
    policyId: string;
    policyName: string;
    changeType: 'created' | 'modified' | 'deleted';
    changes: string[];
    affectedResources: string[];
    affectedApplications: string[];
    requiredActions: string[];
  }>;
  complianceStatus: {
    overallScore: number;
    policyScores: Array<{
      policyId: string;
      policyName: string;
      score: number;
      gaps: number;
    }>;
  };
  gapAnalysis: {
    totalGaps: number;
    gapsBySeverity: Record<string, number>;
    topGaps: Array<{
      id: string;
      title: string;
      severity: string;
      priority: number;
    }>;
  };
}

@Injectable()
export class AISummaryService {
  constructor(
    private readonly policiesService: PoliciesService,
    private readonly llmService: LLMIntegrationService,
    private readonly cacheService: CacheService,
  ) {}

  /**
   * Generate executive summary of policy changes
   */
  async generateExecutiveSummary(
    startDate: Date,
    endDate: Date,
  ): Promise<ExecutiveSummary> {
    // Check cache first
    const cacheKey = `executive-summary:${startDate.toISOString()}:${endDate.toISOString()}`;
    const cached = await this.cacheService.getCachedSummary(cacheKey);
    if (cached) {
      return cached;
    }

    // Get policies changed in date range
    const policies = await this.policiesService.findAll();
    const changedPolicies = this.filterByDateRange(policies, startDate, endDate);

    // Get compliance analysis (with caching)
    const complianceAnalysis = await this.getComplianceAnalysis();

    // Generate summary using LLM if enabled, otherwise use template
    let summary: string;
    if (this.llmService.isEnabled()) {
      try {
        summary = await this.llmService.generateEnhancedSummary(
          {
            policies: changedPolicies,
            compliance: complianceAnalysis,
            gaps: complianceAnalysis.gaps || [],
          },
          { tone: 'executive' }
        );
      } catch (error) {
        // Fallback to template if LLM fails
        summary = this.generateSummaryText(changedPolicies, complianceAnalysis);
      }
    } else {
      summary = this.generateSummaryText(changedPolicies, complianceAnalysis);
    }

    return {
      summary,
      keyMetrics: {
        policiesCreated: changedPolicies.filter(p => this.isNew(p, startDate)).length,
        policiesModified: changedPolicies.filter(p => !this.isNew(p, startDate)).length,
        policiesDeleted: 0, // Would need to track deletions
        complianceScore: complianceAnalysis.compliancePercentage,
        totalGaps: complianceAnalysis.gaps.length,
        criticalGaps: complianceAnalysis.summary.critical,
      },
      keyChanges: this.extractKeyChanges(changedPolicies),
      impact: this.calculateImpact(changedPolicies),
      recommendations: this.generateRecommendations(complianceAnalysis),
    };

    // Cache the result (1 hour TTL)
    await this.cacheService.cacheSummary(cacheKey, result, 3600);

    return result;
  }

  /**
   * Generate detailed technical summary
   */
  async generateDetailedSummary(
    startDate: Date,
    endDate: Date,
  ): Promise<DetailedSummary> {
    // Check cache first
    const cacheKey = `detailed-summary:${startDate.toISOString()}:${endDate.toISOString()}`;
    const cached = await this.cacheService.getCachedSummary(cacheKey);
    if (cached) {
      return cached;
    }

    const policies = await this.policiesService.findAll();
    const changedPolicies = this.filterByDateRange(policies, startDate, endDate);
    const complianceAnalysis = await this.getComplianceAnalysis();

    return {
      policyChanges: changedPolicies.map(policy => ({
        policyId: policy.id,
        policyName: policy.name,
        changeType: this.determineChangeType(policy, startDate),
        changes: this.extractPolicyChanges(policy),
        affectedResources: this.getAffectedResources(policy),
        affectedApplications: this.getAffectedApplications(policy),
        requiredActions: this.getRequiredActions(policy),
      })),
      complianceStatus: {
        overallScore: complianceAnalysis.compliancePercentage,
        policyScores: await this.getPolicyScores(),
      },
      gapAnalysis: {
        totalGaps: complianceAnalysis.gaps.length,
        gapsBySeverity: {
          critical: complianceAnalysis.summary.critical,
          high: complianceAnalysis.summary.high,
          medium: complianceAnalysis.summary.medium,
          low: complianceAnalysis.summary.low,
        },
        topGaps: complianceAnalysis.gaps
          .slice(0, 10)
          .map(gap => ({
            id: gap.type,
            title: gap.description,
            severity: gap.severity,
            priority: this.calculateGapPriority(gap),
          })),
      },
    };

    // Cache the result (1 hour TTL)
    await this.cacheService.cacheSummary(cacheKey, result, 3600);

    return result;
  }

  /**
   * Generate compliance summary
   */
  async generateComplianceSummary(): Promise<string> {
    const complianceAnalysis = await this.getComplianceAnalysis();
    
    return this.formatComplianceSummary(complianceAnalysis);
  }

  // Helper methods
  private filterByDateRange(policies: Policy[], start: Date, end: Date): Policy[] {
    return policies.filter(p => {
      const updated = new Date(p.updatedAt || p.createdAt);
      return updated >= start && updated <= end;
    });
  }

  private generateSummaryText(policies: Policy[], compliance: ComplianceAnalysis): string {
    // Template-based generation with AI enhancement
    // In production, this would call an LLM API
    const template = `
      Policy Changes Summary (${policies.length} policies):
      
      ${policies.length} policies were modified in this period.
      Overall compliance score: ${compliance.compliancePercentage}%
      ${compliance.gaps.length} compliance gaps detected.
      
      Key areas of focus:
      - ${compliance.summary.critical} critical gaps require immediate attention
      - ${compliance.summary.high} high-priority gaps should be addressed within 48 hours
      - ${compliance.summary.medium} medium-priority gaps should be addressed within 1 week
      - ${compliance.summary.low} low-priority gaps can be addressed during regular maintenance
    `;
    
    return template.trim();
  }

  private extractKeyChanges(policies: Policy[]): string[] {
    const changes: string[] = [];
    
    policies.forEach(policy => {
      if (policy.rules && policy.rules.length > 0) {
        changes.push(`Policy "${policy.name}" has ${policy.rules.length} rules`);
      }
      if (policy.conditions && policy.conditions.length > 0) {
        changes.push(`Policy "${policy.name}" has ${policy.conditions.length} conditions`);
      }
      if (policy.status) {
        changes.push(`Policy "${policy.name}" status: ${policy.status}`);
      }
    });

    return changes.slice(0, 10); // Limit to top 10
  }

  private calculateImpact(policies: Policy[]): {
    resourcesAffected: number;
    applicationsAffected: number;
    estimatedEffort: string;
  } {
    // Estimate impact based on policy complexity
    const totalRules = policies.reduce((sum, p) => sum + (p.rules?.length || 0), 0);
    const totalConditions = policies.reduce((sum, p) => sum + (p.conditions?.length || 0), 0);
    
    // Rough estimation
    const resourcesAffected = Math.max(1, Math.floor(totalRules / 2));
    const applicationsAffected = Math.max(1, Math.floor(policies.length / 3));
    const estimatedHours = totalRules * 0.5 + totalConditions * 0.3;
    
    let effort = '';
    if (estimatedHours < 1) {
      effort = '< 1 hour';
    } else if (estimatedHours < 8) {
      effort = `${Math.ceil(estimatedHours)} hours`;
    } else {
      effort = `${Math.ceil(estimatedHours / 8)} days`;
    }

    return {
      resourcesAffected,
      applicationsAffected,
      estimatedEffort: effort,
    };
  }

  private generateRecommendations(compliance: ComplianceAnalysis): string[] {
    const recommendations: string[] = [];

    if (compliance.summary.critical > 0) {
      recommendations.push(`Address ${compliance.summary.critical} critical gaps immediately to prevent security risks`);
    }
    if (compliance.summary.high > 0) {
      recommendations.push(`Prioritize remediation of ${compliance.summary.high} high-severity gaps within 48 hours`);
    }
    if (compliance.compliancePercentage < 80) {
      recommendations.push(`Overall compliance score is below target. Focus on improving policy enforcement`);
    }
    if (compliance.gaps.length === 0) {
      recommendations.push(`Excellent! All policies are compliant. Continue monitoring for new gaps`);
    }

    return recommendations;
  }

  private determineChangeType(policy: Policy, startDate: Date): 'created' | 'modified' | 'deleted' {
    const created = new Date(policy.createdAt);
    const updated = new Date(policy.updatedAt || policy.createdAt);
    
    if (created >= startDate) {
      return 'created';
    }
    if (updated >= startDate) {
      return 'modified';
    }
    return 'modified'; // Default
  }

  private extractPolicyChanges(policy: Policy): string[] {
    const changes: string[] = [];
    
    if (policy.rules && policy.rules.length > 0) {
      changes.push(`Updated ${policy.rules.length} rules`);
    }
    if (policy.conditions && policy.conditions.length > 0) {
      changes.push(`Updated ${policy.conditions.length} conditions`);
    }
    if (policy.status) {
      changes.push(`Status changed to ${policy.status}`);
    }
    if (policy.version) {
      changes.push(`Version updated to ${policy.version}`);
    }

    return changes.length > 0 ? changes : ['No specific changes detected'];
  }

  private getAffectedResources(policy: Policy): string[] {
    // In production, this would query actual resources
    // For now, return empty array
    return [];
  }

  private getAffectedApplications(policy: Policy): string[] {
    // In production, this would query actual applications
    // For now, return empty array
    return [];
  }

  private getRequiredActions(policy: Policy): string[] {
    const actions: string[] = [];
    
    if (policy.status === 'draft') {
      actions.push('Review and approve policy');
    }
    if (policy.status === 'active') {
      actions.push('Verify policy enforcement');
    }
    if (policy.rules && policy.rules.length === 0 && policy.conditions && policy.conditions.length === 0) {
      actions.push('Add rules or conditions to policy');
    }

    return actions.length > 0 ? actions : ['No immediate actions required'];
  }

  private async getPolicyScores(): Promise<Array<{
    policyId: string;
    policyName: string;
    score: number;
    gaps: number;
  }>> {
    const policies = await this.policiesService.findAll();
    const scores = [];

    for (const policy of policies) {
      // Calculate score based on policy completeness
      let score = 100;
      if (!policy.rules || policy.rules.length === 0) {
        if (!policy.conditions || policy.conditions.length === 0) {
          score -= 50;
        }
      }
      if (policy.status === 'draft') {
        score -= 20;
      }

      scores.push({
        policyId: policy.id,
        policyName: policy.name,
        score: Math.max(0, score),
        gaps: 0, // Would need to calculate from gap analysis
      });
    }

    return scores;
  }

  private calculateGapPriority(gap: any): number {
    // Map severity to priority (1-10)
    const severityMap: Record<string, number> = {
      critical: 10,
      high: 7,
      medium: 4,
      low: 1,
    };
    return severityMap[gap.severity] || 5;
  }

  private isNew(policy: Policy, startDate: Date): boolean {
    const created = new Date(policy.createdAt);
    return created >= startDate;
  }

  private async getComplianceAnalysis(): Promise<ComplianceAnalysis> {
    // Check cache first
    const cached = await this.cacheService.getCachedComplianceAnalysis();
    if (cached) {
      return cached;
    }

    // In production, this would call the SystemStateComparisonService
    // For now, return a mock analysis
    const policies = await this.policiesService.findAll();
    
    const analysis: ComplianceAnalysis = {
      totalPolicies: policies.length,
      enforcedPolicies: policies.filter(p => p.status === 'active').length,
      compliancePercentage: 85, // Would calculate from actual compliance
      gaps: [],
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
    };

    // Cache for 30 minutes
    await this.cacheService.cacheComplianceAnalysis(analysis, 1800);

    return analysis;
  }

  private formatComplianceSummary(compliance: ComplianceAnalysis): string {
    return `
      Compliance Summary:
      
      Total Policies: ${compliance.totalPolicies}
      Enforced Policies: ${compliance.enforcedPolicies}
      Compliance Score: ${compliance.compliancePercentage}%
      
      Gap Summary:
      - Critical: ${compliance.summary.critical}
      - High: ${compliance.summary.high}
      - Medium: ${compliance.summary.medium}
      - Low: ${compliance.summary.low}
    `.trim();
  }
}
