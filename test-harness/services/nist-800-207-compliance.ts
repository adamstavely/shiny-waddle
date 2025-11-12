/**
 * NIST 800-207 Compliance Service
 * 
 * Zero Trust Architecture compliance assessment based on NIST 800-207
 */

import { ZTAPillar, ZTAAssessment, ComplianceAssessment } from '../core/types';

/**
 * Configuration for NIST 800-207 compliance assessment
 */
export interface NIST800207Config {
  /**
   * Custom control statuses for each pillar
   * If not provided, uses default mock data
   */
  controlStatuses?: {
    identity?: Array<{
      id: string;
      name: string;
      description: string;
      status: 'compliant' | 'non-compliant' | 'partial';
      evidence: string[];
    }>;
    device?: Array<{
      id: string;
      name: string;
      description: string;
      status: 'compliant' | 'non-compliant' | 'partial';
      evidence: string[];
    }>;
    network?: Array<{
      id: string;
      name: string;
      description: string;
      status: 'compliant' | 'non-compliant' | 'partial';
      evidence: string[];
    }>;
    application?: Array<{
      id: string;
      name: string;
      description: string;
      status: 'compliant' | 'non-compliant' | 'partial';
      evidence: string[];
    }>;
    data?: Array<{
      id: string;
      name: string;
      description: string;
      status: 'compliant' | 'non-compliant' | 'partial';
      evidence: string[];
    }>;
  };
  
  /**
   * Compliance threshold (default: 80%)
   */
  complianceThreshold?: number;
  
  /**
   * Custom assessment provider for real system integration
   */
  assessmentProvider?: {
    assessIdentityPillar(): Promise<ZTAPillar>;
    assessDevicePillar(): Promise<ZTAPillar>;
    assessNetworkPillar(): Promise<ZTAPillar>;
    assessApplicationPillar(): Promise<ZTAPillar>;
    assessDataPillar(): Promise<ZTAPillar>;
  };
}

export class NIST800207Compliance {
  private config: NIST800207Config;

  constructor(config?: NIST800207Config) {
    this.config = config || {};
  }

  /**
   * Assess ZTA pillars
   */
  async assessZTAPillars(assessment: Partial<ZTAAssessment>): Promise<ComplianceAssessment> {
    // Use custom assessment provider if available
    let pillars: ZTAPillar[];
    if (this.config.assessmentProvider) {
      try {
        pillars = [
          await this.config.assessmentProvider.assessIdentityPillar(),
          await this.config.assessmentProvider.assessDevicePillar(),
          await this.config.assessmentProvider.assessNetworkPillar(),
          await this.config.assessmentProvider.assessApplicationPillar(),
          await this.config.assessmentProvider.assessDataPillar(),
        ];
      } catch (error: any) {
        throw new Error(`Failed to assess ZTA pillars: ${error.message}`);
      }
    } else {
      pillars = [
        await this.testIdentityPillar({}),
        await this.testDevicePillar({}),
        await this.testNetworkPillar({}),
        await this.testApplicationPillar({}),
        await this.testDataPillar({}),
      ];
    }

    const overallScore = pillars.reduce((sum, p) => sum + p.score, 0) / 
                         pillars.reduce((sum, p) => sum + p.maxScore, 0) * 100;

    const gaps: string[] = [];
    const recommendations: string[] = [];

    for (const pillar of pillars) {
      if (pillar.score < pillar.maxScore) {
        gaps.push(`${pillar.name} pillar: ${pillar.maxScore - pillar.score} controls non-compliant`);
        recommendations.push(`Improve ${pillar.name} pillar compliance`);
      }
    }

    const ztaAssessment: ZTAAssessment = {
      id: assessment.id || `assessment-${Date.now()}`,
      timestamp: assessment.timestamp || new Date(),
      pillars,
      overallScore,
      gaps,
      recommendations,
    };

    const threshold = this.config.complianceThreshold || 80;
    
    return {
      framework: 'NIST-800-207',
      assessment: ztaAssessment,
      compliancePercentage: overallScore,
      compliant: overallScore >= threshold,
    };
  }

  /**
   * Test Identity pillar
   */
  async testIdentityPillar(config: any): Promise<ZTAPillar> {
    // Use configured control statuses if available
    const controls = this.config.controlStatuses?.identity || [
      {
        id: 'ID-1',
        name: 'Identity Verification',
        description: 'All identities are verified before access is granted',
        status: 'compliant' as const,
        evidence: ['Identity verification implemented'],
      },
      {
        id: 'ID-2',
        name: 'Identity Lifecycle Management',
        description: 'Identity lifecycle is managed (onboarding, changes, offboarding)',
        status: 'compliant' as const,
        evidence: ['Identity lifecycle management implemented'],
      },
      {
        id: 'ID-3',
        name: 'MFA Enforcement',
        description: 'Multi-factor authentication is enforced',
        status: 'partial' as const,
        evidence: ['MFA enabled for admin users'],
      },
    ];

    const score = controls.filter(c => c.status === 'compliant').length * 10 +
                  controls.filter(c => c.status === 'partial').length * 5;

    return {
      name: 'identity',
      score,
      maxScore: controls.length * 10,
      controls,
    };
  }

  /**
   * Test Device pillar
   */
  async testDevicePillar(config: any): Promise<ZTAPillar> {
    const controls = this.config.controlStatuses?.device || [
      {
        id: 'DEV-1',
        name: 'Device Trust',
        description: 'Devices are verified and trusted before access',
        status: 'compliant' as const,
        evidence: ['Device trust verification implemented'],
      },
      {
        id: 'DEV-2',
        name: 'Device Posture Assessment',
        description: 'Device security posture is assessed',
        status: 'partial' as const,
        evidence: ['Basic device posture checks implemented'],
      },
    ];

    const score = controls.filter(c => c.status === 'compliant').length * 10 +
                  controls.filter(c => c.status === 'partial').length * 5;

    return {
      name: 'device',
      score,
      maxScore: controls.length * 10,
      controls,
    };
  }

  /**
   * Test Network pillar
   */
  async testNetworkPillar(config: any): Promise<ZTAPillar> {
    const controls = this.config.controlStatuses?.network || [
      {
        id: 'NET-1',
        name: 'Network Micro-Segmentation',
        description: 'Network is segmented with micro-segmentation',
        status: 'compliant' as const,
        evidence: ['Network micro-segmentation implemented'],
      },
      {
        id: 'NET-2',
        name: 'Network Policies',
        description: 'Network access policies are enforced',
        status: 'compliant' as const,
        evidence: ['Network policies configured'],
      },
    ];

    const score = controls.filter(c => c.status === 'compliant').length * 10;

    return {
      name: 'network',
      score,
      maxScore: controls.length * 10,
      controls,
    };
  }

  /**
   * Test Application pillar
   */
  async testApplicationPillar(config: any): Promise<ZTAPillar> {
    const controls = this.config.controlStatuses?.application || [
      {
        id: 'APP-1',
        name: 'Application Access Policies',
        description: 'Application access is controlled by policies',
        status: 'compliant' as const,
        evidence: ['Application access policies implemented'],
      },
      {
        id: 'APP-2',
        name: 'API Security',
        description: 'APIs are secured with authentication and authorization',
        status: 'compliant' as const,
        evidence: ['API security implemented'],
      },
    ];

    const score = controls.filter(c => c.status === 'compliant').length * 10;

    return {
      name: 'application',
      score,
      maxScore: controls.length * 10,
      controls,
    };
  }

  /**
   * Test Data pillar
   */
  async testDataPillar(config: any): Promise<ZTAPillar> {
    const controls = this.config.controlStatuses?.data || [
      {
        id: 'DATA-1',
        name: 'Data Access Controls',
        description: 'Data access is controlled by policies',
        status: 'compliant' as const,
        evidence: ['Data access controls implemented'],
      },
      {
        id: 'DATA-2',
        name: 'Data Encryption',
        description: 'Data is encrypted at rest and in transit',
        status: 'compliant' as const,
        evidence: ['Data encryption implemented'],
      },
      {
        id: 'DATA-3',
        name: 'Data Loss Prevention',
        description: 'Data loss prevention controls are in place',
        status: 'partial' as const,
        evidence: ['Basic DLP controls implemented'],
      },
    ];

    const score = controls.filter(c => c.status === 'compliant').length * 10 +
                  controls.filter(c => c.status === 'partial').length * 5;

    return {
      name: 'data',
      score,
      maxScore: controls.length * 10,
      controls,
    };
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(assessment: ComplianceAssessment): Promise<string> {
    const report = `
# NIST 800-207 Compliance Report

**Framework:** ${assessment.framework}
**Assessment Date:** ${assessment.assessment.timestamp.toISOString()}
**Overall Score:** ${assessment.compliancePercentage.toFixed(1)}%
**Compliant:** ${assessment.compliant ? 'Yes' : 'No'}

## Pillar Assessments

${assessment.assessment.pillars.map(pillar => `
### ${pillar.name.charAt(0).toUpperCase() + pillar.name.slice(1)} Pillar
- **Score:** ${pillar.score}/${pillar.maxScore}
- **Compliance:** ${((pillar.score / pillar.maxScore) * 100).toFixed(1)}%

**Controls:**
${pillar.controls.map(control => `
- ${control.name} (${control.id}): ${control.status}
  - ${control.description}
`).join('')}
`).join('')}

## Gaps
${assessment.assessment.gaps.length > 0 
  ? assessment.assessment.gaps.map(gap => `- ${gap}`).join('\n')
  : '- No gaps identified'
}

## Recommendations
${assessment.assessment.recommendations.length > 0
  ? assessment.assessment.recommendations.map(rec => `- ${rec}`).join('\n')
  : '- No recommendations'
}
`;

    return report;
  }
}

