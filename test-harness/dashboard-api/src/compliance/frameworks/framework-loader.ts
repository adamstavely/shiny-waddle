import { ComplianceControl, ComplianceFramework } from '../entities/compliance.entity';
import { NIST_800_53_REV_4_CONTROLS } from './nist-800-53-rev4.controls';
import { NIST_800_53_REV_5_CONTROLS } from './nist-800-53-rev5.controls';

/**
 * Framework Loader
 * Extensible system for loading compliance framework controls.
 * New frameworks can be added by:
 * 1. Creating a new controls file (e.g., soc2.controls.ts)
 * 2. Adding the framework enum value
 * 3. Adding the loader case below
 */
export class FrameworkLoader {
  /**
   * Load controls for a specific framework
   */
  static loadControls(framework: ComplianceFramework): ComplianceControl[] {
    switch (framework) {
      case ComplianceFramework.NIST_800_53_REV_4:
        return NIST_800_53_REV_4_CONTROLS;
      case ComplianceFramework.NIST_800_53_REV_5:
        return NIST_800_53_REV_5_CONTROLS;
      case ComplianceFramework.SOC_2:
        // NOTE: SOC 2 controls not yet implemented
        // To implement: Create soc2.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.PCI_DSS:
        // NOTE: PCI-DSS controls not yet implemented
        // To implement: Create pci-dss.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.HIPAA:
        // NOTE: HIPAA controls not yet implemented
        // To implement: Create hipaa.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.GDPR:
        // NOTE: GDPR controls not yet implemented
        // To implement: Create gdpr.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.ISO_27001:
        // NOTE: ISO 27001 controls not yet implemented
        // To implement: Create iso-27001.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.NIST_CSF:
        // NOTE: NIST CSF controls not yet implemented
        // To implement: Create nist-csf.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      case ComplianceFramework.OWASP_ASVS:
        // NOTE: OWASP ASVS controls not yet implemented
        // To implement: Create owasp-asvs.controls.ts following the pattern of nist-800-53-rev4.controls.ts
        return [];
      default:
        return [];
    }
  }

  /**
   * Get all available frameworks
   */
  static getAvailableFrameworks(): ComplianceFramework[] {
    return Object.values(ComplianceFramework);
  }

  /**
   * Get framework metadata
   */
  static getFrameworkMetadata(framework: ComplianceFramework): {
    name: string;
    version?: string;
    description: string;
    controlCount: number;
  } {
    const controls = this.loadControls(framework);
    
    const metadata: Record<ComplianceFramework, { name: string; version?: string; description: string }> = {
      [ComplianceFramework.NIST_800_53_REV_4]: {
        name: 'NIST 800-53',
        version: 'Revision 4',
        description: 'Security and Privacy Controls for Federal Information Systems and Organizations',
      },
      [ComplianceFramework.NIST_800_53_REV_5]: {
        name: 'NIST 800-53',
        version: 'Revision 5',
        description: 'Security and Privacy Controls for Information Systems and Organizations',
      },
      [ComplianceFramework.SOC_2]: {
        name: 'SOC 2',
        description: 'System and Organization Controls 2 - Trust Services Criteria',
      },
      [ComplianceFramework.PCI_DSS]: {
        name: 'PCI-DSS',
        description: 'Payment Card Industry Data Security Standard',
      },
      [ComplianceFramework.HIPAA]: {
        name: 'HIPAA',
        description: 'Health Insurance Portability and Accountability Act',
      },
      [ComplianceFramework.GDPR]: {
        name: 'GDPR',
        description: 'General Data Protection Regulation',
      },
      [ComplianceFramework.ISO_27001]: {
        name: 'ISO 27001',
        description: 'Information Security Management System',
      },
      [ComplianceFramework.NIST_CSF]: {
        name: 'NIST CSF',
        description: 'NIST Cybersecurity Framework',
      },
      [ComplianceFramework.OWASP_ASVS]: {
        name: 'OWASP ASVS',
        description: 'OWASP Application Security Verification Standard',
      },
    };

    return {
      ...metadata[framework],
      controlCount: controls.length,
    };
  }
}

