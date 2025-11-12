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
        // TODO: Implement SOC 2 controls
        return [];
      case ComplianceFramework.PCI_DSS:
        // TODO: Implement PCI-DSS controls
        return [];
      case ComplianceFramework.HIPAA:
        // TODO: Implement HIPAA controls
        return [];
      case ComplianceFramework.GDPR:
        // TODO: Implement GDPR controls
        return [];
      case ComplianceFramework.ISO_27001:
        // TODO: Implement ISO 27001 controls
        return [];
      case ComplianceFramework.NIST_CSF:
        // TODO: Implement NIST CSF controls
        return [];
      case ComplianceFramework.OWASP_ASVS:
        // TODO: Implement OWASP ASVS controls
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

