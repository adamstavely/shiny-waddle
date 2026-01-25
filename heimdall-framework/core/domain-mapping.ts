/**
 * Centralized domain mapping utility
 * Maps test types to their corresponding domains
 */

import { TestType, TestDomain } from './types';

/**
 * Maps a test type to its corresponding domain
 */
export function getDomainFromTestType(testType: TestType): TestDomain {
  const domainMap: Record<TestType, TestDomain> = {
    // API Security domain
    'api-security': 'api_security',
    'api-gateway': 'api_security',
    
    // Platform Config domain
    'network-policy': 'platform_config',
    'distributed-systems': 'platform_config',
    
    // Identity domain
    'access-control': 'identity',
    'rls-cls': 'identity',
    
    // Data Contracts domain
    'data-contract': 'data_contracts',
    'data-pipeline': 'data_contracts', // Data pipelines are part of data contracts
    'dlp': 'data_contracts', // DLP is part of data contracts
    'dataset-health': 'data_contracts', // Dataset health is part of data contracts
    
    // Salesforce domain
    'salesforce-config': 'salesforce',
    'salesforce-security': 'salesforce',
    'salesforce-experience-cloud': 'salesforce',
    
    // Elastic domain
    'elastic-config': 'elastic',
    'elastic-security': 'elastic',
    
    // IDP/K8s domain
    'k8s-security': 'idp_platform',
    'k8s-workload': 'idp_platform',
    'idp-compliance': 'idp_platform',
    
    // Platform Config domain (additional test types)
    'servicenow-config': 'platform_config',
    'environment-config': 'platform_config',
    'secrets-management': 'platform_config',
    'config-drift': 'platform_config',
    'environment-policies': 'platform_config',
  };
  
  return domainMap[testType] || 'platform_config'; // Default fallback
}

/**
 * Gets the display name for a domain
 */
export function getDomainDisplayName(domain: TestDomain): string {
  const displayNames: Record<TestDomain, string> = {
    'api_security': 'API Security',
    'platform_config': 'Platform Configuration',
    'identity': 'Identity',
    'data_contracts': 'Data Contracts',
    'salesforce': 'Salesforce',
    'elastic': 'Elastic',
    'idp_platform': 'IDP / Kubernetes',
  };
  
  return displayNames[domain] || domain;
}

