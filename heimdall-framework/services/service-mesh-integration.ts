/**
 * Service Mesh Integration Service
 * 
 * Integrates with service mesh technologies (Istio, Envoy) for access control testing
 */

import { User, Resource } from '../core/types';

export interface ServiceMeshConfig {
  type: 'istio' | 'envoy' | 'linkerd';
  controlPlaneEndpoint: string;
  namespace?: string;
  credentials?: {
    token?: string;
    certificate?: string;
  };
  options?: {
    envoyAdminPort?: number;
    k8sApiEndpoint?: string;
    prometheusEndpoint?: string;
    [key: string]: any;
  };
}

export interface ServiceMeshPolicy {
  name: string;
  namespace: string;
  type: 'AuthorizationPolicy' | 'PeerAuthentication' | 'RequestAuthentication';
  spec: any;
}

export interface ServiceToServiceTest {
  sourceService: string;
  targetService: string;
  path: string;
  method: string;
  expectedAllowed: boolean;
}

export interface ServiceMeshTestResult {
  test: ServiceToServiceTest;
  allowed: boolean;
  policyApplied?: string;
  error?: string;
}

export class ServiceMeshIntegration {
  private config: ServiceMeshConfig;

  constructor(config: ServiceMeshConfig) {
    this.config = config;
  }

  /**
   * Test service-to-service access control
   */
  async testServiceToServiceAccess(
    test: ServiceToServiceTest
  ): Promise<ServiceMeshTestResult> {
    try {
      switch (this.config.type) {
        case 'istio':
          return await this.testIstioAccess(test);
        case 'envoy':
          return await this.testEnvoyAccess(test);
        default:
          throw new Error(`Unsupported service mesh: ${this.config.type}`);
      }
    } catch (error: any) {
      return {
        test,
        allowed: false,
        error: error.message,
      };
    }
  }

  /**
   * Test Istio access control
   */
  private async testIstioAccess(
    test: ServiceToServiceTest
  ): Promise<ServiceMeshTestResult> {
    try {
      // Query Istio Kubernetes API for AuthorizationPolicy
      const policy = await this.getIstioPolicy(test);
      
      if (!policy) {
        // No policy found - default allow in Istio
        return {
          test,
          allowed: true,
        };
      }
      
      const allowed = this.evaluateIstioPolicy(policy, test);
      
      return {
        test,
        allowed,
        policyApplied: policy.name,
      };
    } catch (error: any) {
      return {
        test,
        allowed: false,
        error: error.message,
      };
    }
  }

  /**
   * Test Envoy access control
   */
  private async testEnvoyAccess(
    test: ServiceToServiceTest
  ): Promise<ServiceMeshTestResult> {
    try {
      // Query Envoy admin API for RBAC configuration
      const envoyAdminPort = this.config.options?.envoyAdminPort || 15000;
      const serviceName = test.targetService;
      
      // Get RBAC configuration from Envoy
      const rbacConfig = await this.getEnvoyRBACConfig(serviceName, envoyAdminPort);
      
      if (!rbacConfig) {
        // No RBAC configured - default allow
        return {
          test,
          allowed: true,
        };
      }
      
      // Evaluate RBAC rules
      const allowed = this.evaluateEnvoyRBAC(rbacConfig, test);
      
      return {
        test,
        allowed,
        policyApplied: 'envoy-rbac',
      };
    } catch (error: any) {
      return {
        test,
        allowed: false,
        error: error.message,
      };
    }
  }

  /**
   * Get Envoy RBAC configuration
   */
  private async getEnvoyRBACConfig(
    serviceName: string,
    adminPort: number
  ): Promise<any> {
    try {
      // Query Envoy admin API
      const response = await fetch(
        `http://${serviceName}:${adminPort}/config_dump?include_eds`,
        {
          headers: {
            'Authorization': `Bearer ${this.config.credentials?.token || ''}`,
          },
        }
      );

      if (!response.ok) {
        return null;
      }

      const config = await response.json();
      
      // Extract RBAC filter configuration
      for (const configDump of config.configs || []) {
        if (configDump['@type']?.includes('listener')) {
          const listeners = configDump.dynamic_listeners || configDump.static_listeners || [];
          for (const listener of listeners) {
            const filterChains = listener.filter_chains || [];
            for (const chain of filterChains) {
              const filters = chain.filters || [];
              for (const filter of filters) {
                if (filter.name === 'envoy.filters.network.rbac') {
                  return filter.typed_config?.rules || null;
                }
              }
            }
          }
        }
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Evaluate Envoy RBAC rules
   */
  private evaluateEnvoyRBAC(rbacConfig: any, test: ServiceToServiceTest): boolean {
    const policies = rbacConfig.policies || {};
    
    for (const [policyName, policy] of Object.entries(policies)) {
      const policyData = policy as any;
      const permissions = policyData.permissions || [];
      const principals = policyData.principals || [];

      // Check if source matches principals
      const sourceMatches = this.matchesEnvoyPrincipals(principals, test.sourceService);
      
      // Check if action matches permissions
      const actionMatches = this.matchesEnvoyPermissions(permissions, test);

      if (sourceMatches && actionMatches) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if source matches Envoy principals
   */
  private matchesEnvoyPrincipals(principals: any[], sourceService: string): boolean {
    for (const principal of principals) {
      if (principal.authenticated?.principal_name?.exact) {
        const expectedPrincipal = principal.authenticated.principal_name.exact;
        if (expectedPrincipal.includes(sourceService)) {
          return true;
        }
      }
      if (principal.any) {
        return true; // Allow any principal
      }
    }
    return false;
  }

  /**
   * Check if action matches Envoy permissions
   */
  private matchesEnvoyPermissions(permissions: any[], test: ServiceToServiceTest): boolean {
    for (const permission of permissions) {
      if (permission.any) {
        return true; // Allow any action
      }
      if (permission.header?.name && permission.header?.exact_match) {
        // Check header-based permissions
        // This is simplified - would need actual request headers
        return true;
      }
      if (permission.url_path?.path?.exact) {
        if (permission.url_path.path.exact === test.path) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Get Istio AuthorizationPolicy
   */
  private async getIstioPolicy(
    test: ServiceToServiceTest
  ): Promise<ServiceMeshPolicy | null> {
    try {
      // Query Kubernetes API for Istio AuthorizationPolicy
      const k8sApiEndpoint = this.config.options?.k8sApiEndpoint || 
                            process.env.KUBERNETES_SERVICE_HOST || 
                            'https://kubernetes.default.svc';
      const namespace = this.config.namespace || 'default';
      const token = this.config.credentials?.token || 
                    process.env.KUBERNETES_SERVICE_ACCOUNT_TOKEN ||
                    '';

      // Query AuthorizationPolicy CRD
      const response = await fetch(
        `${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      if (!response.ok) {
        // Fallback: Try local file or mock
        return this.getIstioPolicyFromFile(test);
      }

      const data = await response.json();
      const items = data.items || [];

      // Find policy that matches the target service
      for (const item of items) {
        const spec = item.spec || {};
        const selector = spec.selector || {};
        const matchLabels = selector.matchLabels || {};

        // Check if policy applies to target service
        if (matchLabels.app === test.targetService || 
            matchLabels.service === test.targetService ||
            !Object.keys(matchLabels).length) {
          return {
            name: item.metadata.name,
            namespace: item.metadata.namespace || namespace,
            type: 'AuthorizationPolicy',
            spec: spec,
          };
        }
      }

      return null;
    } catch (error: any) {
      // Fallback: Try local file
      return this.getIstioPolicyFromFile(test);
    }
  }

  /**
   * Get Istio policy from local file (fallback)
   */
  private async getIstioPolicyFromFile(
    test: ServiceToServiceTest
  ): Promise<ServiceMeshPolicy | null> {
    try {
      const fs = require('fs/promises');
      const path = require('path');
      
      const policyPath = path.join(
        process.cwd(),
        'policies',
        'istio',
        `${test.targetService}-policy.yaml`
      );

      const content = await fs.readFile(policyPath, 'utf-8');
      // Parse YAML (simplified - would use yaml parser)
      const yaml = require('yaml');
      const policy = yaml.parse(content);

      return {
        name: policy.metadata?.name || 'policy',
        namespace: policy.metadata?.namespace || this.config.namespace || 'default',
        type: 'AuthorizationPolicy',
        spec: policy.spec || {},
      };
    } catch {
      return null;
    }
  }

  /**
   * Evaluate Istio policy
   */
  private evaluateIstioPolicy(
    policy: ServiceMeshPolicy,
    test: ServiceToServiceTest
  ): boolean {
    // Simplified evaluation - would need full Istio policy parsing
    const spec = policy.spec || {};
    
    // Check action
    if (spec.action === 'DENY') {
      return false;
    }
    
    // Check rules
    if (spec.rules) {
      for (const rule of spec.rules) {
        if (this.matchesIstioRule(rule, test)) {
          return spec.action !== 'DENY';
        }
      }
    }
    
    return true;
  }

  /**
   * Check if test matches Istio rule
   */
  private matchesIstioRule(rule: any, test: ServiceToServiceTest): boolean {
    // Check source
    if (rule.from) {
      const sourceMatches = rule.from.some((from: any) => {
        if (from.source?.principals) {
          return from.source.principals.includes(`cluster.local/ns/${this.config.namespace}/sa/${test.sourceService}`);
        }
        return true;
      });
      if (!sourceMatches) return false;
    }
    
    // Check destination
    if (rule.to) {
      const destMatches = rule.to.some((to: any) => {
        if (to.operation?.hosts) {
          return to.operation.hosts.includes(test.targetService);
        }
        if (to.operation?.paths) {
          return to.operation.paths.includes(test.path);
        }
        if (to.operation?.methods) {
          return to.operation.methods.includes(test.method);
        }
        return true;
      });
      if (!destMatches) return false;
    }
    
    return true;
  }

  /**
   * Create Istio AuthorizationPolicy
   */
  async createIstioPolicy(
    policy: ServiceMeshPolicy
  ): Promise<ServiceMeshPolicy> {
    try {
      const k8sApiEndpoint = this.config.options?.k8sApiEndpoint || 
                            process.env.KUBERNETES_SERVICE_HOST || 
                            'https://kubernetes.default.svc';
      const namespace = policy.namespace || this.config.namespace || 'default';
      const token = this.config.credentials?.token || 
                    process.env.KUBERNETES_SERVICE_ACCOUNT_TOKEN ||
                    '';

      // Create AuthorizationPolicy resource
      const policyResource = {
        apiVersion: 'security.istio.io/v1beta1',
        kind: 'AuthorizationPolicy',
        metadata: {
          name: policy.name,
          namespace: namespace,
        },
        spec: policy.spec,
      };

      const response = await fetch(
        `${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(policyResource),
        }
      );

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Failed to create Istio policy: ${response.statusText} - ${error}`);
      }

      const created = await response.json();
      
      return {
        name: created.metadata.name,
        namespace: created.metadata.namespace,
        type: 'AuthorizationPolicy',
        spec: created.spec,
      };
    } catch (error: any) {
      // Fallback: Save to file
      return await this.saveIstioPolicyToFile(policy);
    }
  }

  /**
   * Save Istio policy to file (fallback)
   */
  private async saveIstioPolicyToFile(
    policy: ServiceMeshPolicy
  ): Promise<ServiceMeshPolicy> {
    try {
      const fs = require('fs/promises');
      const path = require('path');
      const yaml = require('yaml');

      const policyDir = path.join(process.cwd(), 'policies', 'istio');
      await fs.mkdir(policyDir, { recursive: true });

      const policyResource = {
        apiVersion: 'security.istio.io/v1beta1',
        kind: 'AuthorizationPolicy',
        metadata: {
          name: policy.name,
          namespace: policy.namespace || 'default',
        },
        spec: policy.spec,
      };

      const yamlContent = yaml.stringify(policyResource);
      const filePath = path.join(policyDir, `${policy.name}.yaml`);
      await fs.writeFile(filePath, yamlContent);

      return policy;
    } catch (error: any) {
      throw new Error(`Failed to save Istio policy: ${error.message}`);
    }
  }

  /**
   * Test microservices access patterns
   */
  async testMicroservicesAccess(
    services: string[],
    user: User
  ): Promise<ServiceMeshTestResult[]> {
    const results: ServiceMeshTestResult[] = [];
    
    // Test access between all service pairs
    for (let i = 0; i < services.length; i++) {
      for (let j = i + 1; j < services.length; j++) {
        const test: ServiceToServiceTest = {
          sourceService: services[i],
          targetService: services[j],
          path: '/api/v1',
          method: 'GET',
          expectedAllowed: true,
        };
        
        const result = await this.testServiceToServiceAccess(test);
        results.push(result);
      }
    }
    
    return results;
  }

  /**
   * Validate service mesh policies
   */
  async validatePolicies(
    policies: ServiceMeshPolicy[]
  ): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];
    
    for (const policy of policies) {
      // Validate policy structure
      if (!policy.name) {
        errors.push(`Policy missing name`);
      }
      if (!policy.spec) {
        errors.push(`Policy ${policy.name} missing spec`);
      }
      
      // Validate based on type
      if (policy.type === 'AuthorizationPolicy') {
        const specErrors = this.validateAuthorizationPolicy(policy);
        errors.push(...specErrors);
      }
    }
    
    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate AuthorizationPolicy
   */
  private validateAuthorizationPolicy(policy: ServiceMeshPolicy): string[] {
    const errors: string[] = [];
    const spec = policy.spec || {};
    
    if (!spec.action) {
      errors.push(`Policy ${policy.name} missing action`);
    } else if (!['ALLOW', 'DENY'].includes(spec.action)) {
      errors.push(`Policy ${policy.name} has invalid action: ${spec.action}`);
    }
    
    return errors;
  }

  /**
   * Get service mesh metrics
   */
  async getServiceMeshMetrics(): Promise<{
    totalPolicies: number;
    services: number;
    requests: number;
    deniedRequests: number;
  }> {
    try {
      if (this.config.type === 'istio') {
        return await this.getIstioMetrics();
      } else if (this.config.type === 'envoy') {
        return await this.getEnvoyMetrics();
      }
    } catch (error) {
      // Return empty metrics on error
    }

    return {
      totalPolicies: 0,
      services: 0,
      requests: 0,
      deniedRequests: 0,
    };
  }

  /**
   * Get Istio metrics
   */
  private async getIstioMetrics(): Promise<{
    totalPolicies: number;
    services: number;
    requests: number;
    deniedRequests: number;
  }> {
    try {
      const k8sApiEndpoint = this.config.options?.k8sApiEndpoint || 
                            process.env.KUBERNETES_SERVICE_HOST || 
                            'https://kubernetes.default.svc';
      const namespace = this.config.namespace || 'default';
      const token = this.config.credentials?.token || '';

      // Get AuthorizationPolicy count
      const policyResponse = await fetch(
        `${k8sApiEndpoint}/apis/security.istio.io/v1beta1/namespaces/${namespace}/authorizationpolicies`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      let totalPolicies = 0;
      if (policyResponse.ok) {
        const data = await policyResponse.json();
        totalPolicies = data.items?.length || 0;
      }

      // Get service count
      const serviceResponse = await fetch(
        `${k8sApiEndpoint}/api/v1/namespaces/${namespace}/services`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      let services = 0;
      if (serviceResponse.ok) {
        const data = await serviceResponse.json();
        services = data.items?.length || 0;
      }

      // Get metrics from Istio Prometheus (if available)
      const prometheusEndpoint = this.config.options?.prometheusEndpoint || 
                                 'http://prometheus.istio-system:9090';
      
      let requests = 0;
      let deniedRequests = 0;

      try {
        const metricsResponse = await fetch(
          `${prometheusEndpoint}/api/v1/query?query=istio_requests_total{namespace="${namespace}"}`
        );
        
        if (metricsResponse.ok) {
          const metricsData = await metricsResponse.json();
          const result = metricsData.data?.result || [];
          requests = result.reduce((sum: number, r: any) => sum + parseFloat(r.value[1] || 0), 0);

          // Get denied requests
          const deniedResponse = await fetch(
            `${prometheusEndpoint}/api/v1/query?query=istio_requests_total{namespace="${namespace}",response_code="403"}`
          );
          
          if (deniedResponse.ok) {
            const deniedData = await deniedResponse.json();
            const deniedResult = deniedData.data?.result || [];
            deniedRequests = deniedResult.reduce((sum: number, r: any) => sum + parseFloat(r.value[1] || 0), 0);
          }
        }
      } catch {
        // Prometheus not available - use defaults
      }

      return {
        totalPolicies,
        services,
        requests: Math.round(requests),
        deniedRequests: Math.round(deniedRequests),
      };
    } catch {
      return {
        totalPolicies: 0,
        services: 0,
        requests: 0,
        deniedRequests: 0,
      };
    }
  }

  /**
   * Get Envoy metrics
   */
  private async getEnvoyMetrics(): Promise<{
    totalPolicies: number;
    services: number;
    requests: number;
    deniedRequests: number;
  }> {
    try {
      const envoyAdminPort = this.config.options?.envoyAdminPort || 15000;
      
      // Query Envoy admin API for stats
      const statsResponse = await fetch(
        `http://localhost:${envoyAdminPort}/stats?format=json`
      );

      let requests = 0;
      let deniedRequests = 0;

      if (statsResponse.ok) {
        const stats = await statsResponse.json();
        const statsArray = stats.stats || [];

        for (const stat of statsArray) {
          if (stat.name === 'http.incoming_rq_total') {
            requests += parseInt(stat.value || 0);
          }
          if (stat.name === 'rbac.denied') {
            deniedRequests += parseInt(stat.value || 0);
          }
        }
      }

      return {
        totalPolicies: 0, // Would need to query Envoy config
        services: 0, // Would need to query service registry
        requests,
        deniedRequests,
      };
    } catch {
      return {
        totalPolicies: 0,
        services: 0,
        requests: 0,
        deniedRequests: 0,
      };
    }
  }
}

