import { ref } from 'vue';
import axios from 'axios';

const API_BASE = '/api/agent-tests';

export interface UserContext {
  userId: string;
  email: string;
  role: string;
  permissions: string[];
}

export interface Resource {
  id: string;
  type: string;
  attributes?: Record<string, any>;
}

export interface OAuthConfig {
  authorizationEndpoint?: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scopes: string[];
}

export interface DelegatedAccessTestRequest {
  agentId: string;
  userContext: UserContext;
  resources: Resource[];
  actions: string[];
  oauthConfig?: OAuthConfig;
}

export interface DirectAccessTestRequest {
  agentId: string;
  agentType: 'autonomous' | 'event-driven' | 'scheduled';
  resources: Resource[];
  actions: string[];
  oauthConfig?: OAuthConfig;
}

export interface MultiServiceTestRequest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userContext?: {
    userId: string;
    permissions: string[];
  };
  services: Array<{
    serviceId: string;
    resource: Resource;
    action: string;
    expectedAllowed: boolean;
  }>;
}

export interface DynamicAccessScenario {
  name: string;
  context: {
    ipAddress?: string;
    timeOfDay?: string;
    location?: string;
    device?: string;
    additionalAttributes?: Record<string, any>;
  };
  requestedPermission: string;
  expectedGranted: boolean;
  jitAccess?: boolean;
}

export interface DynamicAccessTestRequest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userContext?: {
    userId: string;
    permissions: string[];
  };
  scenarios: DynamicAccessScenario[];
}

export interface AuditTrailValidationRequest {
  agentId: string;
  agentType: 'delegated' | 'direct';
  userId?: string;
  actions: Array<{
    serviceId: string;
    action: string;
    resourceId: string;
    resourceType: string;
    timestamp: Date;
    expectedLogged: boolean;
  }>;
  auditSources?: string[];
  retentionPeriod?: number;
}

export interface AgentTestResult {
  testType: string;
  testName: string;
  passed: boolean;
  timestamp: Date;
  agentId: string;
  allowed?: boolean;
  expectedAllowed?: boolean;
  decisionReason?: string;
  permissionBoundariesRespected?: boolean;
  userPermissionsEnforced?: boolean;
  contextAwareDecision?: boolean;
  multiServiceConsistency?: boolean;
  details?: Record<string, any>;
}

export interface AuditTrailValidationResult {
  testType: string;
  testName: string;
  passed: boolean;
  timestamp: Date;
  agentId: string;
  auditLogComplete: boolean;
  auditLogIntegrity: boolean;
  crossServiceCorrelation: boolean;
  retentionCompliance?: boolean;
  missingEntries?: Array<{
    serviceId: string;
    action: string;
    timestamp: Date;
  }>;
  correlationIssues?: string[];
  integrityIssues?: string[];
  details: Record<string, any>;
}

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  agentId: string;
  agentType: 'delegated' | 'direct';
  action: string;
  serviceId: string;
  resourceId: string;
  resourceType: string;
  allowed: boolean;
}

export function useAgentTests() {
  const loading = ref(false);
  const error = ref<string | null>(null);

  /**
   * Run delegated access tests
   */
  const runDelegatedAccessTests = async (
    request: DelegatedAccessTestRequest
  ): Promise<AgentTestResult> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/delegated-access`, request);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run delegated access tests';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Run direct access tests
   */
  const runDirectAccessTests = async (
    request: DirectAccessTestRequest
  ): Promise<AgentTestResult> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/direct-access`, request);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run direct access tests';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Test multi-service access
   */
  const testMultiServiceAccess = async (
    request: MultiServiceTestRequest
  ): Promise<{ agentId: string; testType: string; result: AgentTestResult }> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/multi-service`, request);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to test multi-service access';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Test dynamic access
   */
  const testDynamicAccess = async (
    request: DynamicAccessTestRequest
  ): Promise<AgentTestResult[]> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/dynamic-access`, request);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to test dynamic access';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Get agent audit trail
   */
  const getAuditTrail = async (
    agentId: string,
    filters?: {
      startDate?: Date;
      endDate?: Date;
      serviceId?: string;
      action?: string;
    }
  ): Promise<AuditLogEntry[]> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(`${API_BASE}/audit-trail/${agentId}`, {
        params: filters,
      });
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to get audit trail';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Validate audit trail
   */
  const validateAuditTrail = async (
    request: AuditTrailValidationRequest
  ): Promise<{ agentId: string; validationResult: AuditTrailValidationResult }> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/audit-trail/validate`, request);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to validate audit trail';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    error,
    runDelegatedAccessTests,
    runDirectAccessTests,
    testMultiServiceAccess,
    testDynamicAccess,
    getAuditTrail,
    validateAuditTrail,
  };
}
