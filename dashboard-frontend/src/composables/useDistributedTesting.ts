import { ref } from 'vue';
import axios from 'axios';

const API_BASE = '/api/distributed';

export interface MultiRegionTestRequest {
  name: string;
  testType: 'access-control' | 'policy-consistency' | 'synchronization';
  user?: {
    id: string;
    email?: string;
    role?: string;
    attributes?: Record<string, any>;
  };
  resource?: {
    id: string;
    type?: string;
    attributes?: Record<string, any>;
  };
  action?: string;
  regions?: string[];
  expectedResult?: boolean;
  timeout?: number;
  applicationId?: string;
  executionMode?: 'parallel' | 'sequential';
  retryOnFailure?: boolean;
  maxRetries?: number;
}

export interface PolicyConsistencyCheckRequest {
  applicationId?: string;
  regions?: string[];
  policyIds?: string[];
  checkTypes?: ('version' | 'configuration' | 'evaluation')[];
}

export interface PolicySyncTestRequest {
  applicationId?: string;
  regions?: string[];
  policyId?: string;
  testScenarios?: ('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[];
}

export function useDistributedTesting() {
  const loading = ref(false);
  const error = ref<string | null>(null);

  /**
   * Execute multi-region test
   */
  const executeMultiRegionTest = async (
    request: MultiRegionTestRequest
  ) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(
        `${API_BASE}/tests/multi-region/execute`,
        request
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to execute multi-region test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Get multi-region test status
   */
  const getMultiRegionTestStatus = async (testId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(
        `${API_BASE}/tests/multi-region/${testId}/status`
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to get test status';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Check policy consistency
   */
  const checkPolicyConsistency = async (
    request: PolicyConsistencyCheckRequest
  ) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(
        `${API_BASE}/tests/policy-consistency/check`,
        request
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to check policy consistency';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Get policy consistency report
   */
  const getPolicyConsistencyReport = async (reportId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(
        `${API_BASE}/tests/policy-consistency/report/${reportId}`
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to get consistency report';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Test policy synchronization
   */
  const testPolicySynchronization = async (
    request: PolicySyncTestRequest
  ) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(
        `${API_BASE}/tests/policy-sync/test`,
        request
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to test policy synchronization';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  /**
   * Get policy synchronization report
   */
  const getPolicySyncReport = async (reportId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(
        `${API_BASE}/tests/policy-sync/report/${reportId}`
      );
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to get sync report';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    error,
    executeMultiRegionTest,
    getMultiRegionTestStatus,
    checkPolicyConsistency,
    getPolicyConsistencyReport,
    testPolicySynchronization,
    getPolicySyncReport,
  };
}
