import { ref } from 'vue';
import axios from 'axios';
import type {
  SalesforceExperienceCloudConfigEntity,
  SalesforceExperienceCloudTestResultEntity,
} from '../types/salesforce-experience-cloud';

const API_BASE = '/api/salesforce-experience-cloud';

export function useSalesforceExperienceCloud() {
  const loading = ref(false);
  const error = ref<string | null>(null);

  // Configuration Management
  const createConfig = async (config: Partial<SalesforceExperienceCloudConfigEntity>) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/configs`, config);
      return response.data as SalesforceExperienceCloudConfigEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to create configuration';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getConfigs = async () => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(`${API_BASE}/configs`);
      return response.data as SalesforceExperienceCloudConfigEntity[];
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load configurations';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getConfig = async (id: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(`${API_BASE}/configs/${id}`);
      return response.data as SalesforceExperienceCloudConfigEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load configuration';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const updateConfig = async (id: string, config: Partial<SalesforceExperienceCloudConfigEntity>) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.patch(`${API_BASE}/configs/${id}`, config);
      return response.data as SalesforceExperienceCloudConfigEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to update configuration';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const deleteConfig = async (id: string) => {
    loading.value = true;
    error.value = null;
    try {
      await axios.delete(`${API_BASE}/configs/${id}`);
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to delete configuration';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  // Test Execution
  const runGuestAccessTest = async (configId: string, cookies?: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/guest-access`, { configId, cookies });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run guest access test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runAuthenticatedAccessTest = async (configId: string, cookies?: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/authenticated-access`, { configId, cookies });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run authenticated access test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runGraphQLTest = async (configId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/graphql`, { configId });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run GraphQL test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runSelfRegistrationTest = async (configId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/self-registration`, { configId });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run self-registration test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runRecordListTest = async (configId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/record-lists`, { configId });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run record list test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runHomeURLTest = async (configId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/home-urls`, { configId });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run home URL test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runObjectAccessTest = async (configId: string, objects: string[]) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/object-access`, { configId, objects });
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run object access test';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runFullAudit = async (configId: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/tests/full-audit`, { configId });
      return response.data as SalesforceExperienceCloudTestResultEntity[];
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run full audit';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  // Results Management
  const getResults = async (configId?: string) => {
    loading.value = true;
    error.value = null;
    try {
      const params = configId ? { configId } : {};
      const response = await axios.get(`${API_BASE}/results`, { params });
      return response.data as SalesforceExperienceCloudTestResultEntity[];
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load results';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getResult = async (id: string) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(`${API_BASE}/results/${id}`);
      return response.data as SalesforceExperienceCloudTestResultEntity;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load result';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getSummary = async () => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(API_BASE);
      return response.data as { configs: number; results: number };
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load summary';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    error,
    createConfig,
    getConfigs,
    getConfig,
    updateConfig,
    deleteConfig,
    runGuestAccessTest,
    runAuthenticatedAccessTest,
    runGraphQLTest,
    runSelfRegistrationTest,
    runRecordListTest,
    runHomeURLTest,
    runObjectAccessTest,
    runFullAudit,
    getResults,
    getResult,
    getSummary,
  };
}
