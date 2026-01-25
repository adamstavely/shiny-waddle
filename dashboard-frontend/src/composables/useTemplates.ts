import { ref } from 'vue';
import axios from 'axios';

const API_BASE = '/api/templates';

export interface Template {
  name: string;
  displayName: string;
  description: string;
}

export interface TemplateDetail extends Template {
  fullDescription: string;
  configSchema: any;
}

export interface CreateFromTemplateConfig {
  applicationName: string;
  config: {
    roles?: string[];
    resources?: string[];
    actions?: string[];
    departments?: string[];
    clearanceLevels?: string[];
    dataClassifications?: string[];
    projects?: string[];
    coveredEntities?: string[];
    businessAssociates?: string[];
    dataControllers?: string[];
    dataProcessors?: string[];
    euMemberStates?: string[];
    applicationId?: string;
  };
  outputFileName?: string;
}

export function useTemplates() {
  const loading = ref(false);
  const error = ref<string | null>(null);

  const listTemplates = async (): Promise<Template[]> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(API_BASE);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load templates';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const getTemplate = async (name: string): Promise<TemplateDetail> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.get(`${API_BASE}/${name}`);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to load template';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const createFromTemplate = async (
    templateName: string,
    config: CreateFromTemplateConfig
  ) => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/${templateName}/create`, config);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to create policy from template';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    error,
    listTemplates,
    getTemplate,
    createFromTemplate,
  };
}
