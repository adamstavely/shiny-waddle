import { ref } from 'vue';
import axios from 'axios';

const API_BASE = '/api/batch';

export interface BatchOperation {
  type: 'test' | 'validate' | 'report';
  suite?: string;
  policyFile?: string;
  output?: string;
  config?: string;
}

export interface BatchFile {
  operations: BatchOperation[];
  config?: {
    outputDir?: string;
    parallel?: boolean;
    stopOnError?: boolean;
  };
}

export interface BatchResult {
  summary: {
    total: number;
    successful: number;
    failed: number;
  };
  results: Array<{
    operation: BatchOperation;
    success: boolean;
    error?: string;
    data?: any;
  }>;
  outputDir: string;
}

export function useBatchOperations() {
  const loading = ref(false);
  const error = ref<string | null>(null);

  const runBatch = async (
    batchFile: BatchFile,
    filterType?: 'test' | 'validate' | 'report'
  ): Promise<BatchResult> => {
    loading.value = true;
    error.value = null;
    try {
      const params = filterType ? { type: filterType } : {};
      const response = await axios.post(`${API_BASE}/run`, batchFile, { params });
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run batch operations';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runBatchTest = async (batchFile: BatchFile): Promise<BatchResult> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/test`, batchFile);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run batch tests';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runBatchValidate = async (batchFile: BatchFile): Promise<BatchResult> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/validate`, batchFile);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run batch validation';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const runBatchReport = async (batchFile: BatchFile): Promise<BatchResult> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/report`, batchFile);
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to run batch report';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const parseBatchFile = async (
    content: string,
    format: 'json' | 'yaml' = 'json'
  ): Promise<BatchFile> => {
    loading.value = true;
    error.value = null;
    try {
      const response = await axios.post(`${API_BASE}/parse`, { content, format });
      return response.data;
    } catch (err: any) {
      error.value = err.response?.data?.message || 'Failed to parse batch file';
      throw err;
    } finally {
      loading.value = false;
    }
  };

  return {
    loading,
    error,
    runBatch,
    runBatchTest,
    runBatchValidate,
    runBatchReport,
    parseBatchFile,
  };
}
