import { ref, type Ref } from 'vue';
import type { AxiosError } from 'axios';

/**
 * Composable for handling API data fetching with loading and error states
 * 
 * @template T - The type of data being fetched
 * @param fetchFn - Function that returns a Promise resolving to the data
 * @param options - Configuration options
 * @returns Object containing data, loading, error, and load function
 * 
 * @example
 * ```ts
 * const { data, loading, error, load } = useApiData(
 *   async () => {
 *     const response = await fetch('/api/v1/applications');
 *     return response.json();
 *   }
 * );
 * 
 * onMounted(() => {
 *   load();
 * });
 * ```
 */
export function useApiData<T>(
  fetchFn: () => Promise<T>,
  options: {
    initialData?: T;
    errorMessage?: string;
    onError?: (error: AxiosError | Error) => void;
  } = {}
) {
  const { initialData, errorMessage, onError } = options;

  const data = ref<T | null>(initialData ?? null) as Ref<T | null>;
  const loading = ref(false);
  const error = ref<string | null>(null);

  const load = async () => {
    try {
      loading.value = true;
      error.value = null;
      const result = await fetchFn();
      data.value = result;
      return result;
    } catch (err) {
      const axiosError = err as AxiosError | Error;
      const message = 
        (axiosError as AxiosError).response?.data?.message ||
        errorMessage ||
        axiosError.message ||
        'Failed to load data';
      
      error.value = message;
      
      if (onError) {
        onError(axiosError);
      } else {
        console.error('Error loading data:', axiosError);
      }
      
      throw err;
    } finally {
      loading.value = false;
    }
  };

  const reset = () => {
    data.value = initialData ?? null;
    error.value = null;
    loading.value = false;
  };

  return {
    data,
    loading,
    error,
    load,
    reset,
  };
}

/**
 * Composable for handling API data fetching with automatic loading on mount
 * 
 * @template T - The type of data being fetched
 * @param fetchFn - Function that returns a Promise resolving to the data
 * @param options - Configuration options
 * @returns Object containing data, loading, error, and load function
 * 
 * @example
 * ```ts
 * const { data, loading, error, reload } = useApiDataAuto(
 *   async () => {
 *     const response = await fetch('/api/v1/applications');
 *     return response.json();
 *   }
 * );
 * ```
 */
export function useApiDataAuto<T>(
  fetchFn: () => Promise<T>,
  options: {
    initialData?: T;
    errorMessage?: string;
    onError?: (error: AxiosError | Error) => void;
    autoLoad?: boolean;
  } = {}
) {
  const { autoLoad = true, ...restOptions } = options;
  const apiData = useApiData(fetchFn, restOptions);

  if (autoLoad) {
    apiData.load();
  }

  return {
    ...apiData,
    reload: apiData.load,
  };
}
