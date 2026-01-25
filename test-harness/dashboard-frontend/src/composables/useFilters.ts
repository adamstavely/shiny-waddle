import { ref, computed, type Ref } from 'vue';

export interface FilterOption {
  label: string;
  value: string | number | null;
}

/**
 * Composable for managing filter state and filtered data
 * 
 * @template T - The type of items being filtered
 * @param items - Array of items to filter
 * @param filterFn - Function that determines if an item matches the filters
 * @param initialFilters - Initial filter values
 * @returns Object containing filter state and filtered items
 * 
 * @example
 * ```ts
 * const items = ref([...]);
 * 
 * const filters = useFilters(items, (item, filters) => {
 *   if (filters.search && !item.name.toLowerCase().includes(filters.search.toLowerCase())) {
 *     return false;
 *   }
 *   if (filters.status && item.status !== filters.status) {
 *     return false;
 *   }
 *   return true;
 * }, {
 *   search: '',
 *   status: null,
 * });
 * 
 * // Access filtered items
 * filters.filteredItems.value
 * 
 * // Update filters
 * filters.filters.value.search = 'test';
 * ```
 */
export function useFilters<T>(
  items: Ref<T[]>,
  filterFn: (item: T, filters: Record<string, any>) => boolean,
  initialFilters: Record<string, any> = {}
) {
  const filters = ref<Record<string, any>>({ ...initialFilters });

  const filteredItems = computed(() => {
    return items.value.filter((item) => filterFn(item, filters.value));
  });

  const resetFilters = () => {
    filters.value = { ...initialFilters };
  };

  const setFilter = (key: string, value: any) => {
    filters.value[key] = value;
  };

  const clearFilter = (key: string) => {
    if (key in initialFilters) {
      filters.value[key] = initialFilters[key];
    } else {
      delete filters.value[key];
    }
  };

  const hasActiveFilters = computed(() => {
    return Object.keys(filters.value).some((key) => {
      const value = filters.value[key];
      if (value === null || value === undefined) return false;
      if (typeof value === 'string') return value.trim().length > 0;
      if (Array.isArray(value)) return value.length > 0;
      return value !== initialFilters[key];
    });
  });

  return {
    filters,
    filteredItems,
    resetFilters,
    setFilter,
    clearFilter,
    hasActiveFilters,
  };
}

/**
 * Composable for search functionality
 * 
 * @template T - The type of items being searched
 * @param items - Array of items to search
 * @param searchFields - Fields to search in (can be string keys or functions)
 * @param initialQuery - Initial search query
 * @returns Object containing search state and filtered items
 * 
 * @example
 * ```ts
 * const items = ref([...]);
 * 
 * const search = useSearch(items, ['name', 'description']);
 * 
 * // Or with custom search function
 * const search = useSearch(items, [
 *   (item) => item.name,
 *   (item) => item.description,
 * ]);
 * ```
 */
export function useSearch<T>(
  items: Ref<T[]>,
  searchFields: (string | ((item: T) => string))[],
  initialQuery = ''
) {
  const query = ref(initialQuery);

  const filteredItems = computed(() => {
    if (!query.value.trim()) {
      return items.value;
    }

    const searchTerm = query.value.toLowerCase().trim();

    return items.value.filter((item) => {
      return searchFields.some((field) => {
        let value: string;
        if (typeof field === 'string') {
          value = String((item as any)[field] || '');
        } else {
          value = String(field(item) || '');
        }
        return value.toLowerCase().includes(searchTerm);
      });
    });
  });

  const clear = () => {
    query.value = '';
  };

  return {
    query,
    filteredItems,
    clear,
  };
}
