import { ref, computed, watch, type Ref, type ComputedRef } from 'vue';

export interface PaginationOptions {
  itemsPerPage?: number;
  initialPage?: number;
}

/**
 * Composable for pagination functionality
 * 
 * @template T - The type of items being paginated
 * @param items - Array of items to paginate
 * @param options - Pagination configuration
 * @returns Object containing pagination state and paginated items
 * 
 * @example
 * ```ts
 * const items = ref([...]);
 * 
 * const pagination = usePagination(items, {
 *   itemsPerPage: 10,
 *   initialPage: 1,
 * });
 * 
 * // Access paginated items
 * pagination.paginatedItems.value
 * 
 * // Navigate pages
 * pagination.nextPage();
 * pagination.goToPage(3);
 * ```
 */
export function usePagination<T>(
  items: Ref<T[]>,
  options: PaginationOptions = {}
) {
  const { itemsPerPage = 10, initialPage = 1 } = options;

  const currentPage = ref(initialPage);
  const perPage = ref(itemsPerPage);

  const totalPages = computed(() => {
    return Math.ceil(items.value.length / perPage.value);
  });

  const paginatedItems = computed(() => {
    const start = (currentPage.value - 1) * perPage.value;
    const end = start + perPage.value;
    return items.value.slice(start, end);
  });

  const hasNextPage = computed(() => {
    return currentPage.value < totalPages.value;
  });

  const hasPreviousPage = computed(() => {
    return currentPage.value > 1;
  });

  const nextPage = () => {
    if (hasNextPage.value) {
      currentPage.value++;
    }
  };

  const previousPage = () => {
    if (hasPreviousPage.value) {
      currentPage.value--;
    }
  };

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages.value) {
      currentPage.value = page;
    }
  };

  const goToFirstPage = () => {
    currentPage.value = 1;
  };

  const goToLastPage = () => {
    currentPage.value = totalPages.value;
  };

  const setItemsPerPage = (count: number) => {
    perPage.value = count;
    // Reset to first page when changing items per page
    currentPage.value = 1;
  };

  const reset = () => {
    currentPage.value = initialPage;
    perPage.value = itemsPerPage;
  };

  return {
    currentPage,
    perPage,
    totalPages,
    paginatedItems,
    hasNextPage,
    hasPreviousPage,
    nextPage,
    previousPage,
    goToPage,
    goToFirstPage,
    goToLastPage,
    setItemsPerPage,
    reset,
  };
}

/**
 * Composable for combining pagination with filters/search
 * 
 * @template T - The type of items being paginated
 * @param filteredItems - Computed array of filtered items
 * @param options - Pagination configuration
 * @returns Object containing pagination state and paginated items
 * 
 * @example
 * ```ts
 * const items = ref([...]);
 * const { filteredItems } = useFilters(items, filterFn);
 * const pagination = usePaginationForFiltered(filteredItems);
 * ```
 */
export function usePaginationForFiltered<T>(
  filteredItems: ComputedRef<T[]>,
  options: PaginationOptions = {}
) {
  const { itemsPerPage = 10, initialPage = 1 } = options;

  const currentPage = ref(initialPage);
  const perPage = ref(itemsPerPage);

  const totalPages = computed(() => {
    return Math.ceil(filteredItems.value.length / perPage.value);
  });

  const paginatedItems = computed(() => {
    const start = (currentPage.value - 1) * perPage.value;
    const end = start + perPage.value;
    return filteredItems.value.slice(start, end);
  });

  const hasNextPage = computed(() => {
    return currentPage.value < totalPages.value;
  });

  const hasPreviousPage = computed(() => {
    return currentPage.value > 1;
  });

  const nextPage = () => {
    if (hasNextPage.value) {
      currentPage.value++;
    }
  };

  const previousPage = () => {
    if (hasPreviousPage.value) {
      currentPage.value--;
    }
  };

  const goToPage = (page: number) => {
    if (page >= 1 && page <= totalPages.value) {
      currentPage.value = page;
    }
  };

  const goToFirstPage = () => {
    currentPage.value = 1;
  };

  const goToLastPage = () => {
    currentPage.value = totalPages.value;
  };

  const setItemsPerPage = (count: number) => {
    perPage.value = count;
    currentPage.value = 1;
  };

  const reset = () => {
    currentPage.value = initialPage;
    perPage.value = itemsPerPage;
  };

  // Reset to first page when filtered items change
  watch(filteredItems, () => {
    if (currentPage.value > totalPages.value) {
      currentPage.value = 1;
    }
  });

  return {
    currentPage,
    perPage,
    totalPages,
    paginatedItems,
    hasNextPage,
    hasPreviousPage,
    nextPage,
    previousPage,
    goToPage,
    goToFirstPage,
    goToLastPage,
    setItemsPerPage,
    reset,
  };
}
