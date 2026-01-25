import { ref, type Ref } from 'vue';

/**
 * Composable for managing modal state
 * 
 * @template T - The type of data associated with the modal (optional)
 * @param initialOpen - Initial open state (default: false)
 * @returns Object containing isOpen state and open/close functions
 * 
 * @example
 * ```ts
 * const modal = useModal();
 * 
 * // Open modal
 * modal.open();
 * 
 * // Close modal
 * modal.close();
 * 
 * // Toggle modal
 * modal.toggle();
 * ```
 * 
 * @example With data
 * ```ts
 * const modal = useModal<Application>();
 * 
 * // Open modal with data
 * modal.open(application);
 * 
 * // Access data
 * modal.data.value // Application | null
 * ```
 */
export function useModal<T = unknown>(initialOpen = false) {
  const isOpen = ref(initialOpen);
  const data = ref<T | null>(null) as Ref<T | null>;

  const open = (modalData?: T) => {
    if (modalData !== undefined) {
      data.value = modalData;
    }
    isOpen.value = true;
  };

  const close = () => {
    isOpen.value = false;
    // Optionally clear data when closing
    // data.value = null;
  };

  const toggle = (modalData?: T) => {
    if (isOpen.value) {
      close();
    } else {
      open(modalData);
    }
  };

  const reset = () => {
    isOpen.value = false;
    data.value = null;
  };

  return {
    isOpen,
    data,
    open,
    close,
    toggle,
    reset,
  };
}

/**
 * Composable for managing multiple modals in a single component
 * 
 * @param modalNames - Array of modal names to manage
 * @returns Object with modal states and control functions
 * 
 * @example
 * ```ts
 * const modals = useMultiModal(['create', 'edit', 'delete']);
 * 
 * // Open specific modal
 * modals.open('create');
 * 
 * // Check if modal is open
 * modals.isOpen('create') // boolean
 * 
 * // Close all modals
 * modals.closeAll();
 * ```
 */
export function useMultiModal(modalNames: string[]) {
  const modals = ref<Record<string, boolean>>(
    modalNames.reduce((acc, name) => {
      acc[name] = false;
      return acc;
    }, {} as Record<string, boolean>)
  );

  const isOpen = (name: string): boolean => {
    return modals.value[name] ?? false;
  };

  const open = (name: string) => {
    modals.value[name] = true;
  };

  const close = (name: string) => {
    modals.value[name] = false;
  };

  const toggle = (name: string) => {
    modals.value[name] = !modals.value[name];
  };

  const closeAll = () => {
    modalNames.forEach((name) => {
      modals.value[name] = false;
    });
  };

  const openOnly = (name: string) => {
    closeAll();
    open(name);
  };

  return {
    modals,
    isOpen,
    open,
    close,
    toggle,
    closeAll,
    openOnly,
  };
}
