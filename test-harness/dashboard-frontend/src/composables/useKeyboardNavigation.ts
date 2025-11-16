/**
 * Composable for keyboard navigation support
 * Provides utilities for managing keyboard interactions in components
 */

import { onMounted, onBeforeUnmount, type Ref } from 'vue';
import { handleKeyboardNavigation } from '../utils/accessibility';

export interface KeyboardNavigationOptions {
  onEnter?: () => void;
  onEscape?: () => void;
  onArrowUp?: () => void;
  onArrowDown?: () => void;
  onArrowLeft?: () => void;
  onArrowRight?: () => void;
  onHome?: () => void;
  onEnd?: () => void;
  onTab?: () => void;
  onShiftTab?: () => void;
  enabled?: Ref<boolean> | boolean;
  target?: Ref<HTMLElement | null> | HTMLElement | null;
}

/**
 * Composable for keyboard navigation
 */
export function useKeyboardNavigation(options: KeyboardNavigationOptions) {
  const handleKeyDown = (event: KeyboardEvent) => {
    // Check if navigation is enabled
    const isEnabled = typeof options.enabled === 'boolean' 
      ? options.enabled 
      : options.enabled?.value ?? true;
    
    if (!isEnabled) return;

    // Check if event target is within the target element
    if (options.target) {
      const targetElement = options.target instanceof HTMLElement
        ? options.target
        : options.target.value;
      
      if (targetElement && !targetElement.contains(event.target as Node)) {
        return;
      }
    }

    // Handle Tab navigation
    if (event.key === 'Tab') {
      if (event.shiftKey && options.onShiftTab) {
        event.preventDefault();
        options.onShiftTab();
        return;
      } else if (options.onTab) {
        options.onTab();
        return;
      }
    }

    // Handle other keys
    handleKeyboardNavigation(event, {
      onEnter: options.onEnter,
      onEscape: options.onEscape,
      onArrowUp: options.onArrowUp,
      onArrowDown: options.onArrowDown,
      onArrowLeft: options.onArrowLeft,
      onArrowRight: options.onArrowRight,
      onHome: options.onHome,
      onEnd: options.onEnd,
    });
  };

  onMounted(() => {
    const targetElement = options.target instanceof HTMLElement
      ? options.target
      : options.target?.value || document;
    
    if (targetElement instanceof HTMLElement) {
      targetElement.addEventListener('keydown', handleKeyDown);
    } else {
      document.addEventListener('keydown', handleKeyDown);
    }
  });

  onBeforeUnmount(() => {
    const targetElement = options.target instanceof HTMLElement
      ? options.target
      : options.target?.value || document;
    
    if (targetElement instanceof HTMLElement) {
      targetElement.removeEventListener('keydown', handleKeyDown);
    } else {
      document.removeEventListener('keydown', handleKeyDown);
    }
  });

  return {
    handleKeyDown,
  };
}

/**
 * Composable for arrow key navigation in lists
 */
export function useArrowKeyNavigation<T>(
  items: Ref<T[]>,
  selectedIndex: Ref<number>,
  options: {
    onSelect?: (item: T, index: number) => void;
    loop?: boolean;
    orientation?: 'horizontal' | 'vertical';
  } = {}
) {
  const { loop = false, orientation = 'vertical', onSelect } = options;

  const navigate = (direction: 'up' | 'down' | 'left' | 'right') => {
    const currentIndex = selectedIndex.value;
    let newIndex = currentIndex;

    if (orientation === 'vertical') {
      if (direction === 'up') {
        newIndex = currentIndex > 0 ? currentIndex - 1 : (loop ? items.value.length - 1 : currentIndex);
      } else if (direction === 'down') {
        newIndex = currentIndex < items.value.length - 1 ? currentIndex + 1 : (loop ? 0 : currentIndex);
      }
    } else {
      if (direction === 'left') {
        newIndex = currentIndex > 0 ? currentIndex - 1 : (loop ? items.value.length - 1 : currentIndex);
      } else if (direction === 'right') {
        newIndex = currentIndex < items.value.length - 1 ? currentIndex + 1 : (loop ? 0 : currentIndex);
      }
    }

    if (newIndex !== currentIndex) {
      selectedIndex.value = newIndex;
      if (onSelect && items.value[newIndex]) {
        onSelect(items.value[newIndex], newIndex);
      }
    }
  };

  useKeyboardNavigation({
    onArrowUp: orientation === 'vertical' ? () => navigate('up') : undefined,
    onArrowDown: orientation === 'vertical' ? () => navigate('down') : undefined,
    onArrowLeft: orientation === 'horizontal' ? () => navigate('left') : undefined,
    onArrowRight: orientation === 'horizontal' ? () => navigate('right') : undefined,
    onHome: () => {
      selectedIndex.value = 0;
      if (onSelect && items.value[0]) {
        onSelect(items.value[0], 0);
      }
    },
    onEnd: () => {
      const lastIndex = items.value.length - 1;
      selectedIndex.value = lastIndex;
      if (onSelect && items.value[lastIndex]) {
        onSelect(items.value[lastIndex], lastIndex);
      }
    },
  });

  return {
    navigate,
  };
}

