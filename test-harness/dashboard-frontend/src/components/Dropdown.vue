<template>
  <div class="dropdown-wrapper" ref="dropdownRef">
    <button
      type="button"
      @click="toggleDropdown"
      class="dropdown-button"
      :class="{ 'open': isOpen, 'has-value': modelValue }"
      :aria-expanded="isOpen"
      :aria-haspopup="true"
    >
      <span class="dropdown-value">
        {{ displayValue || placeholder }}
      </span>
      <ChevronDown class="dropdown-icon" :class="{ 'rotated': isOpen }" />
    </button>
    
    <Transition name="dropdown">
      <div v-if="isOpen" class="dropdown-menu" role="listbox">
        <div
          v-for="(option, index) in flattenedOptions"
          :key="index"
          @click="selectOption(option)"
          class="dropdown-option"
          :class="{
            'selected': isSelected(option),
            'disabled': option.disabled,
            'group-label': option.isGroupLabel
          }"
          :role="option.isGroupLabel ? 'group' : 'option'"
          :aria-selected="isSelected(option)"
        >
          <Check v-if="isSelected(option) && !option.isGroupLabel" class="check-icon" />
          <span class="option-label">{{ option.label }}</span>
        </div>
        <div v-if="flattenedOptions.length === 0" class="dropdown-empty">
          No options available
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { ChevronDown, Check } from 'lucide-vue-next';

export interface DropdownOption {
  label: string;
  value: any;
  disabled?: boolean;
  isGroupLabel?: boolean;
  groupName?: string;
}

const props = withDefaults(defineProps<{
  modelValue: any;
  options: DropdownOption[] | Record<string, DropdownOption[]>;
  placeholder?: string;
  disabled?: boolean;
}>(), {
  placeholder: 'Select...',
  disabled: false
});

const emit = defineEmits<{
  'update:modelValue': [value: any];
  'change': [value: any];
}>();

const isOpen = ref(false);
const dropdownRef = ref<HTMLElement | null>(null);

const flattenedOptions = computed(() => {
  if (Array.isArray(props.options)) {
    return props.options;
  }
  
  // Handle grouped options
  const flattened: DropdownOption[] = [];
  Object.entries(props.options).forEach(([groupName, groupOptions]) => {
    flattened.push({
      label: groupName,
      value: null,
      isGroupLabel: true,
      groupName
    });
    flattened.push(...groupOptions);
  });
  return flattened;
});

const displayValue = computed(() => {
  if (props.modelValue === null || props.modelValue === undefined || props.modelValue === '') {
    return null;
  }
  
  const findOption = (options: DropdownOption[]): DropdownOption | undefined => {
    for (const option of options) {
      if (option.value === props.modelValue && !option.isGroupLabel) {
        return option;
      }
    }
    return undefined;
  };
  
  if (Array.isArray(props.options)) {
    return findOption(props.options)?.label;
  }
  
  // Search in grouped options
  for (const groupOptions of Object.values(props.options)) {
    const found = findOption(groupOptions);
    if (found) return found.label;
  }
  
  return String(props.modelValue);
});

const isSelected = (option: DropdownOption): boolean => {
  return option.value === props.modelValue && !option.isGroupLabel;
};

const toggleDropdown = () => {
  if (props.disabled) return;
  isOpen.value = !isOpen.value;
};

const selectOption = (option: DropdownOption) => {
  if (option.disabled || option.isGroupLabel) return;
  
  emit('update:modelValue', option.value);
  emit('change', option.value);
  isOpen.value = false;
};

const handleClickOutside = (event: MouseEvent) => {
  if (dropdownRef.value && !dropdownRef.value.contains(event.target as Node)) {
    isOpen.value = false;
  }
};

onMounted(() => {
  document.addEventListener('click', handleClickOutside);
});

onBeforeUnmount(() => {
  document.removeEventListener('click', handleClickOutside);
});
</script>

<style scoped>
.dropdown-wrapper {
  position: relative;
  width: 100%;
  min-width: 200px;
}

.dropdown-button {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  cursor: pointer;
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--spacing-sm);
  text-align: left;
}

.dropdown-button:hover:not(:disabled) {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
}

.dropdown-button:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.dropdown-button.open {
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.dropdown-button.has-value .dropdown-value {
  color: var(--color-text-primary);
}

.dropdown-button:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.dropdown-value {
  flex: 1;
  color: var(--color-text-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dropdown-icon {
  width: 18px;
  height: 18px;
  color: var(--color-text-muted);
  transition: var(--transition-base);
  flex-shrink: 0;
}

.dropdown-icon.rotated {
  transform: rotate(180deg);
}

.dropdown-menu {
  position: absolute;
  top: calc(100% + var(--spacing-sm));
  left: 0;
  min-width: 100%;
  width: max-content;
  max-width: 400px;
  max-height: 300px;
  overflow-y: auto;
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  box-shadow: var(--shadow-md);
  z-index: var(--z-index-dropdown);
  padding: var(--spacing-sm);
}

.dropdown-option {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  cursor: pointer;
  transition: var(--transition-all);
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.dropdown-option:hover:not(.disabled):not(.group-label) {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.dropdown-option.selected {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.dropdown-option.disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.dropdown-option.group-label {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
  text-transform: uppercase;
  letter-spacing: var(--letter-spacing-wide);
  padding: var(--spacing-sm) var(--spacing-sm);
  cursor: default;
  margin-top: var(--spacing-xs);
}

.dropdown-option.group-label:first-child {
  margin-top: 0;
}

.check-icon {
  width: 16px;
  height: 16px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.option-label {
  flex: 1;
  overflow: visible;
  white-space: nowrap;
  min-width: 0;
}

.dropdown-empty {
  padding: var(--spacing-xl);
  text-align: center;
  color: var(--color-text-muted);
  font-size: var(--font-size-sm);
}

/* Scrollbar styling */
.dropdown-menu::-webkit-scrollbar {
  width: var(--spacing-xs);
}

.dropdown-menu::-webkit-scrollbar-track {
  background: transparent;
}

.dropdown-menu::-webkit-scrollbar-thumb {
  background-color: var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
}

.dropdown-menu::-webkit-scrollbar-thumb:hover {
  background-color: var(--border-color-primary);
  opacity: 0.5;
}

/* Transitions */
.dropdown-enter-active,
.dropdown-leave-active {
  transition: var(--transition-base);
}

.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>

