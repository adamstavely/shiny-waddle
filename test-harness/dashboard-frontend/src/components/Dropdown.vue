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
}

.dropdown-button {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  text-align: left;
}

.dropdown-button:hover:not(:disabled) {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.dropdown-button:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.dropdown-button.open {
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.dropdown-button.has-value .dropdown-value {
  color: #ffffff;
}

.dropdown-button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.dropdown-value {
  flex: 1;
  color: #a0aec0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dropdown-icon {
  width: 18px;
  height: 18px;
  color: #718096;
  transition: transform 0.2s;
  flex-shrink: 0;
}

.dropdown-icon.rotated {
  transform: rotate(180deg);
}

.dropdown-menu {
  position: absolute;
  top: calc(100% + 8px);
  left: 0;
  right: 0;
  max-height: 300px;
  overflow-y: auto;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  z-index: 1000;
  padding: 8px;
}

.dropdown-option {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
  color: #a0aec0;
  font-size: 0.9rem;
}

.dropdown-option:hover:not(.disabled):not(.group-label) {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.dropdown-option.selected {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.dropdown-option.disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.dropdown-option.group-label {
  font-weight: 600;
  color: #718096;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 8px 12px;
  cursor: default;
  margin-top: 4px;
}

.dropdown-option.group-label:first-child {
  margin-top: 0;
}

.check-icon {
  width: 16px;
  height: 16px;
  color: #4facfe;
  flex-shrink: 0;
}

.option-label {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dropdown-empty {
  padding: 20px;
  text-align: center;
  color: #718096;
  font-size: 0.875rem;
}

/* Scrollbar styling */
.dropdown-menu::-webkit-scrollbar {
  width: 6px;
}

.dropdown-menu::-webkit-scrollbar-track {
  background: transparent;
}

.dropdown-menu::-webkit-scrollbar-thumb {
  background-color: rgba(79, 172, 254, 0.3);
  border-radius: 3px;
}

.dropdown-menu::-webkit-scrollbar-thumb:hover {
  background-color: rgba(79, 172, 254, 0.5);
}

/* Transitions */
.dropdown-enter-active,
.dropdown-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>

