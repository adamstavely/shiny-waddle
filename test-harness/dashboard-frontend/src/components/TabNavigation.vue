<template>
  <div class="tab-navigation" :class="{ 'tabs-compact': compact }">
    <button
      v-for="tab in tabs"
      :key="tab.id"
      @click="selectTab(tab.id)"
      class="tab-button"
      :class="{
        'tab-active': activeTab === tab.id,
        'tab-disabled': tab.disabled
      }"
      :disabled="tab.disabled"
      :aria-selected="activeTab === tab.id"
      role="tab"
    >
      <component v-if="tab.icon" :is="tab.icon" class="tab-icon" />
      <span class="tab-label">{{ tab.label }}</span>
      <span v-if="tab.badge !== undefined && tab.badge !== null" class="tab-badge">
        {{ tab.badge }}
      </span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { type LucideIcon } from 'lucide-vue-next';

export interface Tab {
  id: string;
  label: string;
  icon?: LucideIcon;
  badge?: number | string | null;
  disabled?: boolean;
}

interface Props {
  tabs: Tab[];
  activeTab: string;
  compact?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  compact: false,
});

const emit = defineEmits<{
  'update:activeTab': [id: string];
  'tab-change': [id: string];
}>();

const selectTab = (id: string) => {
  const tab = props.tabs.find(t => t.id === id);
  if (tab && !tab.disabled) {
    emit('update:activeTab', id);
    emit('tab-change', id);
  }
};
</script>

<style scoped>
.tab-navigation {
  display: flex;
  gap: var(--spacing-xs);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  margin-bottom: var(--spacing-lg);
  overflow-x: auto;
}

.tabs-compact {
  gap: 0;
  margin-bottom: var(--spacing-md);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  white-space: nowrap;
  position: relative;
}

.tab-button:hover:not(.tab-disabled) {
  color: var(--color-primary);
  background: var(--border-color-muted);
  opacity: 0.5;
}

.tab-button.tab-active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
}

.tab-button.tab-disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.tab-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.tab-label {
  flex: 1;
}

.tab-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  height: 20px;
  padding: 0 var(--spacing-xs);
  background: var(--color-primary);
  color: var(--color-text-primary);
  border-radius: var(--border-radius-full);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  margin-left: var(--spacing-xs);
}

.tab-button.tab-active .tab-badge {
  background: var(--color-primary);
  color: var(--color-text-primary);
}

.tabs-compact .tab-button {
  padding: var(--spacing-sm) var(--spacing-md);
  font-size: var(--font-size-sm);
}

.tabs-compact .tab-icon {
  width: 18px;
  height: 18px;
}
</style>
