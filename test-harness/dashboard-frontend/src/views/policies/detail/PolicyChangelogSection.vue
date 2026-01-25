<template>
  <div class="policy-changelog-section">
    <div class="section-header">
      <h2 class="section-title">
        <History class="title-icon" />
        Version History
      </h2>
      <BaseButton label="Add Version" :icon="Plus" size="sm" @click="$emit('add-version')" />
    </div>
    <div v-if="versions && versions.length > 0" class="changelog-timeline">
      <div
        v-for="(version, index) in versions"
        :key="version.version"
        class="version-item"
      >
        <div class="version-header">
          <div class="version-info">
            <h3 class="version-title">Version {{ version.version }}</h3>
            <StatusBadge :status="version.status" />
          </div>
          <span class="version-date">{{ formatDate(version.createdAt) }}</span>
        </div>
        <p v-if="version.notes" class="version-notes">{{ version.notes }}</p>
        <div v-if="version.changes && version.changes.length > 0" class="version-changes">
          <h4 class="changes-title">Changes</h4>
          <ul class="changes-list">
            <li
              v-for="(change, changeIndex) in version.changes"
              :key="changeIndex"
              class="change-item"
              :class="`change-${change.type}`"
            >
              <span class="change-type">{{ change.type }}</span>
              <span class="change-description">{{ change.description }}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
    <EmptyState
      v-else
      title="No version history"
      description="Version history will appear here as you create new versions"
      :show-default-action="false"
    />
  </div>
</template>

<script setup lang="ts">
import { History, Plus } from 'lucide-vue-next';
import BaseButton from '../../../components/BaseButton.vue';
import StatusBadge from '../../../components/StatusBadge.vue';
import EmptyState from '../../../components/EmptyState.vue';

import type { PolicyVersion } from '../../../types/test';

interface Props {
  versions: PolicyVersion[];
}

defineProps<Props>();

defineEmits<{
  'add-version': [];
}>();

const formatDate = (date: Date | string | null | undefined): string => {
  if (!date) return 'Unknown';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};
</script>

<style scoped>
.policy-changelog-section {
  margin-bottom: var(--spacing-xl);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.changelog-timeline {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.version-item {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  position: relative;
}

.version-item::before {
  content: '';
  position: absolute;
  left: -8px;
  top: 24px;
  bottom: -24px;
  width: 2px;
  background: var(--border-color-muted);
}

.version-item:last-child::before {
  display: none;
}

.version-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.version-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.version-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.version-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.version-notes {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0;
}

.version-changes {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.changes-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.changes-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.change-item {
  display: flex;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.change-type {
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
  min-width: 60px;
}

.change-added {
  color: var(--color-success);
}

.change-changed {
  color: var(--color-warning);
}

.change-removed {
  color: var(--color-error);
}

.change-description {
  color: var(--color-text-secondary);
  flex: 1;
}
</style>
