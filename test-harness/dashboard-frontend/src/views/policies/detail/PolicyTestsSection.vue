<template>
  <div class="policy-tests-section">
    <div class="section-header">
      <h2 class="section-title">
        <TestTube class="title-icon" />
        Tests Using This Policy
      </h2>
      <div class="section-actions">
        <BaseButton label="Create Test" :icon="Plus" size="sm" @click="$emit('create-test')" />
        <BaseButton label="View All Tests" variant="secondary" size="sm" @click="$emit('view-all-tests')" />
      </div>
    </div>
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading tests...</div>
    </div>
    <EmptyState
      v-else-if="tests.length === 0"
      title="No tests are currently using this policy"
      description="Create a test from this policy to get started"
      :icon="TestTube"
      action-label="Create Test from Policy"
      :show-default-action="true"
      @action="$emit('create-test')"
    />
    <div v-else class="tests-list">
      <div
        v-for="test in tests"
        :key="test.id"
        class="test-item"
        @click="$emit('view-test', test.id)"
      >
        <div class="test-info">
          <div class="test-name-row">
            <h4 class="test-name">{{ test.name }}</h4>
            <StatusBadge :status="`v${test.version}`" size="sm" />
          </div>
          <p v-if="test.description" class="test-description">{{ test.description }}</p>
          <div class="test-meta">
            <span class="meta-item">
              <span class="meta-label">Role:</span>
              <span class="meta-value">{{ test.role }}</span>
            </span>
            <span class="meta-item">
              <span class="meta-label">Resource:</span>
              <span class="meta-value">{{ test.resource?.type || test.resource?.id }}</span>
            </span>
            <span class="meta-item">
              <span class="meta-label">Expected:</span>
              <StatusBadge
                :status="test.expectedDecision ? 'allow' : 'deny'"
                :variant="test.expectedDecision ? 'success' : 'error'"
                size="sm"
              />
            </span>
          </div>
        </div>
        <div class="test-actions">
          <BaseButton label="View" :icon="Eye" variant="ghost" size="sm" @click.stop="$emit('view-test', test.id)" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { TestTube, Plus, Eye } from 'lucide-vue-next';
import BaseButton from '../../../components/BaseButton.vue';
import StatusBadge from '../../../components/StatusBadge.vue';
import EmptyState from '../../../components/EmptyState.vue';

import type { Test } from '../../../types/test';

interface Props {
  tests: Test[];
  loading?: boolean;
}

withDefaults(defineProps<Props>(), {
  loading: false
});

defineEmits<{
  'create-test': [];
  'view-all-tests': [];
  'view-test': [testId: string];
}>();
</script>

<style scoped>
.policy-tests-section {
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

.section-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.tests-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.test-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: var(--spacing-md);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.test-item:hover {
  border-color: var(--border-color-primary-active);
  background: var(--border-color-muted);
  opacity: 0.5;
}

.test-info {
  flex: 1;
}

.test-name-row {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.test-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.test-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0 var(--spacing-sm) 0;
}

.test-meta {
  display: flex;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.meta-label {
  color: var(--color-text-secondary);
}

.meta-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.test-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
}
</style>
