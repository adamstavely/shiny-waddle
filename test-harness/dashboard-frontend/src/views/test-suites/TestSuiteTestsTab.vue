<template>
  <div class="test-suite-tests-tab">
    <div class="tests-section">
      <div class="section-header">
        <h2 class="section-title">Assigned Tests</h2>
        <BaseButton 
          label="Add Test" 
          :icon="Plus" 
          @click="$emit('add-test')"
          :disabled="!testType"
        />
      </div>
      <div v-if="!testType" class="info-message">
        <Info class="info-icon" />
        <p>Please select a test type above before adding tests.</p>
      </div>
      <EmptyState
        v-else-if="assignedTests.length === 0"
        title="No Tests Assigned"
        :description="`Add tests to this suite to get started. All tests must be of type: ${getTestTypeLabel(testType)}`"
        :icon="TestTube"
        action-label="Add Test"
        :show-default-action="true"
        @action="$emit('add-test')"
      />
      <div v-else class="tests-list">
        <div
          v-for="test in assignedTests"
          :key="test.id"
          class="test-item"
        >
          <div class="test-info">
            <div class="test-name-row">
              <h4 class="test-name">{{ test.name }}</h4>
              <StatusBadge :status="`v${test.version}`" size="sm" />
            </div>
            <p v-if="test.description" class="test-description">{{ test.description }}</p>
            <div v-if="test.testType === 'access-control' && test.policyIds && test.policyIds.length > 0" class="test-policies">
              <span class="policies-label">Policies:</span>
              <StatusBadge
                v-for="policyId in test.policyIds"
                :key="policyId"
                :status="getPolicyName(policyId)"
                size="sm"
                variant="info"
                @click.stop="$emit('view-policy', policyId)"
                class="policy-badge-clickable"
              />
            </div>
          </div>
          <div class="test-actions">
            <BaseButton label="View" :icon="Eye" variant="ghost" size="sm" @click="$emit('view-test', test.id)" />
            <BaseButton label="Remove" :icon="X" variant="danger" size="sm" @click="$emit('remove-test', test.id)" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { TestTube, Plus, Eye, X, Info } from 'lucide-vue-next';
import BaseButton from '../../components/BaseButton.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import EmptyState from '../../components/EmptyState.vue';

import type { Test, Policy } from '../../../types/test';

interface Props {
  assignedTests: Test[];
  testType: string;
  policies?: Policy[];
}

const props = defineProps<Props>();

defineEmits<{
  'add-test': [];
  'view-test': [testId: string];
  'view-policy': [policyId: string];
  'remove-test': [testId: string];
}>();

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
  };
  return labels[testType] || testType;
};

const getPolicyName = (policyId: string): string => {
  const policy = props.policies?.find(p => p.id === policyId);
  return policy?.name || policyId;
};
</script>

<style scoped>
.test-suite-tests-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.tests-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.info-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
}

.info-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
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
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
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
  margin: var(--spacing-xs) 0;
}

.test-policies {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  margin-top: var(--spacing-sm);
  flex-wrap: wrap;
}

.policies-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.policy-badge-clickable {
  cursor: pointer;
}

.test-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-shrink: 0;
}
</style>
