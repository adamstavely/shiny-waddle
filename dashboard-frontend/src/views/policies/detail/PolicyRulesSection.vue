<template>
  <div class="policy-rules-section">
    <!-- RBAC Rules -->
    <div v-if="policy.type === 'rbac'">
      <div class="section-header">
        <h2 class="section-title">
          <Shield class="title-icon" />
          Policy Rules
        </h2>
        <span class="rule-count">{{ policy.rules?.length || 0 }} rules</span>
      </div>
      <div v-if="policy.rules && policy.rules.length > 0" class="rules-list">
        <div
          v-for="(rule, index) in policy.rules"
          :key="rule.id || index"
          class="rule-card"
        >
          <div class="rule-header">
            <div class="rule-title-group">
              <h3 class="rule-name">{{ rule.id }}</h3>
              <StatusBadge :status="rule.effect" />
            </div>
          </div>
          <p v-if="rule.description" class="rule-description">{{ rule.description }}</p>
          <div v-if="rule.conditions && Object.keys(rule.conditions).length > 0" class="rule-conditions">
            <h4 class="conditions-title">Conditions</h4>
            <div class="conditions-grid">
              <div
                v-for="(value, key) in rule.conditions"
                :key="key"
                class="condition-display"
              >
                <span class="condition-key">{{ key }}</span>
                <span class="condition-separator">:</span>
                <span class="condition-value">
                  {{ Array.isArray(value) ? JSON.stringify(value) : value }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
      <EmptyState
        v-else
        title="No rules defined"
        description="This policy has no rules configured"
        :show-default-action="false"
      />
    </div>

    <!-- ABAC Conditions -->
    <div v-if="policy.type === 'abac'">
      <div class="section-header">
        <h2 class="section-title">
          <Shield class="title-icon" />
          Policy Conditions
        </h2>
        <span class="rule-count">{{ policy.conditions?.length || 0 }} conditions</span>
      </div>
      <div v-if="policy.conditions && policy.conditions.length > 0" class="conditions-list">
        <div
          v-for="(condition, index) in policy.conditions"
          :key="index"
          class="condition-card"
        >
          <div class="condition-header">
            <h3 class="condition-title">Condition {{ index + 1 }}</h3>
            <StatusBadge
              v-if="condition.logicalOperator"
              :status="condition.logicalOperator"
              size="sm"
            />
          </div>
          <div class="condition-details">
            <div class="detail-row">
              <span class="detail-label">Attribute:</span>
              <span class="detail-value">{{ condition.attribute }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Operator:</span>
              <span class="detail-value">{{ condition.operator }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Value:</span>
              <span class="detail-value">{{ condition.value }}</span>
            </div>
          </div>
        </div>
      </div>
      <EmptyState
        v-else
        title="No conditions defined"
        description="This policy has no conditions configured"
        :show-default-action="false"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { Shield } from 'lucide-vue-next';
import StatusBadge from '../../../components/StatusBadge.vue';
import EmptyState from '../../../components/EmptyState.vue';

import type { Policy } from '../../../types/test';

interface Props {
  policy: Policy;
}

defineProps<Props>();
</script>

<style scoped>
.policy-rules-section {
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

.rule-count {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.rules-list,
.conditions-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.rule-card,
.condition-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.rule-header,
.condition-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.rule-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.rule-name,
.condition-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.rule-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.rule-conditions {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.conditions-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.conditions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-sm);
}

.condition-display {
  display: flex;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.condition-key {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.condition-separator {
  color: var(--color-text-muted);
}

.condition-value {
  color: var(--color-text-secondary);
  font-family: monospace;
}

.condition-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.detail-row {
  display: flex;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.detail-label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
}

.detail-value {
  color: var(--color-text-primary);
}
</style>
