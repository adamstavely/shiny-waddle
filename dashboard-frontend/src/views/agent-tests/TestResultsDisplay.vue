<template>
  <div class="test-results">
    <!-- Array of results -->
    <div v-if="Array.isArray(result)" class="results-list">
      <div v-for="(item, index) in result" :key="index" class="result-item">
        <div class="result-card" :class="{ 'passed': item.passed, 'failed': !item.passed }">
          <div class="result-header">
            <CheckCircle2 v-if="item.passed" class="result-icon" />
            <XCircle v-else class="result-icon" />
            <h3 class="result-title">{{ item.testName }}</h3>
            <span class="result-status">{{ item.passed ? 'PASSED' : 'FAILED' }}</span>
          </div>
          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Agent ID:</span>
              <span class="detail-value">{{ item.agentId }}</span>
            </div>
            <div v-if="item.decisionReason" class="detail-row">
              <span class="detail-label">Decision Reason:</span>
              <span class="detail-value">{{ item.decisionReason }}</span>
            </div>
            <div v-if="item.allowed !== undefined" class="detail-row">
              <span class="detail-label">Access:</span>
              <span class="detail-value">{{ item.allowed ? 'Allowed' : 'Denied' }}</span>
            </div>
            <div v-if="item.permissionBoundariesRespected !== undefined" class="detail-row">
              <span class="detail-label">Permission Boundaries:</span>
              <span class="detail-value">{{ item.permissionBoundariesRespected ? 'Respected' : 'Violated' }}</span>
            </div>
            <div v-if="item.multiServiceConsistency !== undefined" class="detail-row">
              <span class="detail-label">Multi-Service Consistency:</span>
              <span class="detail-value">{{ item.multiServiceConsistency ? 'Consistent' : 'Inconsistent' }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
    <!-- Single result with nested result -->
    <div v-else-if="result?.result" class="single-result">
      <div class="result-card" :class="{ 'passed': result.result.passed, 'failed': !result.result.passed }">
        <div class="result-header">
          <CheckCircle2 v-if="result.result.passed" class="result-icon" />
          <XCircle v-else class="result-icon" />
          <h3 class="result-title">{{ result.result.testName }}</h3>
          <span class="result-status">{{ result.result.passed ? 'PASSED' : 'FAILED' }}</span>
        </div>
        <div class="result-details">
          <div class="detail-row">
            <span class="detail-label">Agent ID:</span>
            <span class="detail-value">{{ result.result.agentId }}</span>
          </div>
          <div v-if="result.result.decisionReason" class="detail-row">
            <span class="detail-label">Decision Reason:</span>
            <span class="detail-value">{{ result.result.decisionReason }}</span>
          </div>
          <div v-if="result.result.allowed !== undefined" class="detail-row">
            <span class="detail-label">Access:</span>
            <span class="detail-value">{{ result.result.allowed ? 'Allowed' : 'Denied' }}</span>
          </div>
        </div>
      </div>
    </div>
    <!-- Audit validation result -->
    <div v-else-if="result?.validationResult" class="single-result">
      <div class="result-card" :class="{ 'passed': result.validationResult.passed, 'failed': !result.validationResult.passed }">
        <div class="result-header">
          <CheckCircle2 v-if="result.validationResult.passed" class="result-icon" />
          <XCircle v-else class="result-icon" />
          <h3 class="result-title">{{ result.validationResult.testName }}</h3>
          <span class="result-status">{{ result.validationResult.passed ? 'PASSED' : 'FAILED' }}</span>
        </div>
        <div class="result-details">
          <div class="detail-row">
            <span class="detail-label">Agent ID:</span>
            <span class="detail-value">{{ result.validationResult.agentId }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Audit Log Complete:</span>
            <span class="detail-value">{{ result.validationResult.auditLogComplete ? 'Yes' : 'No' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Audit Log Integrity:</span>
            <span class="detail-value">{{ result.validationResult.auditLogIntegrity ? 'Valid' : 'Invalid' }}</span>
          </div>
          <div class="detail-row">
            <span class="detail-label">Cross-Service Correlation:</span>
            <span class="detail-value">{{ result.validationResult.crossServiceCorrelation ? 'Valid' : 'Invalid' }}</span>
          </div>
          <div v-if="result.validationResult.missingEntries && result.validationResult.missingEntries.length > 0" class="detail-row">
            <span class="detail-label">Missing Entries:</span>
            <span class="detail-value">{{ result.validationResult.missingEntries.length }}</span>
          </div>
          <div v-if="result.validationResult.correlationIssues && result.validationResult.correlationIssues.length > 0" class="detail-row">
            <span class="detail-label">Correlation Issues:</span>
            <span class="detail-value">{{ result.validationResult.correlationIssues.join(', ') }}</span>
          </div>
        </div>
      </div>
    </div>
    <!-- Single result -->
    <div v-else-if="result" class="single-result">
      <div class="result-card" :class="{ 'passed': result.passed, 'failed': !result.passed }">
        <div class="result-header">
          <CheckCircle2 v-if="result.passed" class="result-icon" />
          <XCircle v-else class="result-icon" />
          <h3 class="result-title">{{ result.testName }}</h3>
          <span class="result-status">{{ result.passed ? 'PASSED' : 'FAILED' }}</span>
        </div>
        <div class="result-details">
          <div class="detail-row">
            <span class="detail-label">Agent ID:</span>
            <span class="detail-value">{{ result.agentId }}</span>
          </div>
          <div v-if="result.decisionReason" class="detail-row">
            <span class="detail-label">Decision Reason:</span>
            <span class="detail-value">{{ result.decisionReason }}</span>
          </div>
          <div v-if="result.allowed !== undefined" class="detail-row">
            <span class="detail-label">Access:</span>
            <span class="detail-value">{{ result.allowed ? 'Allowed' : 'Denied' }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { CheckCircle2, XCircle } from 'lucide-vue-next';

defineProps<{
  result: any;
}>();
</script>

<style scoped>
.test-results {
  max-height: 70vh;
  overflow-y: auto;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.result-card {
  padding: var(--spacing-lg);
  border-radius: var(--border-radius-md);
  border: 2px solid var(--border-color-primary);
}

.result-card.passed {
  background: var(--color-success-bg);
  border-color: var(--color-success);
}

.result-card.failed {
  background: var(--color-error-bg);
  border-color: var(--color-error);
}

.result-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
}

.result-icon {
  width: 24px;
  height: 24px;
}

.result-card.passed .result-icon {
  color: var(--color-success);
}

.result-card.failed .result-icon {
  color: var(--color-error);
}

.result-title {
  flex: 1;
  font-size: var(--font-size-lg);
  font-weight: 600;
  margin: 0;
}

.result-status {
  font-weight: 600;
  font-size: var(--font-size-sm);
  text-transform: uppercase;
}

.result-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.detail-row {
  display: flex;
  gap: var(--spacing-sm);
}

.detail-label {
  font-weight: 500;
  min-width: 150px;
}

.detail-value {
  color: var(--color-text-secondary);
}
</style>
