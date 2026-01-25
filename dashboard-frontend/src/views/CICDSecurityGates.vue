<template>
  <div class="cicd-security-gates-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">CI/CD Security Gates</h1>
          <p class="page-description">Validate pre-merge policies, scan infrastructure, and check security gates</p>
        </div>
        <button @click="checkGates" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Checking...' : 'Check Security Gates' }}
        </button>
      </div>
    </div>

    <div v-if="gateResult" class="gates-results">
      <div class="overall-status-card" :class="gateResult.passed ? 'status-success' : 'status-error'">
        <div class="status-header">
          <CheckCircle2 v-if="gateResult.passed" class="status-icon-large" />
          <XCircle v-else class="status-icon-large" />
          <div>
            <h2 class="status-title">{{ gateResult.passed ? 'All Gates Passed' : 'Gates Failed' }}</h2>
            <p class="status-message">{{ gateResult.message }}</p>
          </div>
        </div>
        <div class="risk-score">
          <span class="risk-label">Risk Score:</span>
          <span class="risk-value">{{ gateResult.riskScore.toFixed(2) }}</span>
        </div>
      </div>

      <div class="gates-section">
        <h3 class="gates-title">Security Gates</h3>
        <div class="gates-list">
          <div v-for="(gate, idx) in gateResult.gates" :key="idx" class="gate-item">
            <div class="gate-header">
              <CheckCircle2 v-if="gate.passed" class="gate-icon success" />
              <XCircle v-else class="gate-icon error" />
              <h4 class="gate-name">{{ gate.name }}</h4>
            </div>
            <div v-if="gate.details" class="gate-details">
              <div v-if="gate.details.passed !== undefined" class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="detail-value" :class="gate.details.passed ? 'success' : 'error'">
                  {{ gate.details.passed ? 'Passed' : 'Failed' }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="gateResult.findings.length > 0" class="findings-section">
        <h3 class="findings-title">Findings</h3>
        <div class="findings-list">
          <div v-for="(finding, idx) in gateResult.findings" :key="idx" class="finding-item" :class="`finding-${finding.severity}`">
            <AlertTriangle class="finding-icon" />
            <div class="finding-content">
              <div class="finding-header">
                <span class="finding-severity">{{ finding.severity }}</span>
                <span class="finding-type">{{ finding.type }}</span>
              </div>
              <p class="finding-description">{{ finding.description || finding.message }}</p>
              <div v-if="finding.recommendation" class="finding-recommendation">
                <strong>Recommendation:</strong> {{ finding.recommendation }}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <Shield class="empty-icon" />
      <h3>No Security Gate Results</h3>
      <p>Check security gates to see validation results</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Shield, CheckCircle2, XCircle, AlertTriangle } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';
import { useApiData } from '../composables/useApiData';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'CI/CD Security Gates', to: '/admin/ci-cd/security-gates' },
];

const gateResult = ref<any>(null);

const { loading, load: checkGates } = useApiData(
  async () => {
    const response = await axios.post('/api/cicd/security-gates/check-gates', {
      pr: { id: 'test', number: 1, branch: 'test', baseBranch: 'main', files: [], author: 'test' },
      config: {
        severityThreshold: 'high',
        failOnThreshold: true,
        requirePolicies: true,
        scanIAC: true,
        scanContainers: true,
        validateK8sRBAC: true,
      },
    });
    gateResult.value = response.data;
    return response.data;
  },
  {
    errorMessage: 'Failed to check security gates',
  }
);
</script>

<style scoped>
.cicd-security-gates-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  white-space: nowrap;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: var(--border-width-medium) solid var(--color-text-primary);
  opacity: 0.3;
  border-top-color: var(--color-text-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.gates-results {
  margin-top: var(--spacing-lg);
}

.overall-status-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid;
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  margin-bottom: var(--spacing-xl);
}

.overall-status-card.status-success {
  border-color: var(--color-success);
}

.overall-status-card.status-error {
  border-color: var(--color-error);
}

.status-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.status-icon-large {
  width: 48px;
  height: 48px;
  flex-shrink: 0;
}

.status-success .status-icon-large {
  color: var(--color-success);
}

.status-error .status-icon-large {
  color: var(--color-error);
}

.status-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.status-message {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.risk-score {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
}

.risk-label {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}

.risk-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-primary);
}

.gates-section {
  margin-bottom: var(--spacing-xl);
}

.gates-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.gates-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--spacing-md);
}

.gate-item {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
}

.gate-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.gate-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.gate-icon.success {
  color: var(--color-success);
}

.gate-icon.error {
  color: var(--color-error);
}

.gate-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.gate-details {
  margin-top: var(--spacing-sm);
  padding-top: var(--spacing-sm);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: var(--spacing-sm) 0;
}

.detail-label {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}

.detail-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
}

.detail-value.success {
  color: var(--color-success);
}

.detail-value.error {
  color: var(--color-error);
}

.findings-section {
  margin-top: var(--spacing-xl);
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.findings-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.finding-item {
  display: flex;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  border-left: 4px solid;
}

.finding-critical {
  background: var(--color-error-bg);
  border-left-color: var(--color-error);
}

.finding-high {
  background: var(--color-error-bg);
  border-left-color: var(--color-error);
}

.finding-medium {
  background: var(--color-warning-bg);
  border-left-color: var(--color-warning);
}

.finding-low {
  background: var(--border-color-muted);
  border-left-color: var(--color-primary);
}

.finding-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.finding-critical .finding-icon,
.finding-high .finding-icon {
  color: var(--color-error);
}

.finding-medium .finding-icon {
  color: var(--color-warning);
}

.finding-low .finding-icon {
  color: var(--color-primary);
}

.finding-content {
  flex: 1;
}

.finding-header {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.finding-severity {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.finding-critical .finding-severity,
.finding-high .finding-severity {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.finding-medium .finding-severity {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.finding-low .finding-severity {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.finding-type {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.finding-description {
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
  line-height: 1.5;
}

.finding-recommendation {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-top: var(--spacing-sm);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
}
</style>
