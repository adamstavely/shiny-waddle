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

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'CI/CD Security Gates', to: '/admin/ci-cd/security-gates' },
];

const loading = ref(false);
const gateResult = ref<any>(null);

const checkGates = async () => {
  loading.value = true;
  try {
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
  } catch (error) {
    console.error('Error checking gates:', error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.cicd-security-gates-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: #ffffff;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.gates-results {
  margin-top: 24px;
}

.overall-status-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid;
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 32px;
}

.overall-status-card.status-success {
  border-color: rgba(34, 197, 94, 0.3);
}

.overall-status-card.status-error {
  border-color: rgba(252, 129, 129, 0.3);
}

.status-header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}

.status-icon-large {
  width: 48px;
  height: 48px;
  flex-shrink: 0;
}

.status-success .status-icon-large {
  color: #22c55e;
}

.status-error .status-icon-large {
  color: #fc8181;
}

.status-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.status-message {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0;
}

.risk-score {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.risk-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.risk-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #4facfe;
}

.gates-section {
  margin-bottom: 32px;
}

.gates-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
}

.gates-list {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
}

.gate-item {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.gate-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.gate-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.gate-icon.success {
  color: #22c55e;
}

.gate-icon.error {
  color: #fc8181;
}

.gate-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.gate-details {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
}

.detail-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.detail-value {
  font-size: 0.9rem;
  font-weight: 600;
}

.detail-value.success {
  color: #22c55e;
}

.detail-value.error {
  color: #fc8181;
}

.findings-section {
  margin-top: 32px;
  padding: 24px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.findings-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.finding-item {
  display: flex;
  gap: 12px;
  padding: 16px;
  border-radius: 8px;
  border-left: 4px solid;
}

.finding-critical {
  background: rgba(252, 129, 129, 0.1);
  border-left-color: #fc8181;
}

.finding-high {
  background: rgba(252, 129, 129, 0.1);
  border-left-color: #fc8181;
}

.finding-medium {
  background: rgba(251, 191, 36, 0.1);
  border-left-color: #fbbf24;
}

.finding-low {
  background: rgba(79, 172, 254, 0.1);
  border-left-color: #4facfe;
}

.finding-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.finding-critical .finding-icon,
.finding-high .finding-icon {
  color: #fc8181;
}

.finding-medium .finding-icon {
  color: #fbbf24;
}

.finding-low .finding-icon {
  color: #4facfe;
}

.finding-content {
  flex: 1;
}

.finding-header {
  display: flex;
  gap: 12px;
  margin-bottom: 8px;
}

.finding-severity {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.finding-critical .finding-severity,
.finding-high .finding-severity {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.finding-medium .finding-severity {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.finding-low .finding-severity {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.finding-type {
  padding: 4px 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  font-size: 0.75rem;
  color: #4facfe;
}

.finding-description {
  color: #ffffff;
  margin-bottom: 8px;
  line-height: 1.5;
}

.finding-recommendation {
  padding: 8px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #a0aec0;
  margin-top: 8px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
}
</style>
