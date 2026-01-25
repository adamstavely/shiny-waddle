<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Shield class="modal-title-icon" />
              <h2>{{ result?.testName }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body" v-if="result">
            <!-- Status Badge -->
            <div class="status-badge-section">
              <span class="status-badge" :class="`badge-${result.status}`">
                {{ result.status }}
              </span>
              <span class="test-type-badge">{{ formatTestType(result.testType) }}</span>
            </div>

            <!-- Basic Information -->
            <div class="detail-section">
              <h3 class="section-title">Test Details</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Endpoint</span>
                  <span class="info-value">{{ result.method }} {{ result.endpoint }}</span>
                </div>
                <div class="info-item" v-if="result.statusCode">
                  <span class="info-label">Status Code</span>
                  <span class="info-value" :class="getStatusClass(result.statusCode)">
                    {{ result.statusCode }}
                  </span>
                </div>
                <div class="info-item" v-if="result.responseTime">
                  <span class="info-label">Response Time</span>
                  <span class="info-value">{{ formatDuration(result.responseTime) }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Timestamp</span>
                  <span class="info-value">{{ formatDateTime(result.timestamp) }}</span>
                </div>
              </div>
            </div>

            <!-- Authentication Result -->
            <div class="detail-section" v-if="result.authenticationResult">
              <h3 class="section-title">Authentication</h3>
              <div class="auth-result">
                <span class="auth-status" :class="result.authenticationResult.authenticated ? 'authenticated' : 'not-authenticated'">
                  {{ result.authenticationResult.authenticated ? 'Authenticated' : 'Not Authenticated' }}
                </span>
                <div v-if="result.authenticationResult.tokenValid !== undefined" class="auth-details">
                  <span>Token Valid: {{ result.authenticationResult.tokenValid ? 'Yes' : 'No' }}</span>
                  <span v-if="result.authenticationResult.tokenExpired !== undefined">
                    Token Expired: {{ result.authenticationResult.tokenExpired ? 'Yes' : 'No' }}
                  </span>
                </div>
              </div>
            </div>

            <!-- Authorization Result -->
            <div class="detail-section" v-if="result.authorizationResult">
              <h3 class="section-title">Authorization</h3>
              <div class="authz-result">
                <span class="authz-status" :class="result.authorizationResult.authorized ? 'authorized' : 'not-authorized'">
                  {{ result.authorizationResult.authorized ? 'Authorized' : 'Not Authorized' }}
                </span>
                <p v-if="result.authorizationResult.reason" class="authz-reason">
                  {{ result.authorizationResult.reason }}
                </p>
              </div>
            </div>

            <!-- Rate Limit Info -->
            <div class="detail-section" v-if="result.rateLimitInfo">
              <h3 class="section-title">Rate Limiting</h3>
              <div class="rate-limit-info">
                <div class="rate-limit-item" v-if="result.rateLimitInfo.limit">
                  <span class="rate-limit-label">Limit:</span>
                  <span class="rate-limit-value">{{ result.rateLimitInfo.limit }}</span>
                </div>
                <div class="rate-limit-item" v-if="result.rateLimitInfo.remaining !== undefined">
                  <span class="rate-limit-label">Remaining:</span>
                  <span class="rate-limit-value">{{ result.rateLimitInfo.remaining }}</span>
                </div>
                <div class="rate-limit-item" v-if="result.rateLimitInfo.resetTime">
                  <span class="rate-limit-label">Reset Time:</span>
                  <span class="rate-limit-value">{{ formatDateTime(result.rateLimitInfo.resetTime) }}</span>
                </div>
              </div>
            </div>

            <!-- Security Issues -->
            <div class="detail-section" v-if="result.securityIssues && result.securityIssues.length > 0">
              <h3 class="section-title">Security Issues</h3>
              <ul class="security-issues-list">
                <li v-for="(issue, index) in result.securityIssues" :key="index" class="security-issue">
                  <AlertTriangle class="issue-icon" />
                  {{ issue }}
                </li>
              </ul>
            </div>

            <!-- Vulnerability Details -->
            <div class="detail-section" v-if="result.vulnerabilityDetails && result.vulnerabilityDetails.length > 0">
              <h3 class="section-title">Vulnerabilities</h3>
              <div class="vulnerabilities-list">
                <div
                  v-for="(vuln, index) in result.vulnerabilityDetails"
                  :key="index"
                  class="vulnerability-item"
                  :class="`severity-${vuln.severity}`"
                >
                  <div class="vuln-header">
                    <span class="vuln-type">{{ vuln.type }}</span>
                    <span class="vuln-severity">{{ vuln.severity }}</span>
                  </div>
                  <p class="vuln-description">{{ vuln.description }}</p>
                  <p v-if="vuln.recommendation" class="vuln-recommendation">
                    <strong>Recommendation:</strong> {{ vuln.recommendation }}
                  </p>
                </div>
              </div>
            </div>

            <!-- Error -->
            <div class="detail-section" v-if="result.error">
              <h3 class="section-title">Error</h3>
              <div class="error-message">
                {{ result.error }}
              </div>
            </div>

            <!-- Details -->
            <div class="detail-section" v-if="result.details && Object.keys(result.details).length > 0">
              <h3 class="section-title">Additional Details</h3>
              <pre class="details-preview">{{ JSON.stringify(result.details, null, 2) }}</pre>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { Shield, X, AlertTriangle } from 'lucide-vue-next';
import type { APISecurityTestResultEntity } from '../types/api-security';

interface Props {
  show: boolean;
  result: APISecurityTestResultEntity | null;
}

defineProps<Props>();
defineEmits<{
  close: [];
}>();

const formatTestType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatDateTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
};

const getStatusClass = (statusCode: number): string => {
  if (statusCode >= 200 && statusCode < 300) return 'status-success';
  if (statusCode >= 400 && statusCode < 500) return 'status-client-error';
  if (statusCode >= 500) return 'status-server-error';
  return '';
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 28px;
  height: 28px;
  color: #4facfe;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 8px;
  transition: all 0.2s;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.status-badge-section {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.status-badge,
.test-type-badge {
  padding: 6px 16px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
}

.badge-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.badge-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.badge-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.test-type-badge {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.detail-section {
  margin-bottom: 32px;
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value {
  font-size: 0.9rem;
  color: #ffffff;
}

.status-success {
  color: #22c55e;
}

.status-client-error {
  color: #fc8181;
}

.status-server-error {
  color: #fbbf24;
}

.auth-result,
.authz-result {
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.auth-status,
.authz-status {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 600;
  margin-bottom: 8px;
}

.authenticated,
.authorized {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.not-authenticated,
.not-authorized {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.auth-details {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.authz-reason {
  margin-top: 8px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.rate-limit-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rate-limit-item {
  display: flex;
  gap: 8px;
  font-size: 0.9rem;
}

.rate-limit-label {
  color: #718096;
  font-weight: 500;
}

.rate-limit-value {
  color: #ffffff;
}

.security-issues-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.security-issue {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin-bottom: 8px;
  font-size: 0.9rem;
  color: #fc8181;
}

.issue-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.vulnerabilities-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.vulnerability-item {
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid;
  border-radius: 8px;
}

.vulnerability-item.severity-critical {
  border-color: #fc8181;
  background: rgba(252, 129, 129, 0.1);
}

.vulnerability-item.severity-high {
  border-color: #fbbf24;
  background: rgba(251, 191, 36, 0.1);
}

.vulnerability-item.severity-medium {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.vulnerability-item.severity-low {
  border-color: #718096;
  background: rgba(113, 128, 150, 0.1);
}

.vuln-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.vuln-type {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.vuln-severity {
  padding: 4px 8px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.severity-critical .vuln-severity {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.severity-high .vuln-severity {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-medium .vuln-severity {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.severity-low .vuln-severity {
  background: rgba(113, 128, 150, 0.2);
  color: #718096;
}

.vuln-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.vuln-recommendation {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.error-message {
  padding: 12px 16px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  color: #fc8181;
  font-size: 0.9rem;
}

.details-preview {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  color: #a0aec0;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

