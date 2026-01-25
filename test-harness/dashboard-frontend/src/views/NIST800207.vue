<template>
  <div class="nist-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">NIST 800-207 Compliance</h1>
          <p class="page-description">Zero Trust Architecture compliance assessment</p>
        </div>
        <button @click="runAssessment" class="btn-primary" :disabled="loading">
          <Shield v-if="!loading" class="btn-icon" />
          <div v-else class="loading-spinner-small"></div>
          {{ loading ? 'Assessing...' : 'Run Assessment' }}
        </button>
      </div>
    </div>

    <div v-if="assessment" class="assessment-results">
      <div class="overall-score-card">
        <div class="score-header">
          <h2>Overall Compliance</h2>
          <div class="score-value" :class="assessment.compliant ? 'compliant' : 'non-compliant'">
            {{ assessment.compliancePercentage.toFixed(1) }}%
          </div>
        </div>
        <div class="score-status" :class="assessment.compliant ? 'status-success' : 'status-error'">
          <CheckCircle2 v-if="assessment.compliant" class="status-icon" />
          <XCircle v-else class="status-icon" />
          <span>{{ assessment.compliant ? 'Compliant' : 'Non-Compliant' }}</span>
        </div>
      </div>

      <div class="pillars-section">
        <h3 class="pillars-title">ZTA Pillars</h3>
        <div class="pillars-grid">
          <div v-for="pillar in assessment.assessment.pillars" :key="pillar.name" class="pillar-card">
            <div class="pillar-header">
              <h4 class="pillar-name">{{ pillar.name.charAt(0).toUpperCase() + pillar.name.slice(1) }}</h4>
              <div class="pillar-score">
                {{ pillar.score }}/{{ pillar.maxScore }}
              </div>
            </div>
            <div class="pillar-progress">
              <div class="progress-bar">
                <div
                  class="progress-fill"
                  :style="{ width: `${(pillar.score / pillar.maxScore) * 100}%` }"
                ></div>
              </div>
              <span class="progress-percentage">{{ ((pillar.score / pillar.maxScore) * 100).toFixed(1) }}%</span>
            </div>
            <div class="pillar-controls">
              <div
                v-for="control in pillar.controls"
                :key="control.id"
                class="control-item"
                :class="`control-${control.status}`"
              >
                <CheckCircle2 v-if="control.status === 'compliant'" class="control-icon" />
                <AlertTriangle v-else-if="control.status === 'partial'" class="control-icon" />
                <XCircle v-else class="control-icon" />
                <span class="control-name">{{ control.name }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="assessment.assessment.gaps.length > 0" class="gaps-section">
        <h3 class="gaps-title">Compliance Gaps</h3>
        <div class="gaps-list">
          <div v-for="(gap, idx) in assessment.assessment.gaps" :key="idx" class="gap-item">
            <AlertTriangle class="gap-icon" />
            <span>{{ gap }}</span>
          </div>
        </div>
      </div>

      <div v-if="assessment.assessment.recommendations.length > 0" class="recommendations-section">
        <h3 class="recommendations-title">Recommendations</h3>
        <div class="recommendations-list">
          <div v-for="(rec, idx) in assessment.assessment.recommendations" :key="idx" class="recommendation-item">
            <span>{{ rec }}</span>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <Shield class="empty-icon" />
      <h3>No Assessment Results</h3>
      <p>Run an assessment to view NIST 800-207 compliance status</p>
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
  { label: 'Compliance', to: '/compliance' },
  { label: 'NIST 800-207', to: '/compliance/nist-800-207' },
];

const assessment = ref<any>(null);

const { loading, load: runAssessment } = useApiData(
  async () => {
    const response = await axios.post('/api/compliance/nist-800-207/assess', {});
    assessment.value = response.data;
    return response.data;
  },
  {
    errorMessage: 'Failed to run assessment',
  }
);
</script>

<style scoped>
.nist-page {
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
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
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
  border: var(--border-width-medium) solid rgba(255, 255, 255, 0.3);
  border-top-color: var(--color-text-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.assessment-results {
  margin-top: var(--spacing-lg);
}

.overall-score-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  margin-bottom: var(--spacing-xl);
  text-align: center;
}

.score-header {
  margin-bottom: var(--spacing-md);
}

.score-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.score-value {
  font-size: var(--font-size-5xl);
  font-weight: var(--font-weight-bold);
  margin-bottom: var(--spacing-md);
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-value.compliant {
  background: linear-gradient(135deg, var(--color-success) 0%, #16a34a 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-value.non-compliant {
  background: linear-gradient(135deg, var(--color-error) 0%, #ef4444 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-status {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-semibold);
}

.status-success {
  background: var(--color-success-bg);
  border: var(--border-width-thin) solid var(--color-success);
  color: var(--color-success);
}

.status-error {
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  color: var(--color-error);
}

.status-icon {
  width: 20px;
  height: 20px;
}

.pillars-section {
  margin-bottom: var(--spacing-xl);
}

.pillars-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.pillars-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--spacing-lg);
}

.pillar-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.pillar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.pillar-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  text-transform: capitalize;
}

.pillar-score {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-primary);
}

.pillar-progress {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.progress-bar {
  flex: 1;
  height: 8px;
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-xs);
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: var(--gradient-primary);
  transition: width 0.3s;
}

.progress-percentage {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-semibold);
  min-width: 50px;
  text-align: right;
}

.pillar-controls {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.control-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
}

.control-compliant {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.control-partial {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.control-non-compliant {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.control-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.control-name {
  flex: 1;
}

.gaps-section,
.recommendations-section {
  margin-top: var(--spacing-xl);
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.gaps-title,
.recommendations-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.gaps-list,
.recommendations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.gap-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-warning-bg);
  border: var(--border-width-thin) solid var(--color-warning);
  border-radius: var(--border-radius-md);
  color: var(--color-warning);
}

.gap-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.recommendation-item {
  padding: var(--spacing-sm);
  background: rgba(79, 172, 254, 0.1);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
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
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
}
</style>
