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

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Compliance', to: '/compliance' },
  { label: 'NIST 800-207', to: '/compliance/nist-800-207' },
];

const loading = ref(false);
const assessment = ref<any>(null);

const runAssessment = async () => {
  loading.value = true;
  try {
    const response = await axios.post('/api/compliance/nist-800-207/assess', {});
    assessment.value = response.data;
  } catch (error) {
    console.error('Error running assessment:', error);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.nist-page {
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

.assessment-results {
  margin-top: 24px;
}

.overall-score-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 32px;
  text-align: center;
}

.score-header {
  margin-bottom: 16px;
}

.score-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.score-value {
  font-size: 4rem;
  font-weight: 700;
  margin-bottom: 16px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-value.compliant {
  background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-value.non-compliant {
  background: linear-gradient(135deg, #fc8181 0%, #ef4444 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.score-status {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 8px;
  font-weight: 600;
}

.status-success {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.status-error {
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.status-icon {
  width: 20px;
  height: 20px;
}

.pillars-section {
  margin-bottom: 32px;
}

.pillars-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
}

.pillars-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.pillar-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.pillar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.pillar-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  text-transform: capitalize;
}

.pillar-score {
  font-size: 1.125rem;
  font-weight: 600;
  color: #4facfe;
}

.pillar-progress {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.progress-bar {
  flex: 1;
  height: 8px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.progress-percentage {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 600;
  min-width: 50px;
  text-align: right;
}

.pillar-controls {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.control-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  border-radius: 6px;
  font-size: 0.875rem;
}

.control-compliant {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.control-partial {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.control-non-compliant {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
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
  margin-top: 32px;
  padding: 24px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.gaps-title,
.recommendations-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.gaps-list,
.recommendations-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.gap-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  color: #fbbf24;
}

.gap-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.recommendation-item {
  padding: 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
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
