<template>
  <div class="gap-analysis-view">
    <div class="view-header">
      <div class="header-content">
        <h2>Gap Analysis</h2>
        <p class="subtitle">Comprehensive analysis of policy compliance gaps</p>
      </div>
      <div class="header-actions">
        <button @click="loadAnalysis" :disabled="loading" class="btn-secondary">
          Refresh
        </button>
        <button @click="exportReport" :disabled="!analysis" class="btn-primary">
          Export Report
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Analyzing gaps...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadAnalysis" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="analysis" class="analysis-content">
      <!-- Summary Cards -->
      <div class="summary-cards">
        <div class="summary-card total">
          <div class="card-icon">
            <AlertCircle class="icon" />
          </div>
          <div class="card-content">
            <div class="card-value">{{ analysis.summary.totalGaps }}</div>
            <div class="card-label">Total Gaps</div>
          </div>
        </div>
        <div class="summary-card critical">
          <div class="card-icon">
            <AlertTriangle class="icon" />
          </div>
          <div class="card-content">
            <div class="card-value">{{ analysis.summary.critical }}</div>
            <div class="card-label">Critical</div>
          </div>
        </div>
        <div class="summary-card high">
          <div class="card-icon">
            <AlertCircle class="icon" />
          </div>
          <div class="card-content">
            <div class="card-value">{{ analysis.summary.high }}</div>
            <div class="card-label">High</div>
          </div>
        </div>
        <div class="summary-card compliance">
          <div class="card-icon">
            <Gauge class="icon" />
          </div>
          <div class="card-content">
            <div class="card-value">{{ analysis.summary.complianceScore }}%</div>
            <div class="card-label">Compliance Score</div>
          </div>
        </div>
      </div>

      <!-- Recommendations -->
      <div v-if="analysis.recommendations.length > 0" class="recommendations-section">
        <h3>Recommendations</h3>
        <ul class="recommendations-list">
          <li v-for="(rec, index) in analysis.recommendations" :key="index">
            {{ rec }}
          </li>
        </ul>
      </div>

      <!-- Filters -->
      <div class="filters-section">
        <div class="filter-group">
          <label>Filter by Severity:</label>
          <div class="filter-buttons">
            <button
              v-for="severity in ['all', 'critical', 'high', 'medium', 'low']"
              :key="severity"
              @click="filterSeverity = severity === 'all' ? null : severity"
              :class="['filter-btn', { active: filterSeverity === severity || (severity === 'all' && !filterSeverity) }]"
            >
              {{ severity.charAt(0).toUpperCase() + severity.slice(1) }}
            </button>
          </div>
        </div>
        <div class="filter-group">
          <label>Filter by Type:</label>
          <div class="filter-buttons">
            <button
              v-for="type in ['all', 'enforcement', 'tag', 'attribute', 'policy']"
              :key="type"
              @click="filterType = type === 'all' ? null : type"
              :class="['filter-btn', { active: filterType === type || (type === 'all' && !filterType) }]"
            >
              {{ type.charAt(0).toUpperCase() + type.slice(1) }}
            </button>
          </div>
        </div>
        <div class="filter-group">
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search gaps..."
            class="search-input"
          />
        </div>
      </div>

      <!-- Gaps List -->
      <div class="gaps-list">
        <div
          v-for="gap in filteredGaps"
          :key="gap.id"
          class="gap-card"
          :class="`severity-${gap.severity}`"
          @click="viewGapDetails(gap)"
        >
          <div class="gap-header">
            <div class="gap-severity-badge" :class="`badge-${gap.severity}`">
              {{ gap.severity.toUpperCase() }}
            </div>
            <div class="gap-priority">
              Priority: {{ gap.priority }}/10
            </div>
            <div class="gap-type-badge">
              {{ gap.type }}
            </div>
          </div>
          <h4 class="gap-title">{{ gap.title }}</h4>
          <p class="gap-description">{{ gap.description }}</p>
          <div class="gap-meta">
            <div class="meta-item">
              <span class="meta-label">Effort:</span>
              <span class="meta-value">{{ gap.estimatedEffort }}</span>
            </div>
            <div v-if="gap.affectedResources.length > 0" class="meta-item">
              <span class="meta-label">Resources:</span>
              <span class="meta-value">{{ gap.affectedResources.length }}</span>
            </div>
            <div v-if="gap.affectedApplications.length > 0" class="meta-item">
              <span class="meta-label">Applications:</span>
              <span class="meta-value">{{ gap.affectedApplications.length }}</span>
            </div>
          </div>
          <div class="gap-actions">
            <button @click.stop="viewRemediation(gap)" class="btn-view-remediation">
              View Remediation Guide
            </button>
          </div>
        </div>

        <div v-if="filteredGaps.length === 0" class="no-gaps">
          <CheckCircle2 class="success-icon" />
          <h3>No gaps found</h3>
          <p v-if="filterSeverity || filterType || searchQuery">
            Try adjusting your filters
          </p>
          <p v-else>
            All policies are compliant!
          </p>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <AlertCircle class="empty-icon" />
      <h3>Gap Analysis</h3>
      <p>Click "Refresh" to analyze policy compliance gaps</p>
    </div>

    <!-- Remediation Guide Modal -->
    <RemediationGuide
      v-if="selectedGap"
      :show="showRemediationModal"
      :gap="selectedGap"
      @close="closeRemediationModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { AlertCircle, AlertTriangle, Gauge, CheckCircle2 } from 'lucide-vue-next';
import RemediationGuide from './RemediationGuide.vue';
import axios from 'axios';

interface Props {
  policyId?: string;
  applicationId?: string;
}

const props = defineProps<Props>();

interface PrioritizedGap {
  id: string;
  type: 'enforcement' | 'tag' | 'attribute' | 'policy';
  severity: 'low' | 'medium' | 'high' | 'critical';
  priority: number;
  title: string;
  description: string;
  affectedResources: string[];
  affectedApplications: string[];
  remediation: any;
  estimatedEffort: string;
}

interface GapAnalysis {
  policyId?: string;
  applicationId?: string;
  gaps: PrioritizedGap[];
  summary: {
    totalGaps: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    complianceScore: number;
  };
  recommendations: string[];
}

const analysis = ref<GapAnalysis | null>(null);
const loading = ref(false);
const error = ref<string>('');
const filterSeverity = ref<string | null>(null);
const filterType = ref<string | null>(null);
const searchQuery = ref('');
const selectedGap = ref<PrioritizedGap | null>(null);
const showRemediationModal = ref(false);

const filteredGaps = computed(() => {
  if (!analysis.value) return [];

  return analysis.value.gaps.filter(gap => {
    if (filterSeverity.value && gap.severity !== filterSeverity.value) {
      return false;
    }
    if (filterType.value && gap.type !== filterType.value) {
      return false;
    }
    if (searchQuery.value) {
      const query = searchQuery.value.toLowerCase();
      return (
        gap.title.toLowerCase().includes(query) ||
        gap.description.toLowerCase().includes(query)
      );
    }
    return true;
  });
});

const loadAnalysis = async () => {
  loading.value = true;
  error.value = '';

  try {
    const params: any = {};
    if (props.policyId) params.policyId = props.policyId;
    if (props.applicationId) params.applicationId = props.applicationId;

    const response = await axios.get('/api/policies/gap-analysis', { params });
    analysis.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load gap analysis';
    analysis.value = null;
  } finally {
    loading.value = false;
  }
};

const viewGapDetails = (gap: PrioritizedGap) => {
  selectedGap.value = gap;
  showRemediationModal.value = true;
};

const viewRemediation = (gap: PrioritizedGap) => {
  viewGapDetails(gap);
};

const closeRemediationModal = () => {
  showRemediationModal.value = false;
  selectedGap.value = null;
};

const exportReport = () => {
  if (!analysis.value) return;

  const report = {
    generatedAt: new Date().toISOString(),
    summary: analysis.value.summary,
    recommendations: analysis.value.recommendations,
    gaps: analysis.value.gaps.map(gap => ({
      id: gap.id,
      severity: gap.severity,
      type: gap.type,
      title: gap.title,
      description: gap.description,
      estimatedEffort: gap.estimatedEffort,
    })),
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `gap-analysis-${new Date().toISOString().split('T')[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

onMounted(() => {
  loadAnalysis();
});
</script>

<style scoped>
.gap-analysis-view {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--color-bg-primary);
}

.view-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.header-content h2 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-2xl);
  font-weight: 600;
}

.subtitle {
  margin: 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.analysis-content {
  flex: 1;
  overflow: auto;
  padding: var(--spacing-lg);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.summary-card {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.summary-card.critical {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.1);
}

.summary-card.high {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.05);
}

.card-icon .icon {
  width: 32px;
  height: 32px;
}

.card-content {
  flex: 1;
}

.card-value {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  line-height: 1;
}

.card-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-top: var(--spacing-xs);
}

.recommendations-section {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border-left: 4px solid var(--color-primary);
}

.recommendations-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.recommendations-list {
  margin: 0;
  padding-left: var(--spacing-lg);
}

.recommendations-list li {
  margin-bottom: var(--spacing-xs);
  line-height: 1.6;
}

.filters-section {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.filter-group label {
  font-size: var(--font-size-sm);
  font-weight: 500;
  color: var(--color-text-secondary);
}

.filter-buttons {
  display: flex;
  gap: var(--spacing-xs);
  flex-wrap: wrap;
}

.filter-btn {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-xs);
  cursor: pointer;
  transition: var(--transition-all);
}

.filter-btn:hover {
  background: var(--border-color-muted);
}

.filter-btn.active {
  background: var(--color-primary);
  border-color: var(--color-primary);
  color: white;
}

.search-input {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.gaps-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.gap-card {
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  border-left: 4px solid;
  background: var(--color-bg-secondary);
  cursor: pointer;
  transition: var(--transition-all);
}

.gap-card:hover {
  transform: translateX(4px);
  box-shadow: var(--shadow-md);
}

.gap-card.severity-critical {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.1);
}

.gap-card.severity-high {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.05);
}

.gap-card.severity-medium {
  border-color: var(--color-warning);
  background: rgba(var(--color-warning-rgb), 0.05);
}

.gap-card.severity-low {
  border-color: var(--color-text-secondary);
}

.gap-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.gap-severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.badge-critical,
.badge-high {
  background: var(--color-error);
  color: white;
}

.badge-medium {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.badge-low {
  background: var(--color-text-secondary);
  color: white;
}

.gap-priority {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.gap-type-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  text-transform: uppercase;
  margin-left: auto;
}

.gap-title {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.gap-description {
  margin: 0 0 var(--spacing-md) 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  line-height: 1.6;
}

.gap-meta {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
  font-size: var(--font-size-xs);
}

.meta-label {
  color: var(--color-text-secondary);
  margin-right: var(--spacing-xs);
}

.meta-value {
  font-weight: 500;
}

.gap-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-view-remediation {
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: 500;
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-view-remediation:hover {
  opacity: 0.9;
}

.no-gaps {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--color-success);
}

.success-icon {
  width: 48px;
  height: 48px;
  color: var(--color-success);
  margin-bottom: var(--spacing-md);
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  min-height: 400px;
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon,
.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
}
</style>
