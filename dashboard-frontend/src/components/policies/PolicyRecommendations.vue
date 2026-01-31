<template>
  <div class="policy-recommendations">
    <div class="recommendations-header">
      <h3>AI Recommendations</h3>
      <button @click="loadRecommendations" :disabled="loading" class="btn-refresh">
        <RefreshCw :class="{ spinning: loading }" class="icon" />
        Refresh
      </button>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Generating recommendations...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadRecommendations" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="recommendations.length === 0" class="empty-state">
      <p>No recommendations available. Try refreshing or check back later.</p>
    </div>

    <div v-else class="recommendations-list">
      <div
        v-for="rec in recommendations"
        :key="rec.id"
        class="recommendation-card"
        :class="`impact-${rec.impact}`"
      >
        <div class="recommendation-header">
          <div class="recommendation-title-row">
            <h4>{{ rec.title }}</h4>
            <span class="recommendation-type-badge" :class="`type-${rec.type}`">
              {{ formatType(rec.type) }}
            </span>
          </div>
          <div class="recommendation-meta">
            <span class="impact-badge" :class="`impact-${rec.impact}`">
              Impact: {{ rec.impact }}
            </span>
            <span class="effort-badge" :class="`effort-${rec.effort}`">
              Effort: {{ rec.effort }}
            </span>
            <span class="confidence-badge">
              Confidence: {{ rec.confidence }}%
            </span>
          </div>
        </div>

        <p class="recommendation-description">{{ rec.description }}</p>

        <div v-if="rec.reasoning" class="recommendation-reasoning">
          <strong>Reasoning:</strong>
          <p>{{ rec.reasoning }}</p>
        </div>

        <div class="recommendation-actions">
          <button @click="applyRecommendation(rec)" class="btn-apply" :disabled="rec.status === 'applied'">
            {{ rec.status === 'applied' ? 'Applied' : 'Apply Recommendation' }}
          </button>
          <button @click="dismissRecommendation(rec)" class="btn-dismiss">
            Dismiss
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { RefreshCw, AlertTriangle } from 'lucide-vue-next';
import axios from 'axios';

interface PolicyRecommendation {
  id: string;
  type: 'add-rule' | 'modify-condition' | 'add-tag' | 'optimize' | 'security-improvement';
  title: string;
  description: string;
  reasoning: string;
  impact: 'low' | 'medium' | 'high';
  effort: 'low' | 'medium' | 'high';
  suggestedChange: Record<string, any>;
  confidence: number;
  status?: 'pending' | 'applied' | 'dismissed';
}

const props = defineProps<{
  policyId: string;
}>();

const recommendations = ref<PolicyRecommendation[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

const loadRecommendations = async () => {
  loading.value = true;
  error.value = null;

  try {
    const response = await axios.get(`/api/policies/${props.policyId}/recommendations`, {
      timeout: 15000, // 15 second timeout
    });
    
    if (!response.data || !Array.isArray(response.data)) {
      throw new Error('Invalid response format');
    }

    recommendations.value = response.data.map((rec: PolicyRecommendation) => ({
      ...rec,
      status: rec.status || 'pending',
    }));
  } catch (err: any) {
    if (err.code === 'ECONNABORTED') {
      error.value = 'Request timed out. Generating recommendations is taking longer than expected.';
    } else if (err.response?.status === 404) {
      error.value = 'Policy not found. Please refresh the page.';
    } else if (err.response?.status === 503) {
      error.value = 'AI service is temporarily unavailable. Please try again later.';
    } else {
      error.value = err.response?.data?.message || err.message || 'Failed to load recommendations. Please try again.';
    }
    console.error('Error loading recommendations:', err);
  } finally {
    loading.value = false;
  }
};

const applyRecommendation = async (rec: PolicyRecommendation) => {
  try {
    // In production, this would call an API to apply the recommendation
    // For now, just mark it as applied locally
    rec.status = 'applied';
    // TODO: Implement actual application logic
    alert(`Applying recommendation: ${rec.title}\n\nThis would update the policy with the suggested changes.`);
  } catch (err: any) {
    console.error('Error applying recommendation:', err);
    alert('Failed to apply recommendation');
  }
};

const dismissRecommendation = (rec: PolicyRecommendation) => {
  rec.status = 'dismissed';
  recommendations.value = recommendations.value.filter(r => r.id !== rec.id);
};

const formatType = (type: string): string => {
  return type
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

onMounted(() => {
  loadRecommendations();
});
</script>

<style scoped>
.policy-recommendations {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.recommendations-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
}

.recommendations-header h3 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.btn-refresh {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
}

.btn-refresh:hover:not(:disabled) {
  background: var(--border-color-muted);
}

.btn-refresh:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.icon {
  width: 16px;
  height: 16px;
}

.icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.recommendations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.recommendation-card {
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  border-left: 4px solid var(--color-primary);
}

.recommendation-card.impact-high {
  border-left-color: var(--color-error);
}

.recommendation-card.impact-medium {
  border-left-color: var(--color-warning);
}

.recommendation-card.impact-low {
  border-left-color: var(--color-success);
}

.recommendation-header {
  margin-bottom: var(--spacing-md);
}

.recommendation-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.recommendation-title-row h4 {
  margin: 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  flex: 1;
}

.recommendation-type-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  margin-left: var(--spacing-sm);
}

.recommendation-type-badge.type-add-rule {
  background: var(--color-success);
  color: white;
}

.recommendation-type-badge.type-modify-condition {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.recommendation-type-badge.type-add-tag {
  background: var(--color-primary);
  color: white;
}

.recommendation-type-badge.type-optimize {
  background: var(--color-info);
  color: white;
}

.recommendation-type-badge.type-security-improvement {
  background: var(--color-error);
  color: white;
}

.recommendation-meta {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.impact-badge,
.effort-badge,
.confidence-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 500;
}

.impact-badge.impact-high {
  background: rgba(var(--color-error-rgb), 0.1);
  color: var(--color-error);
}

.impact-badge.impact-medium {
  background: rgba(var(--color-warning-rgb), 0.1);
  color: var(--color-warning);
}

.impact-badge.impact-low {
  background: rgba(var(--color-success-rgb), 0.1);
  color: var(--color-success);
}

.effort-badge.effort-high {
  background: rgba(var(--color-error-rgb), 0.1);
  color: var(--color-error);
}

.effort-badge.effort-medium {
  background: rgba(var(--color-warning-rgb), 0.1);
  color: var(--color-warning);
}

.effort-badge.effort-low {
  background: rgba(var(--color-success-rgb), 0.1);
  color: var(--color-success);
}

.confidence-badge {
  background: rgba(var(--color-primary-rgb), 0.1);
  color: var(--color-primary);
}

.recommendation-description {
  margin: var(--spacing-md) 0;
  color: var(--color-text-primary);
  line-height: 1.6;
}

.recommendation-reasoning {
  margin: var(--spacing-md) 0;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
}

.recommendation-reasoning strong {
  display: block;
  margin-bottom: var(--spacing-xs);
  color: var(--color-text-secondary);
}

.recommendation-reasoning p {
  margin: 0;
  color: var(--color-text-primary);
  line-height: 1.6;
}

.recommendation-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-md);
}

.btn-apply,
.btn-dismiss {
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-apply {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-apply:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-apply:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-dismiss {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.btn-dismiss:hover {
  background: var(--border-color-muted);
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: var(--spacing-xl);
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin: 0 auto var(--spacing-md);
  animation: spin 1s linear infinite;
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
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
