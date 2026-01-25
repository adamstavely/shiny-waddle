<template>
  <div class="remediation-help" @click.stop>
    <div class="help-header">
      <h3>Remediation Help</h3>
      <button @click="$emit('close')" class="close-btn">
        <X class="close-icon" />
      </button>
    </div>

    <div v-if="loading" class="loading">Loading help information...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="helpData" class="help-content">
      <!-- Remediation Steps -->
      <div class="help-section">
        <h4>Remediation Steps</h4>
        <ol class="steps-list">
          <li v-for="(step, index) in helpData.remediationSteps" :key="index">
            {{ step }}
          </li>
        </ol>
      </div>

      <!-- Estimated Effort & Automation -->
      <div class="help-meta">
        <div v-if="helpData.estimatedEffort" class="meta-item">
          <span class="meta-label">Estimated Effort:</span>
          <span class="meta-value">{{ helpData.estimatedEffort }}</span>
        </div>
        <div v-if="helpData.automated" class="meta-item">
          <span class="automated-badge">Automated Fix Available</span>
        </div>
      </div>

      <!-- References -->
      <div v-if="helpData.references && helpData.references.length > 0" class="help-section">
        <h4>References</h4>
        <ul class="references-list">
          <li v-for="(ref, index) in helpData.references" :key="index">
            <a :href="ref" target="_blank" class="reference-link">{{ ref }}</a>
          </li>
        </ul>
      </div>

      <!-- Knowledge Base Articles -->
      <div v-if="helpData.knowledgeBaseArticles && helpData.knowledgeBaseArticles.length > 0" class="help-section">
        <h4>Related Documentation</h4>
        <div class="articles-list">
          <div
            v-for="(article, index) in helpData.knowledgeBaseArticles"
            :key="index"
            class="article-item"
          >
            <a :href="article.url" target="_blank" class="article-link">
              <h5>{{ article.title }}</h5>
              <p v-if="article.description">{{ article.description }}</p>
            </a>
          </div>
        </div>
      </div>

      <!-- Similar Findings -->
      <div v-if="helpData.similarFindings && helpData.similarFindings.length > 0" class="help-section">
        <h4>Similar Resolved Findings</h4>
        <div class="similar-findings-list">
          <div
            v-for="finding in helpData.similarFindings"
            :key="finding.id"
            class="similar-finding-item"
          >
            <div class="finding-title">{{ finding.title }}</div>
            <div class="finding-meta">
              <span :class="`status-badge status-${finding.status}`">
                {{ finding.status }}
              </span>
              <span v-if="finding.resolutionDate" class="resolution-date">
                Resolved: {{ formatDate(finding.resolutionDate) }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { X } from 'lucide-vue-next';

const props = defineProps<{
  findingId: string;
}>();

const emit = defineEmits<{
  close: [];
}>();

const loading = ref(true);
const error = ref<string | null>(null);
const helpData = ref<any>(null);

const loadHelp = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/unified-findings/remediation-help/${props.findingId}`);
    helpData.value = {
      ...response.data,
      similarFindings: response.data.similarFindings?.map((f: any) => ({
        ...f,
        resolutionDate: f.resolutionDate ? new Date(f.resolutionDate) : null,
      })) || [],
    };
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load remediation help';
    console.error('Failed to load remediation help:', err);
  } finally {
    loading.value = false;
  }
};

const formatDate = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

onMounted(() => {
  loadHelp();
});
</script>

<style scoped>
.remediation-help {
  background: rgba(15, 20, 25, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  max-width: 800px;
  width: 90%;
  max-height: 80vh;
  overflow-y: auto;
  margin: 0 auto;
  position: relative;
  z-index: 1001;
}

.help-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.help-header h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.close-btn {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.close-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.loading,
.error {
  padding: 24px;
  text-align: center;
  color: #ffffff;
}

.error {
  color: #fc8181;
}

.help-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.help-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.help-section h4 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.steps-list,
.references-list {
  margin: 0;
  padding-left: 24px;
  color: #ffffff;
  line-height: 1.8;
}

.steps-list li,
.references-list li {
  margin-bottom: 8px;
}

.reference-link {
  color: #4facfe;
  text-decoration: none;
}

.reference-link:hover {
  text-decoration: underline;
}

.help-meta {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.meta-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.meta-value {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 500;
}

.automated-badge {
  padding: 6px 12px;
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.articles-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.article-item {
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.article-item:hover {
  border-color: rgba(79, 172, 254, 0.5);
  background: rgba(0, 0, 0, 0.4);
}

.article-link {
  text-decoration: none;
  color: inherit;
}

.article-link h5 {
  font-size: 1rem;
  font-weight: 600;
  color: #4facfe;
  margin: 0 0 8px 0;
}

.article-link p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.6;
}

.similar-findings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.similar-finding-item {
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.finding-title {
  font-size: 0.9rem;
  color: #ffffff;
  margin-bottom: 8px;
  font-weight: 500;
}

.finding-meta {
  display: flex;
  gap: 12px;
  align-items: center;
  flex-wrap: wrap;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 500;
}

.status-badge.status-resolved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.status-badge.status-risk-accepted {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.resolution-date {
  font-size: 0.75rem;
  color: #a0aec0;
}
</style>

