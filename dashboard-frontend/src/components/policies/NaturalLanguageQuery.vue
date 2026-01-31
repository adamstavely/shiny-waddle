<template>
  <div class="natural-language-query">
    <div class="query-header">
      <h3>Ask Questions About Policies</h3>
      <p class="subtitle">Ask questions in natural language and get AI-powered answers</p>
    </div>

    <div class="query-history" v-if="history.length > 0">
      <div
        v-for="(item, index) in history"
        :key="index"
        class="history-item"
      >
        <div class="query-bubble">
          <strong>You:</strong> {{ item.query }}
        </div>
        <div class="answer-bubble">
          <strong>AI:</strong> {{ item.answer }}
          <div v-if="item.confidence < 80" class="confidence-warning">
            <AlertCircle class="icon" />
            Low confidence ({{ item.confidence }}%)
          </div>
        </div>
      </div>
    </div>

    <div class="query-input-section">
      <div class="input-container">
        <input
          v-model="currentQuery"
          @keyup.enter="submitQuery"
          type="text"
          placeholder="Ask a question about policies, compliance, or gaps..."
          class="query-input"
          :disabled="loading"
        />
        <button
          @click="submitQuery"
          :disabled="loading || !currentQuery.trim()"
          class="btn-submit"
        >
          <Send v-if="!loading" class="icon" />
          <div v-else class="loading-spinner-small"></div>
        </button>
      </div>

      <div class="suggestions" v-if="suggestions.length > 0 && !currentQuery">
        <p class="suggestions-label">Suggestions:</p>
        <div class="suggestions-list">
          <button
            v-for="(suggestion, index) in suggestions"
            :key="index"
            @click="currentQuery = suggestion"
            class="suggestion-btn"
          >
            {{ suggestion }}
          </button>
        </div>
      </div>
    </div>

    <div v-if="error" class="error-message">
      <AlertTriangle class="icon" />
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { Send, AlertCircle, AlertTriangle } from 'lucide-vue-next';
import axios from 'axios';

interface QueryHistoryItem {
  query: string;
  answer: string;
  confidence: number;
  timestamp: Date;
}

const currentQuery = ref('');
const history = ref<QueryHistoryItem[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

const suggestions = [
  'What is our overall compliance score?',
  'Which policies have the most gaps?',
  'What are the critical security issues?',
  'How many policies were modified this month?',
  'What actions are needed to improve compliance?',
];

const submitQuery = async () => {
  if (!currentQuery.value.trim() || loading.value) return;

  const query = currentQuery.value.trim();
  
  // Validate query length
  if (query.length > 500) {
    error.value = 'Query is too long. Please keep it under 500 characters.';
    return;
  }

  loading.value = true;
  error.value = null;

  try {
    const response = await axios.post('/api/policies/query', {
      query,
    }, {
      timeout: 20000, // 20 second timeout
    });

    if (!response.data || !response.data.answer) {
      throw new Error('Invalid response format');
    }

    history.value.unshift({
      query,
      answer: response.data.answer,
      confidence: response.data.confidence || 85,
      timestamp: new Date(),
    });

    // Keep only last 10 queries
    if (history.value.length > 10) {
      history.value = history.value.slice(0, 10);
    }

    currentQuery.value = '';
  } catch (err: any) {
    if (err.code === 'ECONNABORTED') {
      error.value = 'Request timed out. The query is taking longer than expected. Please try a simpler question.';
    } else if (err.response?.status === 400) {
      error.value = err.response?.data?.message || 'Invalid query. Please check your question and try again.';
    } else if (err.response?.status === 503) {
      error.value = 'AI service is temporarily unavailable. Please try again later.';
    } else {
      error.value = err.response?.data?.message || err.message || 'Failed to get answer. Please try again.';
    }
    console.error('Error submitting query:', err);
  } finally {
    loading.value = false;
  }
};
</script>

<style scoped>
.natural-language-query {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-lg);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.query-header h3 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.subtitle {
  margin: 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.query-history {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  max-height: 400px;
  overflow-y: auto;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
}

.history-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.query-bubble,
.answer-bubble {
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  line-height: 1.6;
}

.query-bubble {
  background: var(--color-primary);
  color: white;
  align-self: flex-end;
  max-width: 80%;
}

.answer-bubble {
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  align-self: flex-start;
  max-width: 80%;
}

.confidence-warning {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  margin-top: var(--spacing-sm);
  padding: var(--spacing-xs) var(--spacing-sm);
  background: rgba(var(--color-warning-rgb), 0.1);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  color: var(--color-warning);
}

.query-input-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.input-container {
  display: flex;
  gap: var(--spacing-sm);
}

.query-input {
  flex: 1;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.query-input:focus {
  outline: none;
  border-color: var(--color-primary);
}

.query-input:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-submit {
  padding: var(--spacing-md);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 48px;
  transition: var(--transition-all);
}

.btn-submit:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.btn-submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.icon {
  width: 20px;
  height: 20px;
}

.loading-spinner-small {
  width: 20px;
  height: 20px;
  border: 2px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

.suggestions {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.suggestions-label {
  margin: 0;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}

.suggestions-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.suggestion-btn {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
  transition: var(--transition-all);
}

.suggestion-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--color-primary);
}

.error-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: rgba(var(--color-error-rgb), 0.1);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
  color: var(--color-error);
}

.error-message .icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}
</style>
