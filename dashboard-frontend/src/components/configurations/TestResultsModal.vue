<template>
  <div v-if="show" class="modal-overlay" @click.self="close">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Test Results</h2>
        <button @click="close" class="close-btn">&times;</button>
      </div>
      
      <div class="modal-body">
        <div v-if="error" class="error-section">
          <h3 class="error-title">Error</h3>
          <div class="error-message" v-html="formatErrorMessage(error)"></div>
          <div v-if="hasConfigurationError(error)" class="error-suggestions">
            <p class="suggestion-title">Suggestions:</p>
            <ul>
              <li>Check that all required configuration fields are filled</li>
              <li>Verify the configuration type matches the test being run</li>
              <li>Edit the configuration to add missing fields</li>
            </ul>
          </div>
        </div>
        
        <div v-else-if="results" class="results-container">
          <!-- Overview Section -->
          <div class="result-section">
            <h3 class="section-title">Overview</h3>
            <div class="status-badge" :class="statusClass">
              {{ statusText }}
            </div>
            <div v-if="results.coveragePercentage !== undefined" class="metric">
              <span class="metric-label">Coverage:</span>
              <span class="metric-value">{{ results.coveragePercentage.toFixed(2) }}%</span>
            </div>
            <div v-if="results.validationResults" class="validation-info">
              <div v-if="results.validationResults.minRLSCoverage !== undefined">
                <span>Min RLS Coverage Required: {{ results.validationResults.minRLSCoverage }}%</span>
                <span :class="results.validationResults.minRLSCoverageMet ? 'pass' : 'fail'">
                  {{ results.validationResults.minRLSCoverageMet ? '✓ Met' : '✗ Not Met' }}
                </span>
              </div>
              <div v-if="results.validationResults.minCLSCoverage !== undefined">
                <span>Min CLS Coverage Required: {{ results.validationResults.minCLSCoverage }}%</span>
                <span :class="results.validationResults.minCLSCoverageMet ? 'pass' : 'fail'">
                  {{ results.validationResults.minCLSCoverageMet ? '✓ Met' : '✗ Not Met' }}
                </span>
              </div>
            </div>
          </div>

          <!-- Workflow Validation Section -->
          <div v-if="results.workflowValidation" class="result-section">
            <h3 class="section-title">Workflow Validation</h3>
            <div class="workflow-details">
              <div><strong>Required Steps:</strong> {{ results.workflowValidation.requiredSteps?.join(', ') || 'N/A' }}</div>
              <div><strong>Completed Steps:</strong> {{ results.workflowValidation.completedSteps?.join(', ') || 'N/A' }}</div>
              <div>
                <strong>All Required Completed:</strong>
                <span :class="results.workflowValidation.allRequiredStepsCompleted ? 'pass' : 'fail'">
                  {{ results.workflowValidation.allRequiredStepsCompleted ? 'Yes' : 'No' }}
                </span>
              </div>
              <div v-if="results.workflowValidation.missingSteps?.length > 0">
                <strong>Missing Steps:</strong>
                <span class="fail">{{ results.workflowValidation.missingSteps.join(', ') }}</span>
              </div>
            </div>
          </div>

          <!-- Custom Validations Section -->
          <div v-if="results.customValidationResults && results.customValidationResults.length > 0" class="result-section">
            <h3 class="section-title">Custom Validations</h3>
            <div v-for="(val, index) in results.customValidationResults" :key="index" class="validation-item">
              <div class="validation-header">
                <span class="validation-name">{{ val.name }}</span>
                <span :class="val.passed ? 'pass-badge' : 'fail-badge'">
                  {{ val.passed ? 'PASSED' : 'FAILED' }}
                </span>
              </div>
              <div v-if="val.description" class="validation-description">{{ val.description }}</div>
            </div>
          </div>

          <!-- Custom Checks Section -->
          <div v-if="results.customCheckResults && results.customCheckResults.length > 0" class="result-section">
            <h3 class="section-title">Custom Checks</h3>
            <div v-for="(check, index) in results.customCheckResults" :key="index" class="validation-item">
              <div class="validation-header">
                <span class="validation-name">{{ check.name }}</span>
                <span :class="check.passed ? 'pass-badge' : 'fail-badge'">
                  {{ check.passed ? 'PASSED' : 'FAILED' }}
                </span>
              </div>
              <div v-if="check.description" class="validation-description">{{ check.description }}</div>
            </div>
          </div>

          <!-- Custom Rules Section -->
          <div v-if="results.customRuleResults && results.customRuleResults.length > 0" class="result-section">
            <h3 class="section-title">Custom Rules</h3>
            <div v-for="(rule, index) in results.customRuleResults" :key="index" class="validation-item">
              <div class="validation-header">
                <span class="validation-name">{{ rule.source }} → {{ rule.target }}</span>
                <span :class="rule.passed ? 'pass-badge' : 'fail-badge'">
                  {{ rule.passed ? 'PASSED' : 'FAILED' }}
                </span>
              </div>
              <div v-if="rule.description" class="validation-description">{{ rule.description }}</div>
            </div>
          </div>

          <!-- Full Results Section (Collapsible) -->
          <div class="result-section">
            <details class="full-results">
              <summary class="section-title">Full Results (JSON)</summary>
              <div class="json-container">
                <pre>{{ formattedJson }}</pre>
                <button @click="copyToClipboard" class="copy-btn">Copy to Clipboard</button>
              </div>
            </details>
          </div>
        </div>
      </div>
      
      <div class="modal-footer">
        <button @click="close" class="btn-primary">Close</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';

const props = defineProps<{
  show: boolean;
  results?: any;
  error?: string;
  configName?: string;
}>();

const emit = defineEmits<{
  close: [];
}>();

const statusClass = computed(() => {
  if (props.error) return 'error';
  if (props.results?.passed === false) return 'failed';
  if (props.results?.passed === true) return 'passed';
  return 'unknown';
});

const statusText = computed(() => {
  if (props.error) return 'ERROR';
  if (props.results?.passed === false) return 'FAILED';
  if (props.results?.passed === true) return 'PASSED';
  return 'UNKNOWN';
});

const formattedJson = computed(() => {
  return JSON.stringify(props.results, null, 2);
});

const close = () => {
  emit('close');
};

const copyToClipboard = async () => {
  try {
    await navigator.clipboard.writeText(formattedJson.value);
    alert('Copied to clipboard!');
  } catch (err) {
    console.error('Failed to copy to clipboard:', err);
  }
};

const formatErrorMessage = (error: string): string => {
  // Format error message with line breaks and highlighting
  return error
    .split('\n')
    .map(line => {
      // Highlight field names and suggestions
      if (line.includes('field:') || line.includes('Suggestion:')) {
        return `<strong>${line}</strong>`;
      }
      return line;
    })
    .join('<br>');
};

const hasConfigurationError = (error: string): boolean => {
  return error.includes('missing required fields') || 
         error.includes('Configuration') || 
         error.includes('validation');
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: #1a1f2e;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  max-width: 800px;
  width: 100%;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  color: #ffffff;
  font-size: 1.5rem;
}

.close-btn {
  background: none;
  border: none;
  color: #a0aec0;
  font-size: 2rem;
  cursor: pointer;
  padding: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  transition: all 0.2s;
}

.close-btn:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #ffffff;
}

.modal-body {
  padding: 1.5rem;
  overflow-y: auto;
  flex: 1;
}

.error-section {
  padding: 1rem;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
}

.error-title {
  color: #fc8181;
  margin: 0 0 0.5rem 0;
}

.error-message {
  color: #ffffff;
  margin: 0;
  white-space: pre-wrap;
  line-height: 1.6;
}

.error-suggestions {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(252, 129, 129, 0.2);
}

.suggestion-title {
  color: #fc8181;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
}

.error-suggestions ul {
  margin: 0.5rem 0 0 0;
  padding-left: 1.5rem;
  color: #a0aec0;
}

.error-suggestions li {
  margin-bottom: 0.25rem;
}

.results-container {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.result-section {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
}

.section-title {
  margin: 0 0 1rem 0;
  color: #ffffff;
  font-size: 1.125rem;
  font-weight: 600;
}

.status-badge {
  display: inline-block;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  font-weight: 600;
  margin-bottom: 1rem;
}

.status-badge.passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.status-badge.failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-badge.error {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-badge.unknown {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.metric {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.metric-label {
  color: #a0aec0;
}

.metric-value {
  color: #ffffff;
  font-weight: 600;
}

.validation-info {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: 1rem;
}

.validation-info > div {
  display: flex;
  justify-content: space-between;
  color: #a0aec0;
}

.pass {
  color: #48bb78;
}

.fail {
  color: #fc8181;
}

.workflow-details {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  color: #a0aec0;
}

.validation-item {
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 6px;
  margin-bottom: 0.5rem;
}

.validation-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.validation-name {
  color: #ffffff;
  font-weight: 500;
}

.pass-badge,
.fail-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.pass-badge {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.fail-badge {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.validation-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.full-results {
  margin-top: 1rem;
}

.full-results summary {
  cursor: pointer;
  user-select: none;
}

.json-container {
  margin-top: 1rem;
  position: relative;
}

.json-container pre {
  background: rgba(0, 0, 0, 0.3);
  padding: 1rem;
  border-radius: 6px;
  overflow-x: auto;
  color: #a0aec0;
  font-size: 0.875rem;
  line-height: 1.5;
  margin: 0;
}

.copy-btn {
  position: absolute;
  top: 0.5rem;
  right: 0.5rem;
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.copy-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.modal-footer {
  padding: 1.5rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  justify-content: flex-end;
}

.btn-primary {
  padding: 0.75rem 1.5rem;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-primary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}
</style>

