<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content remediation-modal" @click.stop>
          <div class="modal-header">
            <div class="header-content">
              <h2>Remediation Guide</h2>
              <div class="gap-info">
                <span class="severity-badge" :class="`badge-${gap.severity}`">
                  {{ gap.severity.toUpperCase() }}
                </span>
                <span class="gap-type">{{ gap.type }}</span>
              </div>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="remediation-content">
              <!-- Gap Overview -->
              <div class="gap-overview">
                <h3>{{ gap.title }}</h3>
                <p class="gap-description">{{ gap.description }}</p>
                <div class="gap-meta">
                  <div class="meta-item">
                    <span class="meta-label">Estimated Effort:</span>
                    <span class="meta-value">{{ gap.estimatedEffort }}</span>
                  </div>
                  <div class="meta-item">
                    <span class="meta-label">Priority:</span>
                    <span class="meta-value">{{ gap.priority }}/10</span>
                  </div>
                </div>
              </div>

              <!-- Remediation Steps -->
              <div class="remediation-steps-section">
                <h3>Remediation Steps</h3>
                <div class="steps-list">
                  <div
                    v-for="(step, index) in gap.remediation.steps"
                    :key="index"
                    class="step-item"
                    :class="{ completed: isStepCompleted(index) }"
                  >
                    <div class="step-header">
                      <div class="step-number">{{ step.order }}</div>
                      <div class="step-content">
                        <h4>{{ step.action }}</h4>
                        <p>{{ step.description }}</p>
                      </div>
                      <div class="step-checkbox">
                        <input
                          type="checkbox"
                          :checked="isStepCompleted(index)"
                          @change="toggleStep(index)"
                        />
                      </div>
                    </div>
                    <div class="step-details">
                      <div class="expected-outcome">
                        <strong>Expected Outcome:</strong> {{ step.expectedOutcome }}
                      </div>
                      <div v-if="step.verification" class="verification">
                        <strong>Verification:</strong> {{ step.verification }}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Additional Info -->
              <div class="additional-info">
                <div class="info-section">
                  <h4>Estimated Time</h4>
                  <p>{{ gap.remediation.estimatedTime }}</p>
                </div>
                <div v-if="gap.remediation.requiredPermissions.length > 0" class="info-section">
                  <h4>Required Permissions</h4>
                  <div class="permissions-list">
                    <span
                      v-for="perm in gap.remediation.requiredPermissions"
                      :key="perm"
                      class="permission-badge"
                    >
                      {{ perm }}
                    </span>
                  </div>
                </div>
                <div v-if="gap.remediation.links.length > 0" class="info-section">
                  <h4>Related Links</h4>
                  <ul class="links-list">
                    <li v-for="link in gap.remediation.links" :key="link.url">
                      <a :href="link.url" target="_blank" :class="`link-${link.type}`">
                        {{ link.label }}
                        <ExternalLink class="link-icon" />
                      </a>
                    </li>
                  </ul>
                </div>
                <div v-if="gap.remediation.codeExamples && gap.remediation.codeExamples.length > 0" class="info-section">
                  <h4>Code Examples</h4>
                  <div
                    v-for="(example, index) in gap.remediation.codeExamples"
                    :key="index"
                    class="code-example"
                  >
                    <div class="code-header">
                      <span class="code-language">{{ example.language }}</span>
                      <span class="code-description">{{ example.description }}</span>
                    </div>
                    <pre class="code-content"><code>{{ example.code }}</code></pre>
                  </div>
                </div>
              </div>

              <!-- Progress Tracking -->
              <div class="progress-section">
                <h4>Progress</h4>
                <div class="progress-bar">
                  <div
                    class="progress-fill"
                    :style="{ width: `${progressPercentage}%` }"
                  ></div>
                </div>
                <p class="progress-text">
                  {{ completedSteps }} of {{ gap.remediation.steps.length }} steps completed
                </p>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button @click="$emit('close')" class="btn-secondary">
              Close
            </button>
            <button @click="saveProgress" class="btn-primary">
              Save Progress
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { X, ExternalLink } from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  show: boolean;
  gap: {
    id: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    type: string;
    title: string;
    description: string;
    estimatedEffort: string;
    priority: number;
    remediation: {
      steps: Array<{
        order: number;
        action: string;
        description: string;
        expectedOutcome: string;
        verification?: string;
      }>;
      estimatedTime: string;
      requiredPermissions: string[];
      links: Array<{
        label: string;
        url: string;
        type: 'internal' | 'external' | 'documentation';
      }>;
      codeExamples?: Array<{
        language: string;
        code: string;
        description: string;
      }>;
    };
  };
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
}>();

const completedSteps = ref<number[]>([]);

const progressPercentage = computed(() => {
  if (props.gap.remediation.steps.length === 0) return 0;
  return Math.round((completedSteps.value.length / props.gap.remediation.steps.length) * 100);
});

const isStepCompleted = (index: number): boolean => {
  return completedSteps.value.includes(index);
};

const toggleStep = async (index: number) => {
  if (completedSteps.value.includes(index)) {
    completedSteps.value = completedSteps.value.filter(i => i !== index);
  } else {
    completedSteps.value.push(index);
  }

  // Save progress to backend
  await saveProgress();
};

const saveProgress = async () => {
  try {
    for (const stepIndex of completedSteps.value) {
      await axios.post(`/api/policies/gaps/${props.gap.id}/progress`, {
        step: stepIndex,
        completed: true,
      });
    }
  } catch (error) {
    console.error('Failed to save progress', error);
  }
};
</script>

<style scoped>
.remediation-modal {
  max-width: 900px;
  width: 90vw;
  max-height: 90vh;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.header-content h2 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-xl);
  font-weight: 600;
}

.gap-info {
  display: flex;
  gap: var(--spacing-sm);
  align-items: center;
}

.severity-badge {
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

.gap-type {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  text-transform: uppercase;
}

.modal-body {
  padding: var(--spacing-lg);
  overflow-y: auto;
  max-height: calc(90vh - 200px);
}

.remediation-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.gap-overview {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.gap-overview h3 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-lg);
  font-weight: 600;
}

.gap-description {
  margin: 0 0 var(--spacing-md) 0;
  color: var(--color-text-secondary);
  line-height: 1.6;
}

.gap-meta {
  display: flex;
  gap: var(--spacing-lg);
}

.meta-item {
  display: flex;
  gap: var(--spacing-xs);
}

.meta-label {
  color: var(--color-text-secondary);
  font-weight: 500;
}

.meta-value {
  font-weight: 600;
}

.remediation-steps-section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.steps-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.step-item {
  padding: var(--spacing-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  background: var(--color-bg-secondary);
  transition: var(--transition-all);
}

.step-item.completed {
  background: rgba(var(--color-success-rgb), 0.1);
  border-color: var(--color-success);
}

.step-header {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-md);
}

.step-number {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-primary);
  color: white;
  border-radius: 50%;
  font-weight: 600;
  flex-shrink: 0;
}

.step-item.completed .step-number {
  background: var(--color-success);
}

.step-content {
  flex: 1;
}

.step-content h4 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.step-content p {
  margin: 0;
  color: var(--color-text-secondary);
  line-height: 1.6;
}

.step-checkbox input {
  width: 20px;
  height: 20px;
  cursor: pointer;
}

.step-details {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  font-size: var(--font-size-sm);
}

.expected-outcome,
.verification {
  margin-bottom: var(--spacing-xs);
  color: var(--color-text-secondary);
}

.additional-info {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-md);
}

.info-section {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.info-section h4 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-sm);
  font-weight: 600;
}

.permissions-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.permission-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
}

.links-list {
  margin: 0;
  padding-left: var(--spacing-md);
  list-style: none;
}

.links-list li {
  margin-bottom: var(--spacing-xs);
}

.links-list a {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-xs);
  color: var(--color-primary);
  text-decoration: none;
}

.links-list a:hover {
  text-decoration: underline;
}

.link-icon {
  width: 14px;
  height: 14px;
}

.code-example {
  margin-top: var(--spacing-sm);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  overflow: hidden;
}

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.code-language {
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: var(--font-size-xs);
  font-weight: 600;
}

.code-description {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.code-content {
  margin: 0;
  padding: var(--spacing-md);
  background: var(--color-bg-primary);
  overflow-x: auto;
}

.code-content code {
  font-family: 'Monaco', 'Courier New', monospace;
  font-size: var(--font-size-xs);
  line-height: 1.6;
}

.progress-section {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.progress-section h4 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-sm);
  font-weight: 600;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  overflow: hidden;
  margin-bottom: var(--spacing-xs);
}

.progress-fill {
  height: 100%;
  background: var(--color-success);
  transition: width 0.3s ease;
}

.progress-text {
  margin: 0;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  padding: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}
</style>
