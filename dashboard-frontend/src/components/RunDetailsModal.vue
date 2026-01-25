<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>Run Details</h2>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div v-if="loading" class="loading-state">
              <p>Loading run details...</p>
            </div>
            <div v-else-if="error" class="error-state">
              <p>{{ error }}</p>
            </div>
            <div v-else-if="run" class="run-details">
              <!-- Run Summary -->
              <div class="run-summary">
                <div class="summary-item">
                  <span class="summary-label">Battery:</span>
                  <span class="summary-value">{{ run.batteryName }}</span>
                </div>
                <div class="summary-item">
                  <span class="summary-label">Status:</span>
                  <span class="summary-value" :class="`status-${run.status}`">
                    {{ run.status }}
                  </span>
                </div>
                <div class="summary-item">
                  <span class="summary-label">Score:</span>
                  <span class="summary-value" :class="getScoreClass(run.score)">
                    {{ run.score }}%
                  </span>
                </div>
                <div class="summary-item">
                  <span class="summary-label">Tests:</span>
                  <span class="summary-value">
                    {{ run.passedTests }}/{{ run.totalTests }} passed
                  </span>
                </div>
                <div class="summary-item">
                  <span class="summary-label">Timestamp:</span>
                  <span class="summary-value">{{ formatTime(run.timestamp) }}</span>
                </div>
              </div>

              <!-- Hierarchy Tree -->
              <div class="hierarchy-tree">
                <h3 class="tree-title">Test Hierarchy</h3>
                <div class="tree-container">
                  <!-- Battery Level -->
                  <div class="tree-node battery-node">
                    <div class="node-header" @click="toggleNode('battery')">
                      <ChevronRight v-if="!expandedNodes.battery" class="chevron" />
                      <ChevronDown v-else class="chevron" />
                      <Battery class="node-icon" />
                      <span class="node-name">{{ run.batteryName }}</span>
                      <span class="node-badge">{{ run.harnesses.length }} harness{{ run.harnesses.length !== 1 ? 'es' : '' }}</span>
                    </div>
                    <div v-if="expandedNodes.battery" class="node-children">
                      <!-- Harness Level -->
                      <div
                        v-for="harness in run.harnesses"
                        :key="harness.id"
                        class="tree-node harness-node"
                      >
                        <div class="node-header" @click="toggleNode(`harness-${harness.id}`)">
                          <ChevronRight v-if="!expandedNodes[`harness-${harness.id}`]" class="chevron" />
                          <ChevronDown v-else class="chevron" />
                          <Layers class="node-icon" />
                          <span class="node-name">{{ harness.name }}</span>
                          <span class="node-badge">{{ harness.suites.length }} suite{{ harness.suites.length !== 1 ? 's' : '' }}</span>
                        </div>
                        <div v-if="expandedNodes[`harness-${harness.id}`]" class="node-children">
                          <!-- Suite Level -->
                          <div
                            v-for="suite in harness.suites"
                            :key="suite.id"
                            class="tree-node suite-node"
                          >
                            <div class="node-header" @click="toggleNode(`suite-${suite.id}`)">
                              <ChevronRight v-if="!expandedNodes[`suite-${suite.id}`]" class="chevron" />
                              <ChevronDown v-else class="chevron" />
                              <List class="node-icon" />
                              <span class="node-name">{{ suite.name }}</span>
                              <span class="node-badge">{{ suite.tests.length }} test{{ suite.tests.length !== 1 ? 's' : '' }}</span>
                            </div>
                            <div v-if="expandedNodes[`suite-${suite.id}`]" class="node-children">
                              <!-- Test Level -->
                              <div
                                v-for="test in suite.tests"
                                :key="test.id"
                                class="tree-node test-node"
                              >
                                <div class="node-header">
                                  <TestTube class="node-icon" />
                                  <span class="node-name">{{ test.testConfigurationName }}</span>
                                  <span class="node-status" :class="`status-${test.status}`">
                                    {{ test.status }}
                                  </span>
                                </div>
                                <div v-if="test.error" class="test-error">
                                  <AlertCircle class="error-icon" />
                                  <span>{{ test.error }}</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button @click="close" class="btn-secondary">Close</button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { Teleport, Transition } from 'vue';
import { X, Battery, Layers, List, TestTube, ChevronRight, ChevronDown, AlertCircle } from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  isOpen: boolean;
  runId: string | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
}>();

const loading = ref(false);
const error = ref<string | null>(null);
const run = ref<any>(null);
const expandedNodes = ref<Record<string, boolean>>({
  battery: true,
});

const loadRunDetails = async () => {
  if (!props.runId) return;
  
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get(`/api/v1/runs/${props.runId}`);
    run.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load run details';
    console.error('Error loading run details:', err);
  } finally {
    loading.value = false;
  }
};

const toggleNode = (nodeId: string) => {
  expandedNodes.value[nodeId] = !expandedNodes.value[nodeId];
};

const getScoreClass = (score: number) => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatTime = (date: Date | string): string => {
  if (!date) return 'Unknown';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const close = () => {
  emit('close');
  run.value = null;
  expandedNodes.value = { battery: true };
  error.value = null;
};

watch(() => props.isOpen, (newValue) => {
  if (newValue && props.runId) {
    loadRunDetails();
  }
});

watch(() => props.runId, (newValue) => {
  if (props.isOpen && newValue) {
    loadRunDetails();
  }
});
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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
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
  border-radius: 6px;
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
  flex: 1;
  padding: 24px;
  overflow-y: auto;
}

.run-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.summary-label {
  font-size: 0.75rem;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.summary-value {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}

.status-completed,
.status-passed {
  color: #48bb78;
}

.status-failed {
  color: #f56565;
}

.status-running {
  color: #ed8936;
}

.score-high {
  color: #48bb78;
}

.score-medium {
  color: #ed8936;
}

.score-low {
  color: #f56565;
}

.hierarchy-tree {
  margin-top: 24px;
}

.tree-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.tree-container {
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  padding: 16px;
}

.tree-node {
  margin-bottom: 8px;
}

.node-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(79, 172, 254, 0.05);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.node-header:hover {
  background: rgba(79, 172, 254, 0.1);
}

.chevron {
  width: 16px;
  height: 16px;
  color: #a0aec0;
  flex-shrink: 0;
}

.node-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
  flex-shrink: 0;
}

.node-name {
  flex: 1;
  color: #ffffff;
  font-weight: 500;
}

.node-badge {
  font-size: 0.75rem;
  padding: 2px 8px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  color: #4facfe;
}

.node-status {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 12px;
  font-weight: 600;
}

.node-children {
  margin-left: 32px;
  margin-top: 4px;
  border-left: 2px solid rgba(79, 172, 254, 0.2);
  padding-left: 16px;
}

.test-node .node-header {
  cursor: default;
}

.test-error {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
  padding: 8px 12px;
  background: rgba(245, 101, 101, 0.1);
  border-left: 3px solid #f56565;
  border-radius: 4px;
  color: #f56565;
  font-size: 0.875rem;
}

.error-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.loading-state,
.error-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.error-state {
  color: #fc8181;
}

.modal-footer {
  padding: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  justify-content: flex-end;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
