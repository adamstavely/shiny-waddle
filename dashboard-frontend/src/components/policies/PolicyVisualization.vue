<template>
  <div class="policy-visualization">
    <div class="visualization-header">
      <h3>Policy Structure Visualization</h3>
      <div class="view-controls">
        <button
          @click="viewMode = 'structure'"
          :class="['view-btn', { active: viewMode === 'structure' }]"
        >
          Structure
        </button>
        <button
          @click="viewMode = 'flow'"
          :class="['view-btn', { active: viewMode === 'flow' }]"
        >
          Evaluation Flow
        </button>
        <button
          @click="viewMode = 'conflicts'"
          :class="['view-btn', { active: viewMode === 'conflicts' }]"
        >
          Conflicts
        </button>
      </div>
    </div>

    <div class="visualization-container">
      <div ref="networkContainer" class="network-container"></div>
      
      <div v-if="!hasData" class="empty-state">
        <p>No policy data to visualize. Create or load a policy to see its structure.</p>
      </div>
    </div>

    <div class="visualization-legend">
      <div class="legend-item">
        <div class="legend-color" style="background: #667eea;"></div>
        <span>Policy Root</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background: #10b981;"></div>
        <span>Rule/Condition</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background: #f59e0b;"></div>
        <span>Condition</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background: #ef4444;"></div>
        <span>Conflict</span>
      </div>
      <div class="legend-item">
        <div class="legend-color" style="background: #8b5cf6;"></div>
        <span>Logical Operator</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue';
import { Network, Options } from 'vis-network';
import { DataSet } from 'vis-data';
import 'vis-network/styles/vis-network.min.css';

interface PolicyData {
  type: 'rbac' | 'abac';
  name: string;
  rules?: any[];
  conditions?: any[];
  effect?: 'allow' | 'deny';
  priority?: number;
}

const props = defineProps<{
  policy: PolicyData | null;
  conflicts?: Array<{ id: string; message: string }>;
}>();

const networkContainer = ref<HTMLElement | null>(null);
const network = ref<Network | null>(null);
const viewMode = ref<'structure' | 'flow' | 'conflicts'>('structure');
const hasData = ref(false);

const createNetwork = (nodes: any[], edges: any[]) => {
  if (!networkContainer.value) return;

  const data = {
    nodes: new DataSet(nodes),
    edges: new DataSet(edges),
  };

  const options: Options = {
    nodes: {
      shape: 'box',
      font: {
        size: 14,
        face: 'Arial',
      },
      borderWidth: 2,
      shadow: true,
    },
    edges: {
      arrows: {
        to: {
          enabled: true,
          scaleFactor: 0.8,
        },
      },
      smooth: {
        type: 'cubicBezier',
        forceDirection: 'vertical',
        roundness: 0.4,
      },
      color: {
        color: '#9ca3af',
        highlight: '#667eea',
      },
    },
    layout: {
      hierarchical: {
        direction: 'UD',
        sortMethod: 'directed',
        levelSeparation: 100,
        nodeSpacing: 150,
        treeSpacing: 200,
      },
    },
    physics: {
      enabled: false, // Disable physics for hierarchical layout
    },
    interaction: {
      dragNodes: true,
      dragView: true,
      zoomView: true,
    },
  };

  if (network.value) {
    network.value.destroy();
  }

  network.value = new Network(networkContainer.value, data, options);
  hasData.value = nodes.length > 0;
};

const generateStructureView = () => {
  if (!props.policy) {
    hasData.value = false;
    return;
  }

  const nodes: any[] = [];
  const edges: any[] = [];

  // Root node
  nodes.push({
    id: 'root',
    label: props.policy.name || 'Policy',
    color: {
      background: '#667eea',
      border: '#4c51bf',
    },
    font: { color: '#ffffff', size: 16, bold: true },
    level: 0,
  });

  if (props.policy.type === 'rbac' && props.policy.rules) {
    // RBAC Rules
    props.policy.rules.forEach((rule, index) => {
      const ruleId = `rule-${index}`;
      nodes.push({
        id: ruleId,
        label: `${rule.id || `Rule ${index + 1}`}\n${rule.effect === 'allow' ? '✓ Allow' : '✗ Deny'}`,
        color: {
          background: '#10b981',
          border: '#059669',
        },
        font: { color: '#ffffff' },
        level: 1,
      });
      edges.push({ from: 'root', to: ruleId });

      // Conditions
      if (rule.conditions) {
        Object.entries(rule.conditions).forEach(([key, value], condIndex) => {
          const condId = `${ruleId}-cond-${condIndex}`;
          nodes.push({
            id: condId,
            label: `${key}\n= ${Array.isArray(value) ? `[${value.join(', ')}]` : value}`,
            color: {
              background: '#f59e0b',
              border: '#d97706',
            },
            font: { color: '#ffffff' },
            level: 2,
          });
          edges.push({ from: ruleId, to: condId });
        });
      }
    });
  } else if (props.policy.type === 'abac' && props.policy.conditions) {
    // ABAC Conditions
    props.policy.conditions.forEach((condition, index) => {
      const condId = `cond-${index}`;
      const logicalOp = condition.logicalOperator || (index === 0 ? '' : 'AND');
      
      nodes.push({
        id: condId,
        label: `${condition.attribute}\n${condition.operator} ${condition.value}${logicalOp ? `\n[${logicalOp}]` : ''}`,
        color: {
          background: '#10b981',
          border: '#059669',
        },
        font: { color: '#ffffff' },
        level: 1,
      });
      edges.push({ from: 'root', to: condId });

      // Show logical operator connections
      if (index > 0 && condition.logicalOperator) {
        const prevCondId = `cond-${index - 1}`;
        nodes.push({
          id: `op-${index}`,
          label: condition.logicalOperator,
          color: {
            background: '#8b5cf6',
            border: '#7c3aed',
          },
          font: { color: '#ffffff', bold: true },
          shape: 'diamond',
          level: 1.5,
        });
        edges.push({ from: prevCondId, to: `op-${index}`, style: 'dashed' });
        edges.push({ from: `op-${index}`, to: condId, style: 'dashed' });
      }
    });
  }

  createNetwork(nodes, edges);
};

const generateFlowView = () => {
  if (!props.policy) {
    hasData.value = false;
    return;
  }

  const nodes: any[] = [];
  const edges: any[] = [];

  // Start node
  nodes.push({
    id: 'start',
    label: 'Policy Evaluation\nStart',
    color: { background: '#667eea', border: '#4c51bf' },
    font: { color: '#ffffff' },
    level: 0,
  });

  if (props.policy.type === 'rbac' && props.policy.rules) {
    // Evaluation flow for RBAC
    props.policy.rules.forEach((rule, index) => {
      const ruleId = `rule-${index}`;
      nodes.push({
        id: ruleId,
        label: `Check Rule\n${rule.id || `Rule ${index + 1}`}`,
        color: { background: '#10b981', border: '#059669' },
        font: { color: '#ffffff' },
        level: index + 1,
      });

      if (index === 0) {
        edges.push({ from: 'start', to: ruleId });
      } else {
        edges.push({ from: `rule-${index - 1}`, to: ruleId, label: 'Next' });
      }

      // Decision node
      const decisionId = `decision-${index}`;
      nodes.push({
        id: decisionId,
        label: rule.effect === 'allow' ? '✓ Allow' : '✗ Deny',
        color: {
          background: rule.effect === 'allow' ? '#10b981' : '#ef4444',
          border: rule.effect === 'allow' ? '#059669' : '#dc2626',
        },
        font: { color: '#ffffff' },
        shape: 'diamond',
        level: index + 1.5,
      });
      edges.push({ from: ruleId, to: decisionId });
    });

    // End node
    const endId = 'end';
    nodes.push({
      id: endId,
      label: 'Evaluation\nComplete',
      color: { background: '#6b7280', border: '#4b5563' },
      font: { color: '#ffffff' },
      level: props.policy.rules.length + 1,
    });
    edges.push({ from: `decision-${props.policy.rules.length - 1}`, to: endId });
  } else if (props.policy.type === 'abac' && props.policy.conditions) {
    // Evaluation flow for ABAC
    props.policy.conditions.forEach((condition, index) => {
      const condId = `cond-${index}`;
      nodes.push({
        id: condId,
        label: `Evaluate\n${condition.attribute}\n${condition.operator}`,
        color: { background: '#10b981', border: '#059669' },
        font: { color: '#ffffff' },
        level: index + 1,
      });

      if (index === 0) {
        edges.push({ from: 'start', to: condId });
      } else {
        const logicalOp = condition.logicalOperator || 'AND';
        nodes.push({
          id: `op-${index}`,
          label: logicalOp,
          color: { background: '#8b5cf6', border: '#7c3aed' },
          font: { color: '#ffffff' },
          shape: 'diamond',
          level: index + 0.5,
        });
        edges.push({ from: `cond-${index - 1}`, to: `op-${index}` });
        edges.push({ from: `op-${index}`, to: condId });
      }
    });

    // Final decision
    const decisionId = 'final-decision';
    nodes.push({
      id: decisionId,
      label: props.policy.effect === 'allow' ? '✓ Allow' : '✗ Deny',
      color: {
        background: props.policy.effect === 'allow' ? '#10b981' : '#ef4444',
        border: props.policy.effect === 'allow' ? '#059669' : '#dc2626',
      },
      font: { color: '#ffffff' },
      shape: 'diamond',
      level: props.policy.conditions.length + 1,
    });
    edges.push({ from: `cond-${props.policy.conditions.length - 1}`, to: decisionId });
  }

  createNetwork(nodes, edges);
};

const generateConflictsView = () => {
  if (!props.policy || !props.conflicts || props.conflicts.length === 0) {
    hasData.value = false;
    return;
  }

  const nodes: any[] = [];
  const edges: any[] = [];

  // Root
  nodes.push({
    id: 'root',
    label: props.policy.name || 'Policy',
    color: { background: '#667eea', border: '#4c51bf' },
    font: { color: '#ffffff' },
    level: 0,
  });

  // Conflict nodes
  props.conflicts.forEach((conflict, index) => {
    const conflictId = `conflict-${index}`;
    nodes.push({
      id: conflictId,
      label: `Conflict ${index + 1}\n${conflict.message}`,
      color: { background: '#ef4444', border: '#dc2626' },
      font: { color: '#ffffff' },
      level: 1,
    });
    edges.push({ from: 'root', to: conflictId, color: { color: '#ef4444' } });
  });

  createNetwork(nodes, edges);
};

watch([() => props.policy, viewMode], () => {
  nextTick(() => {
    if (viewMode.value === 'structure') {
      generateStructureView();
    } else if (viewMode.value === 'flow') {
      generateFlowView();
    } else if (viewMode.value === 'conflicts') {
      generateConflictsView();
    }
  });
}, { immediate: true });

onMounted(() => {
  if (props.policy) {
    generateStructureView();
  }
});

onBeforeUnmount(() => {
  if (network.value) {
    network.value.destroy();
  }
});
</script>

<style scoped>
.policy-visualization {
  display: flex;
  flex-direction: column;
  height: 100%;
  gap: 1rem;
}

.visualization-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.visualization-header h3 {
  margin: 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.view-controls {
  display: flex;
  gap: var(--spacing-sm);
}

.view-btn {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
  cursor: pointer;
  transition: var(--transition-all);
}

.view-btn:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.view-btn.active {
  background: var(--gradient-primary);
  color: white;
  border-color: var(--color-primary);
}

.visualization-container {
  flex: 1;
  min-height: 400px;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  background: var(--color-bg-card);
  position: relative;
}

.network-container {
  width: 100%;
  height: 100%;
  min-height: 400px;
}

.empty-state {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
  color: var(--color-text-muted);
}

.visualization-legend {
  display: flex;
  gap: var(--spacing-lg);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
  flex-wrap: wrap;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.legend-color {
  width: 20px;
  height: 20px;
  border-radius: var(--border-radius-xs);
  border: var(--border-width-thin) solid var(--border-color-primary);
}
</style>
