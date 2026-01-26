<template>
  <div class="agent-tests-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Agent Access Control Tests</h1>
          <p class="page-description">
            Test and validate agent access control patterns, OAuth flows, and audit trails for AI agents and autonomous systems.
          </p>
        </div>
      </div>
    </div>

    <!-- Test Type Tabs -->
    <div class="tabs-container">
      <div class="tabs">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          :class="['tab', { 'tab-active': activeTab === tab.id }]"
          @click="activeTab = tab.id"
        >
          <component :is="tab.icon" class="tab-icon" />
          {{ tab.label }}
        </button>
      </div>
    </div>

    <!-- Tab Content -->
    <div class="tab-content">
      <!-- Delegated Access Tab -->
      <div v-if="activeTab === 'delegated'" class="test-section">
        <h2 class="section-title">Delegated Access Tests</h2>
        <p class="section-description">
          Test agents that act on behalf of users with delegated permissions.
        </p>
        <DelegatedAccessTestForm @test-complete="handleTestComplete" />
      </div>

      <!-- Direct Access Tab -->
      <div v-if="activeTab === 'direct'" class="test-section">
        <h2 class="section-title">Direct Access Tests</h2>
        <p class="section-description">
          Test autonomous agents with direct service-to-service access.
        </p>
        <DirectAccessTestForm @test-complete="handleTestComplete" />
      </div>

      <!-- Multi-Service Tab -->
      <div v-if="activeTab === 'multi-service'" class="test-section">
        <h2 class="section-title">Multi-Service Access Tests</h2>
        <p class="section-description">
          Test agent access across multiple services and validate consistency.
        </p>
        <MultiServiceTestForm @test-complete="handleTestComplete" />
      </div>

      <!-- Dynamic Access Tab -->
      <div v-if="activeTab === 'dynamic'" class="test-section">
        <h2 class="section-title">Dynamic Access Tests</h2>
        <p class="section-description">
          Test context-dependent and just-in-time (JIT) access scenarios.
        </p>
        <DynamicAccessTestForm @test-complete="handleTestComplete" />
      </div>

      <!-- Audit Trail Tab -->
      <div v-if="activeTab === 'audit'" class="test-section">
        <h2 class="section-title">Audit Trail Validation</h2>
        <p class="section-description">
          Validate audit trail completeness, integrity, and cross-service correlation.
        </p>
        <AuditTrailTestForm @test-complete="handleTestComplete" />
      </div>
    </div>

    <!-- Test Results Modal -->
    <BaseModal
      :isOpen="showResultsModal"
      title="Test Results"
      @update:isOpen="showResultsModal = $event"
      @close="closeResultsModal"
    >
      <TestResultsDisplay :result="testResult" />
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  UserCheck,
  Bot,
  Network,
  Zap,
  FileSearch,
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import BaseModal from '../components/BaseModal.vue';
import DelegatedAccessTestForm from './agent-tests/DelegatedAccessTestForm.vue';
import DirectAccessTestForm from './agent-tests/DirectAccessTestForm.vue';
import MultiServiceTestForm from './agent-tests/MultiServiceTestForm.vue';
import DynamicAccessTestForm from './agent-tests/DynamicAccessTestForm.vue';
import AuditTrailTestForm from './agent-tests/AuditTrailTestForm.vue';
import TestResultsDisplay from './agent-tests/TestResultsDisplay.vue';

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Agent Tests' },
]);

const activeTab = ref('delegated');

const tabs = [
  { id: 'delegated', label: 'Delegated Access', icon: UserCheck },
  { id: 'direct', label: 'Direct Access', icon: Bot },
  { id: 'multi-service', label: 'Multi-Service', icon: Network },
  { id: 'dynamic', label: 'Dynamic Access', icon: Zap },
  { id: 'audit', label: 'Audit Trail', icon: FileSearch },
];

const showResultsModal = ref(false);
const testResult = ref<any>(null);

const handleTestComplete = (result: any) => {
  testResult.value = result;
  showResultsModal.value = true;
};

const closeResultsModal = () => {
  showResultsModal.value = false;
  testResult.value = null;
};
</script>

<style scoped>
.agent-tests-page {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 600;
  margin-bottom: var(--spacing-xs);
  color: var(--color-text-primary);
}

.page-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  line-height: 1.6;
}

.tabs-container {
  margin-bottom: var(--spacing-xl);
  border-bottom: 2px solid var(--border-color-primary);
}

.tabs {
  display: flex;
  gap: var(--spacing-xs);
}

.tab {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-md) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--color-text-secondary);
  cursor: pointer;
  font-size: var(--font-size-base);
  font-weight: 500;
  transition: var(--transition-all);
  margin-bottom: -2px;
}

.tab:hover {
  color: var(--color-primary);
  background: var(--color-info-bg);
}

.tab-active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  min-height: 400px;
}

.test-section {
  animation: fadeIn 0.2s ease-in;
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: 600;
  margin-bottom: var(--spacing-xs);
  color: var(--color-text-primary);
}

.section-description {
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xl);
  font-size: var(--font-size-base);
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
