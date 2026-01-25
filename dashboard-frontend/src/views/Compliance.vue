<template>
  <div class="compliance-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Compliance Management</h1>
          <p class="page-description">Manage compliance frameworks, assess controls, and track compliance status</p>
        </div>
        <div class="header-actions">
          <button @click="showFrameworkModal = true" class="btn-secondary">
            <Shield class="btn-icon" />
            Select Framework
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="loading-state">
      <Loader class="loading-icon" />
      <p>Loading compliance frameworks...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <h3>Error</h3>
      <p>{{ error }}</p>
      <button @click="loadFrameworks" class="btn-secondary">
        Retry
      </button>
    </div>

    <!-- Framework Selection -->
    <div v-else-if="!selectedFramework" class="framework-selection">
      <div class="empty-state">
        <Shield class="empty-icon" />
        <h3>Select a Compliance Framework</h3>
        <p>Choose a framework to begin compliance assessment and tracking</p>
        <button @click="showFrameworkModal = true" class="btn-primary">
          <Shield class="btn-icon" />
          Select Framework
        </button>
      </div>
    </div>

    <!-- Compliance Dashboard -->
    <div v-else class="compliance-dashboard">
      <!-- Framework Header -->
      <div v-if="frameworkMetadata" class="framework-header">
        <div class="framework-info">
          <h2>{{ frameworkMetadata.name }} {{ frameworkMetadata.version || '' }}</h2>
          <p>{{ frameworkMetadata.description }}</p>
          <span class="framework-badge">{{ frameworkMetadata.controlCount }} controls</span>
        </div>
        <div class="framework-actions">
          <button @click="loadGapAnalysis" class="btn-secondary" :disabled="loadingGaps">
            <AlertTriangle class="btn-icon" />
            {{ loadingGaps ? 'Analyzing...' : 'Gap Analysis' }}
          </button>
          <button @click="createAssessment" class="btn-secondary" :disabled="creatingAssessment">
            <FileCheck class="btn-icon" />
            {{ creatingAssessment ? 'Creating...' : 'New Assessment' }}
          </button>
          <button @click="createRoadmap" class="btn-primary" :disabled="creatingRoadmap">
            <Target class="btn-icon" />
            {{ creatingRoadmap ? 'Creating...' : 'Create Roadmap' }}
          </button>
        </div>
      </div>

      <!-- Current Assessment Summary -->
      <div v-if="currentAssessment" class="assessment-summary">
        <div class="summary-header">
          <h3>Current Assessment: {{ currentAssessment.name }}</h3>
          <span class="assessment-date">Assessed: {{ formatDate(currentAssessment.assessedAt) }}</span>
        </div>
        <div class="summary-metrics">
          <div class="metric-card">
            <div class="metric-value" :class="getComplianceClass(currentAssessment.summary.compliancePercentage)">
              {{ currentAssessment.summary.compliancePercentage.toFixed(1) }}%
            </div>
            <div class="metric-label">Compliance</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">{{ currentAssessment.summary.compliant }}</div>
            <div class="metric-label">Compliant</div>
          </div>
          <div class="metric-card">
            <div class="metric-value warning">{{ currentAssessment.summary.nonCompliant }}</div>
            <div class="metric-label">Non-Compliant</div>
          </div>
          <div class="metric-card">
            <div class="metric-value info">{{ currentAssessment.summary.partiallyCompliant }}</div>
            <div class="metric-label">Partial</div>
          </div>
          <div class="metric-card">
            <div class="metric-value">{{ currentAssessment.summary.notAssessed }}</div>
            <div class="metric-label">Not Assessed</div>
          </div>
        </div>
        <div v-if="currentAssessment.summary.criticalGaps.length > 0" class="gaps-alert">
          <AlertTriangle class="alert-icon" />
          <div>
            <strong>{{ currentAssessment.summary.criticalGaps.length }} Critical Gap(s)</strong>
            <p>{{ currentAssessment.summary.criticalGaps.join(', ') }}</p>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="activeTab = tab.id"
          class="tab-button"
          :class="{ active: activeTab === tab.id }"
        >
          <component :is="tab.icon" class="tab-icon" />
          {{ tab.label }}
          <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
        </button>
      </div>

      <!-- Controls Tab -->
      <div v-if="activeTab === 'controls'" class="tab-content">
        <div class="controls-filters">
          <input
            v-model="controlSearch"
            type="text"
            placeholder="Search controls..."
            class="search-input"
          />
          <select v-model="selectedFamily" class="filter-select">
            <option value="">All Families</option>
            <option v-for="family in controlFamilies" :key="family" :value="family">
              {{ family }}
            </option>
          </select>
          <select v-model="selectedStatus" class="filter-select">
            <option value="">All Statuses</option>
            <option value="compliant">Compliant</option>
            <option value="non_compliant">Non-Compliant</option>
            <option value="partially_compliant">Partially Compliant</option>
            <option value="not_assessed">Not Assessed</option>
          </select>
        </div>

        <div class="controls-list">
          <div
            v-for="control in filteredControls"
            :key="control.id"
            class="control-card"
            @click="viewControl(control)"
          >
            <div class="control-header">
              <div>
                <h4 class="control-id">{{ control.controlId }}</h4>
                <h5 class="control-title">{{ control.title }}</h5>
              </div>
              <span class="priority-badge" :class="`priority-${control.priority}`">
                {{ control.priority }}
              </span>
            </div>
            <p class="control-description">{{ control.description }}</p>
            <div class="control-footer">
              <span class="control-family">{{ control.family }}</span>
              <span
                v-if="getControlStatus(control.controlId)"
                class="status-badge"
                :class="`status-${getControlStatus(control.controlId)}`"
              >
                {{ formatStatus(getControlStatus(control.controlId)) }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Gaps Tab -->
      <div v-if="activeTab === 'gaps'" class="tab-content">
        <div v-if="loadingGaps" class="loading-state">
          <Loader class="loading-icon" />
          <p>Analyzing compliance gaps...</p>
        </div>
        <div v-else-if="gaps.length === 0" class="empty-state">
          <CheckCircle2 class="empty-icon" />
          <h3>No Compliance Gaps Found</h3>
          <p>All controls are compliant or not applicable</p>
        </div>
        <div v-else class="gaps-list">
          <div
            v-for="gap in gaps"
            :key="gap.controlId"
            class="gap-card"
            :class="`priority-${gap.priority}`"
          >
            <div class="gap-header">
              <div>
                <h4 class="gap-control-id">{{ gap.controlId }}</h4>
                <h5 class="gap-title">{{ gap.controlTitle }}</h5>
              </div>
              <span class="priority-badge" :class="`priority-${gap.priority}`">
                {{ gap.priority }}
              </span>
            </div>
            <div class="gap-status">
              <span class="status-badge" :class="`status-${gap.status}`">
                {{ formatStatus(gap.status) }}
              </span>
              <span v-if="gap.estimatedEffort" class="effort-badge">
                Effort: {{ gap.estimatedEffort }}
              </span>
            </div>
            <div v-if="gap.violations.length > 0" class="gap-violations">
              <strong>{{ gap.violations.length }} Related Violation(s)</strong>
            </div>
            <div class="gap-remediation">
              <strong>Remediation Steps:</strong>
              <ul>
                <li v-for="(step, index) in gap.remediationSteps" :key="index">{{ step }}</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <!-- Roadmaps Tab -->
      <div v-if="activeTab === 'roadmaps'" class="tab-content">
        <div v-if="roadmaps.length === 0" class="empty-state">
          <Target class="empty-icon" />
          <h3>No Roadmaps Created</h3>
          <p>Create a remediation roadmap to track compliance improvement</p>
          <button @click="createRoadmap" class="btn-primary">
            <Target class="btn-icon" />
            Create Roadmap
          </button>
        </div>
        <div v-else class="roadmaps-list">
          <div
            v-for="roadmap in roadmaps"
            :key="roadmap.id"
            class="roadmap-card"
            @click="viewRoadmap(roadmap.id)"
          >
            <div class="roadmap-header">
              <h4>{{ roadmap.name }}</h4>
              <span v-if="roadmap.targetComplianceDate" class="target-date">
                Target: {{ formatDate(roadmap.targetComplianceDate) }}
              </span>
            </div>
            <p v-if="roadmap.description" class="roadmap-description">{{ roadmap.description }}</p>
            <div class="roadmap-stats">
              <span>{{ roadmap.gaps.length }} Gaps</span>
              <span>{{ roadmap.milestones.length }} Milestones</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Framework Selection Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showFrameworkModal" class="modal-overlay" @click="showFrameworkModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Select Compliance Framework</h2>
              <button @click="showFrameworkModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="frameworks-grid">
                <div
                  v-for="framework in availableFrameworks"
                  :key="framework"
                  class="framework-card"
                  @click="selectFramework(framework)"
                >
                  <Shield class="framework-icon" />
                  <h4>{{ getFrameworkName(framework) }}</h4>
                  <p>{{ getFrameworkDescription(framework) }}</p>
                  <span class="framework-control-count">
                    {{ getFrameworkControlCount(framework) }} controls
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Control Detail Modal with Evidence -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showControlModal && selectedControl" class="modal-overlay" @click="closeControlModal">
          <div class="modal-content large" @click.stop>
            <div class="modal-header">
              <div>
                <h2>{{ selectedControl.controlId }}</h2>
                <p class="control-subtitle">{{ selectedControl.title }}</p>
              </div>
              <button @click="closeControlModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="control-detail-section">
                <h3>Description</h3>
                <p>{{ selectedControl.description }}</p>
              </div>
              <div class="control-detail-section">
                <h3>Mapping Status</h3>
                <div v-if="getControlStatus(selectedControl.controlId)" class="status-display">
                  <span class="status-badge" :class="`status-${getControlStatus(selectedControl.controlId)}`">
                    {{ formatStatus(getControlStatus(selectedControl.controlId)) }}
                  </span>
                </div>
                <p v-else class="no-status">No mapping found for this control</p>
              </div>
              <div class="control-detail-section" v-if="getMappingForControl(selectedControl.controlId)">
                <EvidenceManager
                  :mapping-id="getMappingForControl(selectedControl.controlId)!.id"
                  :evidence="getMappingForControl(selectedControl.controlId)!.evidence || []"
                  @evidence-added="handleEvidenceAdded"
                  @evidence-deleted="handleEvidenceDeleted"
                />
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Shield,
  AlertTriangle,
  FileCheck,
  Target,
  X,
  CheckCircle2,
  Loader,
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import EvidenceManager from '../components/compliance/EvidenceManager.vue';
import {
  ComplianceFramework,
  type ComplianceControl,
  type ComplianceMapping,
  type ComplianceAssessment,
  type ComplianceGap,
  type ComplianceRoadmap,
} from '../types/compliance';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', path: '/' },
  { label: 'Compliance', path: '/compliance' },
];

const selectedFramework = ref<ComplianceFramework | null>(null);
const availableFrameworks = ref<ComplianceFramework[]>([]);
const frameworkMetadata = ref<any>(null);
const controls = ref<ComplianceControl[]>([]);
const mappings = ref<ComplianceMapping[]>([]);
const currentAssessment = ref<ComplianceAssessment | null>(null);
const gaps = ref<ComplianceGap[]>([]);
const roadmaps = ref<ComplianceRoadmap[]>([]);
const activeTab = ref<'controls' | 'gaps' | 'roadmaps'>('controls');
const showFrameworkModal = ref(false);
const loadingGaps = ref(false);
const creatingAssessment = ref(false);
const creatingRoadmap = ref(false);
const controlSearch = ref('');
const selectedFamily = ref('');
const selectedStatus = ref('');
const loading = ref(false);
const error = ref<string | null>(null);

const tabs = computed(() => [
  { id: 'controls', label: 'Controls', icon: Shield, badge: controls.value.length },
  { id: 'gaps', label: 'Gaps', icon: AlertTriangle, badge: gaps.value.length },
  { id: 'roadmaps', label: 'Roadmaps', icon: Target, badge: roadmaps.value.length },
]);

const controlFamilies = computed(() => {
  const families = new Set(controls.value.map(c => c.family).filter(Boolean));
  return Array.from(families).sort();
});

const filteredControls = computed(() => {
  let filtered = controls.value;

  if (controlSearch.value) {
    const search = controlSearch.value.toLowerCase();
    filtered = filtered.filter(
      c =>
        c.controlId.toLowerCase().includes(search) ||
        c.title.toLowerCase().includes(search) ||
        c.description.toLowerCase().includes(search)
    );
  }

  if (selectedFamily.value) {
    filtered = filtered.filter(c => c.family === selectedFamily.value);
  }

  if (selectedStatus.value) {
    filtered = filtered.filter(c => getControlStatus(c.controlId) === selectedStatus.value);
  }

  return filtered;
});

const loadFrameworks = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await fetch('/api/v1/compliance/frameworks');
    if (!response.ok) {
      const errorText = await response.text();
      console.error('API Error:', response.status, errorText);
      error.value = `Failed to load frameworks (${response.status}): ${errorText || 'Unknown error'}`;
      return;
    }
    const data = await response.json();
    if (Array.isArray(data) && data.length > 0) {
      availableFrameworks.value = data;
    } else {
      error.value = 'No compliance frameworks available';
    }
  } catch (err: any) {
    console.error('Error loading frameworks:', err);
    error.value = `Failed to load frameworks: ${err.message || 'Network error. Please ensure the backend server is running.'}`;
  } finally {
    loading.value = false;
  }
};

const selectFramework = async (framework: ComplianceFramework) => {
  selectedFramework.value = framework;
  showFrameworkModal.value = false;
  
  // Load framework metadata
  try {
    const response = await fetch(`/api/v1/compliance/frameworks/${framework}`);
    if (response.ok) {
      const data = await response.json();
      frameworkMetadata.value = data;
    } else {
      console.error('Failed to load framework metadata:', response.status, response.statusText);
      // Set default metadata if API fails
      frameworkMetadata.value = {
        name: getFrameworkName(framework),
        version: framework.includes('rev') ? framework.split('_').pop()?.toUpperCase() : '',
        description: getFrameworkDescription(framework),
        controlCount: getFrameworkControlCount(framework),
      };
    }
  } catch (error) {
    console.error('Error loading framework metadata:', error);
    // Set default metadata on error
    frameworkMetadata.value = {
      name: getFrameworkName(framework),
      version: framework.includes('rev') ? framework.split('_').pop()?.toUpperCase() : '',
      description: getFrameworkDescription(framework),
      controlCount: getFrameworkControlCount(framework),
    };
  }

  // Load controls
  await loadControls();
  
  // Load mappings
  await loadMappings();
  
  // Load current assessment
  await loadCurrentAssessment();
  
  // Load roadmaps
  await loadRoadmaps();
};

const loadControls = async () => {
  if (!selectedFramework.value) return;
  
  try {
    const response = await fetch(`/api/v1/compliance/frameworks/${selectedFramework.value}/controls`);
    if (response.ok) {
      const text = await response.text();
      if (text && text.trim()) {
        try {
          controls.value = JSON.parse(text);
        } catch (parseError) {
          console.error('Error parsing controls JSON:', parseError);
          controls.value = [];
        }
      } else {
        controls.value = [];
      }
    } else {
      controls.value = [];
    }
  } catch (error) {
    console.error('Error loading controls:', error);
    controls.value = [];
  }
};

const loadMappings = async () => {
  if (!selectedFramework.value) return;
  
  try {
    const response = await fetch(`/api/v1/compliance/mappings?framework=${selectedFramework.value}`);
    if (response.ok) {
      const text = await response.text();
      if (text && text.trim()) {
        try {
          mappings.value = JSON.parse(text);
        } catch (parseError) {
          console.error('Error parsing mappings JSON:', parseError);
          mappings.value = [];
        }
      } else {
        mappings.value = [];
      }
    } else {
      mappings.value = [];
    }
  } catch (error) {
    console.error('Error loading mappings:', error);
    mappings.value = [];
  }
};

const loadCurrentAssessment = async () => {
  if (!selectedFramework.value) return;
  
  try {
    const response = await fetch(`/api/v1/compliance/assessments?framework=${selectedFramework.value}&latest=true`);
    if (response.ok) {
      const text = await response.text();
      if (text && text.trim()) {
        try {
          const data = JSON.parse(text);
          currentAssessment.value = Array.isArray(data) && data.length > 0 ? data[0] : null;
        } catch (parseError) {
          console.error('Error parsing assessment JSON:', parseError);
          currentAssessment.value = null;
        }
      } else {
        currentAssessment.value = null;
      }
    } else {
      currentAssessment.value = null;
    }
  } catch (error) {
    console.error('Error loading current assessment:', error);
    currentAssessment.value = null;
  }
};

const loadGapAnalysis = async () => {
  if (!selectedFramework.value) return;
  
  loadingGaps.value = true;
  try {
    const response = await fetch(`/api/v1/compliance/frameworks/${selectedFramework.value}/gaps`);
    if (response.ok) {
      gaps.value = await response.json();
      activeTab.value = 'gaps';
    }
  } catch (error) {
    console.error('Error loading gap analysis:', error);
  } finally {
    loadingGaps.value = false;
  }
};

const loadRoadmaps = async () => {
  if (!selectedFramework.value) return;
  
  try {
    const response = await fetch(`/api/v1/compliance/roadmaps?framework=${selectedFramework.value}`);
    if (response.ok) {
      const text = await response.text();
      if (text && text.trim()) {
        try {
          roadmaps.value = JSON.parse(text);
        } catch (parseError) {
          console.error('Error parsing roadmaps JSON:', parseError);
          roadmaps.value = [];
        }
      } else {
        roadmaps.value = [];
      }
    } else {
      roadmaps.value = [];
    }
  } catch (error) {
    console.error('Error loading roadmaps:', error);
    roadmaps.value = [];
  }
};

const createAssessment = async () => {
  if (!selectedFramework.value) return;
  
  creatingAssessment.value = true;
  try {
    // Create a new assessment from current mappings
    const response = await fetch('/api/v1/compliance/assessments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        framework: selectedFramework.value,
        name: `Assessment - ${new Date().toLocaleDateString()}`,
        mappings: mappings.value.map(m => ({
          framework: m.framework,
          controlId: m.controlId,
          status: m.status,
          violations: m.violations,
          policies: m.policies,
          tests: m.tests,
          lastAssessed: m.lastAssessed,
          assessedBy: m.assessedBy,
          notes: m.notes,
        })),
      }),
    });
    
    if (response.ok) {
      await loadCurrentAssessment();
      alert('Assessment created successfully');
    }
  } catch (error) {
    console.error('Error creating assessment:', error);
    alert('Failed to create assessment');
  } finally {
    creatingAssessment.value = false;
  }
};

const createRoadmap = async () => {
  if (!selectedFramework.value) return;
  
  creatingRoadmap.value = true;
  try {
    const response = await fetch(`/api/v1/compliance/frameworks/${selectedFramework.value}/roadmaps`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `Roadmap - ${new Date().toLocaleDateString()}`,
        description: 'Remediation roadmap for compliance gaps',
      }),
    });
    
    if (response.ok) {
      await loadRoadmaps();
      activeTab.value = 'roadmaps';
      alert('Roadmap created successfully');
    }
  } catch (error) {
    console.error('Error creating roadmap:', error);
    alert('Failed to create roadmap');
  } finally {
    creatingRoadmap.value = false;
  }
};

const getControlStatus = (controlId: string): string | null => {
  const mapping = mappings.value.find(m => m.controlId === controlId);
  return mapping?.status || null;
};

const getMappingForControl = (controlId: string): ComplianceMapping | null => {
  return mappings.value.find(m => m.controlId === controlId) || null;
};

const formatStatus = (status: string): string => {
  const statusMap: Record<string, string> = {
    compliant: 'Compliant',
    non_compliant: 'Non-Compliant',
    partially_compliant: 'Partially Compliant',
    not_applicable: 'Not Applicable',
    not_assessed: 'Not Assessed',
  };
  return statusMap[status] || status;
};

const formatDate = (date: Date | string): string => {
  return new Date(date).toLocaleDateString();
};

const getComplianceClass = (percentage: number): string => {
  if (percentage >= 90) return 'success';
  if (percentage >= 70) return 'warning';
  return 'error';
};

const getFrameworkName = (framework: ComplianceFramework): string => {
  const names: Record<ComplianceFramework, string> = {
    [ComplianceFramework.NIST_800_53_REV_4]: 'NIST 800-53',
    [ComplianceFramework.NIST_800_53_REV_5]: 'NIST 800-53',
    [ComplianceFramework.SOC_2]: 'SOC 2',
    [ComplianceFramework.PCI_DSS]: 'PCI-DSS',
    [ComplianceFramework.HIPAA]: 'HIPAA',
    [ComplianceFramework.GDPR]: 'GDPR',
    [ComplianceFramework.ISO_27001]: 'ISO 27001',
    [ComplianceFramework.NIST_CSF]: 'NIST CSF',
    [ComplianceFramework.OWASP_ASVS]: 'OWASP ASVS',
  };
  return names[framework] || framework;
};

const getFrameworkDescription = (framework: ComplianceFramework): string => {
  const descriptions: Record<ComplianceFramework, string> = {
    [ComplianceFramework.NIST_800_53_REV_4]: 'Revision 4 - Security and Privacy Controls',
    [ComplianceFramework.NIST_800_53_REV_5]: 'Revision 5 - Security and Privacy Controls',
    [ComplianceFramework.SOC_2]: 'System and Organization Controls 2',
    [ComplianceFramework.PCI_DSS]: 'Payment Card Industry Data Security Standard',
    [ComplianceFramework.HIPAA]: 'Health Insurance Portability and Accountability Act',
    [ComplianceFramework.GDPR]: 'General Data Protection Regulation',
    [ComplianceFramework.ISO_27001]: 'Information Security Management System',
    [ComplianceFramework.NIST_CSF]: 'NIST Cybersecurity Framework',
    [ComplianceFramework.OWASP_ASVS]: 'OWASP Application Security Verification Standard',
  };
  return descriptions[framework] || '';
};

const getFrameworkControlCount = (framework: ComplianceFramework): number => {
  // This would ideally come from the API
  if (framework === ComplianceFramework.NIST_800_53_REV_4) return 50;
  if (framework === ComplianceFramework.NIST_800_53_REV_5) return 60;
  return 0;
};

const selectedControl = ref<ComplianceControl | null>(null);
const showControlModal = ref(false);

const viewControl = (control: ComplianceControl) => {
  selectedControl.value = control;
  showControlModal.value = true;
};

const closeControlModal = () => {
  showControlModal.value = false;
  selectedControl.value = null;
};

const handleEvidenceAdded = () => {
  loadMappings();
};

const handleEvidenceDeleted = () => {
  loadMappings();
};

const viewRoadmap = (roadmapId: string) => {
  router.push(`/compliance/roadmaps/${roadmapId}`);
};

onMounted(() => {
  loadFrameworks();
});
</script>

<style scoped>
.compliance-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.framework-selection {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.framework-header {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.framework-info h2 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.framework-info p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-md) 0;
}

.framework-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  margin-top: var(--spacing-sm);
}

.framework-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.assessment-summary {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
}

.summary-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.summary-header h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.assessment-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.summary-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
}

.metric-card {
  text-align: center;
  padding: var(--spacing-lg);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.metric-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  margin-bottom: var(--spacing-sm);
  color: var(--color-text-primary);
}

.metric-value.success {
  color: var(--color-success);
}

.metric-value.warning {
  color: var(--color-warning);
}

.metric-value.error {
  color: var(--color-error);
}

.metric-value.info {
  color: var(--color-info);
}

.metric-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.gaps-alert {
  display: flex;
  gap: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-warning-bg);
  border-left: 4px solid var(--color-warning);
  border-radius: var(--border-radius-lg);
  color: var(--color-warning);
  margin-bottom: var(--spacing-md);
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: none;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  cursor: pointer;
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
  transition: var(--transition-all);
}

.tab-button:hover {
  color: var(--color-primary);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.controls-filters {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-select {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-base);
  color: var(--color-text-primary);
  transition: var(--transition-all);
}

.search-input::placeholder {
  color: var(--color-text-secondary);
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-select {
  min-width: 150px;
}

.search-input:focus,
.filter-select:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.controls-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.control-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.control-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.control-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.control-id {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-xs) 0;
}

.control-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  margin: 0;
  color: var(--color-text-primary);
}

.priority-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.priority-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.priority-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.priority-moderate {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.priority-low {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.control-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.control-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.control-family {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.status-compliant {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-non_compliant {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-partially_compliant {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-not_assessed {
  background: var(--color-bg-overlay-light);
  color: var(--color-text-muted);
}

.gaps-list {
  display: grid;
  gap: 1rem;
}

.gap-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left: 4px solid;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
}

.gap-card.priority-critical {
  border-left-color: var(--color-error);
}

.gap-card.priority-high {
  border-left-color: var(--color-warning);
}

.gap-card.priority-moderate {
  border-left-color: var(--color-warning);
}

.gap-card.priority-low {
  border-left-color: var(--color-success);
}

.gap-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.gap-control-id {
  font-size: var(--font-size-sm);
  color: #666;
  margin: 0 0 0.25rem 0;
}

.gap-title {
  font-size: var(--font-size-lg);
  font-weight: 600;
  margin: 0;
}

.gap-status {
  display: flex;
  gap: 1rem;
  align-items: center;
  margin-bottom: 1rem;
}

.effort-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
}

.gap-violations {
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-sm);
  background: var(--color-warning-bg);
  border-radius: var(--border-radius-xs);
}

.gap-remediation ul {
  margin: 0.5rem 0 0 1.5rem;
  padding: 0;
}

.gap-remediation li {
  margin-bottom: 0.5rem;
  font-size: var(--font-size-sm);
}

.roadmaps-list {
  display: grid;
  gap: 1rem;
}

.roadmap-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.roadmap-card:hover {
  box-shadow: var(--shadow-md);
}

.roadmap-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xs);
}

.roadmap-header h4 {
  margin: 0;
  font-size: var(--font-size-lg);
}

.target-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.roadmap-description {
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.roadmap-stats {
  display: flex;
  gap: var(--spacing-lg);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  backdrop-filter: blur(4px);
  z-index: var(--z-index-modal);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border-radius: var(--border-radius-md);
  max-width: 800px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.5rem;
}

.frameworks-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: var(--spacing-lg);
  padding: var(--spacing-lg);
}

.framework-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  text-align: center;
  cursor: pointer;
  transition: var(--transition-all);
}

.framework-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.framework-icon {
  width: 3rem;
  height: 3rem;
  margin: 0 auto var(--spacing-md);
  color: var(--color-primary);
}

.framework-card h4 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.framework-card p {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-sm) 0;
}

.framework-control-count {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto var(--spacing-md);
  color: var(--color-text-muted);
}

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.loading-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto var(--spacing-lg);
  animation: spin 1s linear infinite;
  color: var(--color-primary);
}

.error-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-xl);
  margin: 0 auto;
  max-width: 600px;
}

.error-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto var(--spacing-lg);
  color: var(--color-error);
  opacity: 0.5;
}

.error-state h3 {
  margin: 0 0 var(--spacing-sm) 0;
  color: var(--color-error);
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
}

.error-state p {
  margin: 0 0 var(--spacing-lg) 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  line-height: 1.5;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  font-size: var(--font-size-base);
  border: none;
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-primary);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.btn-secondary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.modal-content.large {
  max-width: 1000px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.gap-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left: 4px solid;
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.roadmap-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.roadmap-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.roadmap-description {
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.target-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.roadmap-stats {
  display: flex;
  gap: var(--spacing-lg);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.gap-control-id {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-xs) 0;
}

.gap-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  margin: 0;
  color: var(--color-text-primary);
}

.priority-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.priority-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.priority-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.priority-moderate {
  background: var(--color-warning-bg);
  color: var(--color-warning-light);
}

.priority-low {
  background: var(--color-success-bg);
  color: var(--color-success-light);
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.status-compliant {
  background: var(--color-success-bg);
  color: var(--color-success-light);
}

.status-non_compliant {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-partially_compliant {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.status-not_assessed {
  background: var(--border-color-muted);
  color: var(--color-text-secondary);
}

.effort-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
}

.gap-violations {
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-warning-bg);
  border-radius: var(--border-radius-md);
  color: var(--color-warning-light);
}

.control-subtitle {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0 0 0;
}

.control-detail-section {
  margin-bottom: var(--spacing-xl);
  padding-bottom: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.control-detail-section:last-child {
  border-bottom: none;
}

.control-detail-section h3 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.control-detail-section p {
  color: var(--color-text-secondary);
  line-height: 1.6;
  margin: 0;
}

.status-display {
  margin-top: var(--spacing-sm);
}

.no-status {
  color: var(--color-text-muted);
  font-style: italic;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: var(--spacing-lg);
}

.modal-body {
  padding: var(--spacing-lg);
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

