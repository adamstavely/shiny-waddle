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
    const response = await fetch('/api/compliance/frameworks');
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
    const response = await fetch(`/api/compliance/frameworks/${framework}`);
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
    const response = await fetch(`/api/compliance/frameworks/${selectedFramework.value}/controls`);
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
    const response = await fetch(`/api/compliance/mappings?framework=${selectedFramework.value}`);
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
    const response = await fetch(`/api/compliance/assessments?framework=${selectedFramework.value}&latest=true`);
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
    const response = await fetch(`/api/compliance/frameworks/${selectedFramework.value}/gaps`);
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
    const response = await fetch(`/api/compliance/roadmaps?framework=${selectedFramework.value}`);
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
    const response = await fetch('/api/compliance/assessments', {
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
    const response = await fetch(`/api/compliance/frameworks/${selectedFramework.value}/roadmaps`, {
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

const viewControl = (control: ComplianceControl) => {
  // Navigate to control detail page
  router.push(`/compliance/${selectedFramework.value}/controls/${control.controlId}`);
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
  gap: 24px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.framework-selection {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 400px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 24px;
}

.framework-header {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
}

.framework-info h2 {
  margin: 0 0 8px 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.framework-info p {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0 0 12px 0;
}

.framework-badge {
  display: inline-block;
  padding: 4px 12px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  margin-top: 8px;
}

.framework-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.assessment-summary {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
}

.summary-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.summary-header h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.assessment-date {
  font-size: 0.875rem;
  color: #a0aec0;
}

.summary-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}

.metric-card {
  text-align: center;
  padding: 20px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.metric-value {
  font-size: 2rem;
  font-weight: 700;
  margin-bottom: 8px;
  color: #ffffff;
}

.metric-value.success {
  color: #22c55e;
}

.metric-value.warning {
  color: #fbbf24;
}

.metric-value.error {
  color: #fc8181;
}

.metric-value.info {
  color: #4facfe;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.gaps-alert {
  display: flex;
  gap: 12px;
  padding: 16px;
  background: rgba(255, 152, 0, 0.1);
  border-left: 4px solid #fbbf24;
  border-radius: 12px;
  color: #fbbf24;
  margin-bottom: 16px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 0.9rem;
  font-weight: 500;
  color: #a0aec0;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-badge {
  padding: 2px 8px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.controls-filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  font-size: 0.9rem;
  color: #ffffff;
  transition: all 0.2s;
}

.search-input::placeholder {
  color: #a0aec0;
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
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.controls-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.control-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.control-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.control-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
}

.control-id {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 0.25rem 0;
}

.control-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.priority-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.priority-critical {
  background: #ffebee;
  color: #c62828;
}

.priority-high {
  background: #fff3e0;
  color: #e65100;
}

.priority-moderate {
  background: #fff9c4;
  color: #f57f17;
}

.priority-low {
  background: #e8f5e9;
  color: #2e7d32;
}

.control-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0.5rem 0;
  line-height: 1.5;
}

.control-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.control-family {
  font-size: 0.75rem;
  color: #a0aec0;
}

.status-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-compliant {
  background: #e8f5e9;
  color: #2e7d32;
}

.status-non_compliant {
  background: #ffebee;
  color: #c62828;
}

.status-partially_compliant {
  background: #fff3e0;
  color: #e65100;
}

.status-not_assessed {
  background: #f5f5f5;
  color: #666;
}

.gaps-list {
  display: grid;
  gap: 1rem;
}

.gap-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-left: 4px solid;
  border-radius: 8px;
  padding: 1.5rem;
}

.gap-card.priority-critical {
  border-left-color: #c62828;
}

.gap-card.priority-high {
  border-left-color: #e65100;
}

.gap-card.priority-moderate {
  border-left-color: #f57f17;
}

.gap-card.priority-low {
  border-left-color: #2e7d32;
}

.gap-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.gap-control-id {
  font-size: 0.875rem;
  color: #666;
  margin: 0 0 0.25rem 0;
}

.gap-title {
  font-size: 1.125rem;
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
  padding: 0.25rem 0.5rem;
  background: #e3f2fd;
  color: #1976d2;
  border-radius: 4px;
  font-size: 0.75rem;
}

.gap-violations {
  margin-bottom: 1rem;
  padding: 0.75rem;
  background: #fff3e0;
  border-radius: 4px;
}

.gap-remediation ul {
  margin: 0.5rem 0 0 1.5rem;
  padding: 0;
}

.gap-remediation li {
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
}

.roadmaps-list {
  display: grid;
  gap: 1rem;
}

.roadmap-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.roadmap-card:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.roadmap-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.roadmap-header h4 {
  margin: 0;
  font-size: 1.125rem;
}

.target-date {
  font-size: 0.875rem;
  color: #666;
}

.roadmap-description {
  color: #666;
  margin-bottom: 1rem;
}

.roadmap-stats {
  display: flex;
  gap: 1.5rem;
  font-size: 0.875rem;
  color: #666;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: white;
  border-radius: 8px;
  max-width: 800px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid #e0e0e0;
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
  gap: 24px;
  padding: 24px;
}

.framework-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s;
}

.framework-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.framework-icon {
  width: 3rem;
  height: 3rem;
  margin: 0 auto 1rem;
  color: #4facfe;
}

.framework-card h4 {
  margin: 0 0 8px 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.framework-card p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 0.5rem 0;
}

.framework-control-count {
  font-size: 0.75rem;
  color: #a0aec0;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto 1rem;
  color: #999;
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #a0aec0;
}

.loading-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto 24px;
  animation: spin 1s linear infinite;
  color: #4facfe;
}

.error-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 16px;
  margin: 0 auto;
  max-width: 600px;
}

.error-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 24px;
  color: #fc8181;
  opacity: 0.5;
}

.error-state h3 {
  margin: 0 0 8px 0;
  color: #fc8181;
  font-size: 1.5rem;
  font-weight: 600;
}

.error-state p {
  margin: 0 0 24px 0;
  color: #a0aec0;
  font-size: 1rem;
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
  gap: 8px;
  padding: 12px 24px;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
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
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.gap-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-left: 4px solid;
  border-radius: 16px;
  padding: 24px;
}

.roadmap-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.roadmap-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.roadmap-description {
  color: #a0aec0;
  margin-bottom: 1rem;
}

.target-date {
  font-size: 0.875rem;
  color: #a0aec0;
}

.roadmap-stats {
  display: flex;
  gap: 1.5rem;
  font-size: 0.875rem;
  color: #a0aec0;
}

.gap-control-id {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 0.25rem 0;
}

.gap-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.priority-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
}

.priority-critical {
  background: rgba(198, 40, 40, 0.2);
  color: #f44336;
}

.priority-high {
  background: rgba(230, 81, 0, 0.2);
  color: #ff9800;
}

.priority-moderate {
  background: rgba(245, 127, 23, 0.2);
  color: #ffb74d;
}

.priority-low {
  background: rgba(46, 125, 50, 0.2);
  color: #66bb6a;
}

.status-badge {
  padding: 0.25rem 0.5rem;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-compliant {
  background: rgba(46, 125, 50, 0.2);
  color: #66bb6a;
}

.status-non_compliant {
  background: rgba(198, 40, 40, 0.2);
  color: #f44336;
}

.status-partially_compliant {
  background: rgba(230, 81, 0, 0.2);
  color: #ff9800;
}

.status-not_assessed {
  background: rgba(79, 172, 254, 0.1);
  color: #a0aec0;
}

.effort-badge {
  padding: 0.25rem 0.5rem;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 8px;
  font-size: 0.75rem;
}

.gap-violations {
  margin-bottom: 1rem;
  padding: 0.75rem;
  background: rgba(255, 152, 0, 0.1);
  border-radius: 8px;
  color: #ffb74d;
}
</style>

