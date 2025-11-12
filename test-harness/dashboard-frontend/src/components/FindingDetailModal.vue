<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen && finding" class="modal-overlay" @click="close">
        <div class="modal-content finding-detail" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <ShieldAlert class="modal-title-icon" :class="`icon-${finding.severity}`" />
              <h2>{{ finding.title }}</h2>
            </div>
            <div class="modal-header-actions">
              <button @click="downloadECS" class="action-btn-header">
                <Download class="action-icon" />
                Export ECS
              </button>
              <button @click="close" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
          </div>

          <div class="modal-body">
            <!-- Summary -->
            <div class="summary-section">
              <div class="summary-cards">
                <div class="summary-card">
                  <div class="summary-card-label">Severity</div>
                  <div class="summary-card-value" :class="`severity-${finding.severity}`">
                    {{ finding.severity }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Risk Score</div>
                  <div class="summary-card-value risk-score" :class="getRiskScoreClass(finding.riskScore)">
                    {{ finding.riskScore }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Status</div>
                  <div class="summary-card-value" :class="`status-${finding.status}`">
                    {{ finding.status }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Source</div>
                  <div class="summary-card-value">{{ finding.source.toUpperCase() }}</div>
                </div>
              </div>
            </div>

            <!-- Enhanced Risk Score -->
            <div v-if="finding.enhancedRiskScore" class="section">
              <EnhancedRiskScore :riskScore="finding.enhancedRiskScore" />
            </div>

            <!-- Description -->
            <div class="section">
              <h3>Description</h3>
              <p class="description-text">{{ finding.description }}</p>
            </div>

            <!-- Vulnerability Details -->
            <div v-if="finding.vulnerability" class="section">
              <h3>Vulnerability Details</h3>
              <div class="details-grid">
                <div class="detail-item" v-if="finding.vulnerability.cve?.id">
                  <span class="detail-label">CVE ID:</span>
                  <span class="detail-value">
                    <a :href="`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.vulnerability.cve.id}`" target="_blank" class="link">
                      {{ finding.vulnerability.cve.id }}
                    </a>
                  </span>
                </div>
                <div class="detail-item" v-if="finding.vulnerability.classification">
                  <span class="detail-label">CWE:</span>
                  <span class="detail-value">
                    <a :href="`https://cwe.mitre.org/data/definitions/${finding.vulnerability.classification.replace('CWE-', '')}.html`" target="_blank" class="link">
                      {{ finding.vulnerability.classification }}
                    </a>
                  </span>
                </div>
                <div class="detail-item" v-if="finding.vulnerability.cve?.score">
                  <span class="detail-label">CVSS Score:</span>
                  <span class="detail-value">{{ finding.vulnerability.cve.score.base }}</span>
                </div>
                <div class="detail-item" v-if="finding.vulnerability.scanner">
                  <span class="detail-label">Scanner:</span>
                  <span class="detail-value">{{ finding.vulnerability.scanner.vendor }} {{ finding.vulnerability.scanner.name }}</span>
                </div>
              </div>
            </div>

            <!-- Asset Information -->
            <div class="section">
              <h3>Asset Information</h3>
              <div class="details-grid">
                <div class="detail-item">
                  <span class="detail-label">Asset Type:</span>
                  <span class="detail-value">{{ finding.asset.type }}</span>
                </div>
                <div class="detail-item" v-if="finding.asset.applicationId">
                  <span class="detail-label">Application:</span>
                  <span class="detail-value">{{ finding.asset.applicationId }}</span>
                </div>
                <div class="detail-item" v-if="finding.asset.component">
                  <span class="detail-label">Component:</span>
                  <span class="detail-value">{{ finding.asset.component }}</span>
                </div>
                <div class="detail-item" v-if="finding.asset.location?.file">
                  <span class="detail-label">File:</span>
                  <span class="detail-value">{{ finding.asset.location.file.path }}</span>
                  <span v-if="finding.asset.location.line" class="detail-value">:{{ finding.asset.location.line }}</span>
                </div>
                <div class="detail-item" v-if="finding.asset.location?.url">
                  <span class="detail-label">URL:</span>
                  <span class="detail-value">
                    <a :href="finding.asset.location.url.original" target="_blank" class="link">
                      {{ finding.asset.location.url.original }}
                    </a>
                  </span>
                </div>
                <div class="detail-item" v-if="finding.asset.location?.resource">
                  <span class="detail-label">Resource:</span>
                  <span class="detail-value">{{ finding.asset.location.resource }}</span>
                </div>
              </div>
            </div>

            <!-- Compliance -->
            <div v-if="finding.compliance" class="section">
              <h3>Compliance</h3>
              <div class="compliance-section">
                <div class="detail-item">
                  <span class="detail-label">Frameworks:</span>
                  <div class="compliance-badges">
                    <span
                      v-for="framework in finding.compliance.frameworks"
                      :key="framework"
                      class="compliance-badge"
                    >
                      {{ framework }}
                    </span>
                  </div>
                </div>
                <div class="detail-item" v-if="finding.compliance.controls">
                  <span class="detail-label">Controls:</span>
                  <span class="detail-value">{{ finding.compliance.controls.join(', ') }}</span>
                </div>
              </div>
            </div>

            <!-- Remediation -->
            <div class="section">
              <h3>Remediation</h3>
              <div class="remediation-section">
                <p class="remediation-description">{{ finding.remediation.description }}</p>
                <div v-if="finding.remediation.steps.length > 0" class="remediation-steps">
                  <h4>Steps:</h4>
                  <ol>
                    <li v-for="(step, index) in finding.remediation.steps" :key="index">
                      {{ step }}
                    </li>
                  </ol>
                </div>
                <div v-if="finding.remediation.references.length > 0" class="remediation-references">
                  <h4>References:</h4>
                  <ul>
                    <li v-for="(ref, index) in finding.remediation.references" :key="index">
                      <a :href="ref" target="_blank" class="link">{{ ref }}</a>
                    </li>
                  </ul>
                </div>
                <div class="remediation-meta">
                  <span v-if="finding.remediation.automated" class="automated-badge">Automated Fix Available</span>
                  <span v-if="finding.remediation.estimatedEffort" class="effort-badge">
                    Effort: {{ finding.remediation.estimatedEffort }}
                  </span>
                </div>
              </div>
            </div>

            <!-- ECS Fields Preview -->
            <div class="section">
              <h3>ECS Mapping</h3>
              <div class="ecs-preview">
                <p class="ecs-note">This finding is mapped to Elastic Common Schema fields for seamless integration with Elasticsearch.</p>
                <div class="ecs-fields">
                  <div class="ecs-field" v-if="finding.event">
                    <span class="ecs-field-name">event.category:</span>
                    <span class="ecs-field-value">{{ finding.event.category }}</span>
                  </div>
                  <div class="ecs-field" v-if="finding.vulnerability?.cve?.id">
                    <span class="ecs-field-name">vulnerability.cve.id:</span>
                    <span class="ecs-field-value">{{ finding.vulnerability.cve.id }}</span>
                  </div>
                  <div class="ecs-field" v-if="finding.asset.location?.file">
                    <span class="ecs-field-name">file.path:</span>
                    <span class="ecs-field-value">{{ finding.asset.location.file.path }}</span>
                  </div>
                  <div class="ecs-field" v-if="finding.asset.location?.url">
                    <span class="ecs-field-name">url.original:</span>
                    <span class="ecs-field-value">{{ finding.asset.location.url.original }}</span>
                  </div>
                </div>
              </div>
            </div>

            <!-- Raw Data -->
            <div v-if="finding.raw" class="section">
              <h3>Raw Scanner Data</h3>
              <div class="raw-data">
                <pre>{{ JSON.stringify(finding.raw, null, 2) }}</pre>
              </div>
            </div>
          </div>

          <div class="modal-footer">
            <button @click="updateStatus('in-progress')" class="btn-secondary" v-if="finding.status === 'open'">
              Mark In Progress
            </button>
            <button @click="updateStatus('resolved')" class="btn-secondary" v-if="finding.status !== 'resolved'">
              Mark Resolved
            </button>
            <button @click="updateStatus('false-positive')" class="btn-secondary" v-if="finding.status !== 'false-positive'">
              Mark False Positive
            </button>
            <button @click="close" class="btn-primary">
              Close
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { Teleport } from 'vue';
import { ShieldAlert, X, Download } from 'lucide-vue-next';
import axios from 'axios';
import EnhancedRiskScore from './EnhancedRiskScore.vue';

const props = defineProps<{
  isOpen: boolean;
  finding: any;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'updated': [];
}>();

const close = () => {
  emit('update:isOpen', false);
};

const updateStatus = async (status: string) => {
  try {
    await axios.patch(`/api/unified-findings/${props.finding.id}`, { status });
    emit('updated');
  } catch (error) {
    console.error('Failed to update finding:', error);
    alert('Failed to update finding. Please try again.');
  }
};

const downloadECS = async () => {
  try {
    const response = await axios.get(`/api/unified-findings/${props.finding.id}`);
    const ecsDocs = await axios.get('/api/unified-findings/ecs', {
      params: { id: props.finding.id },
    });
    
    const blob = new Blob([JSON.stringify(ecsDocs.data[0], null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `finding-${props.finding.id}-ecs.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Failed to export ECS:', error);
    alert('Failed to export ECS format. Please try again.');
  }
};

const getRiskScoreClass = (score: number): string => {
  if (score >= 75) return 'risk-high';
  if (score >= 50) return 'risk-medium';
  return 'risk-low';
};
</script>

<style scoped>
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

.finding-detail {
  max-width: 1000px;
  max-height: 90vh;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.modal-title-icon.icon-critical {
  color: #fc8181;
}

.modal-title-icon.icon-high {
  color: #fbbf24;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.action-btn-header {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn-header:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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

.modal-body {
  padding: 24px;
  max-height: calc(90vh - 200px);
  overflow-y: auto;
}

.summary-section {
  margin-bottom: 24px;
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.summary-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.summary-card-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.summary-card-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #ffffff;
}

.summary-card-value.severity-critical {
  color: #fc8181;
}

.summary-card-value.severity-high {
  color: #fbbf24;
}

.summary-card-value.severity-medium {
  color: #4facfe;
}

.summary-card-value.risk-high {
  color: #fc8181;
}

.summary-card-value.risk-medium {
  color: #fbbf24;
}

.summary-card-value.risk-low {
  color: #22c55e;
}

.summary-card-value.status-open {
  color: #fc8181;
}

.summary-card-value.status-resolved {
  color: #22c55e;
}

.section {
  margin-bottom: 24px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.description-text {
  font-size: 0.9rem;
  color: #ffffff;
  line-height: 1.6;
  margin: 0;
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 16px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.detail-value {
  font-size: 0.9rem;
  color: #ffffff;
}

.link {
  color: #4facfe;
  text-decoration: none;
}

.link:hover {
  text-decoration: underline;
}

.compliance-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.compliance-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.compliance-badge {
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  font-size: 0.875rem;
  color: #4facfe;
  font-weight: 500;
}

.remediation-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.remediation-description {
  font-size: 0.9rem;
  color: #ffffff;
  line-height: 1.6;
}

.remediation-steps,
.remediation-references {
  margin-top: 12px;
}

.remediation-steps h4,
.remediation-references h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.remediation-steps ol,
.remediation-references ul {
  margin: 0;
  padding-left: 24px;
  color: #ffffff;
}

.remediation-steps li,
.remediation-references li {
  margin-bottom: 8px;
  line-height: 1.6;
}

.remediation-meta {
  display: flex;
  gap: 12px;
  margin-top: 16px;
}

.automated-badge,
.effort-badge {
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
}

.automated-badge {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.effort-badge {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.ecs-preview {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.ecs-note {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.ecs-fields {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.ecs-field {
  display: flex;
  gap: 12px;
  padding: 8px 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 6px;
}

.ecs-field-name {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #4facfe;
  font-weight: 500;
  min-width: 200px;
}

.ecs-field-value {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #ffffff;
}

.raw-data {
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
}

.raw-data pre {
  margin: 0;
  color: #a0aec0;
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  line-height: 1.6;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

