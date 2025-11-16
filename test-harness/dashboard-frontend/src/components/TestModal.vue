<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <TestTube class="modal-title-icon" />
              <h2>{{ testId ? 'Edit Test' : 'Create Test' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <form @submit.prevent="save" class="test-form">
              <!-- Basic Information -->
              <div class="form-section">
                <h3 class="section-title">Basic Information</h3>
                <div class="form-group">
                  <label>Test Name *</label>
                  <input v-model="form.name" type="text" required />
                </div>
                <div class="form-group">
                  <label>Description</label>
                  <textarea v-model="form.description" rows="3"></textarea>
                </div>
                <div class="form-group">
                  <label>Test Type *</label>
                  <select v-model="form.testType" required :disabled="!!testId" class="form-select">
                    <option value="">Select a test type...</option>
                    <option value="access-control">Access Control</option>
                    <option value="rls-cls">RLS/CLS</option>
                    <option value="network-policy">Network Policy</option>
                    <option value="dlp">DLP</option>
                    <option value="api-gateway">API Gateway</option>
                    <option value="distributed-systems">Distributed Systems</option>
                    <option value="api-security">API Security</option>
                    <option value="data-pipeline">Data Pipeline</option>
                  </select>
                  <small v-if="testId">Test type cannot be changed after creation</small>
                </div>
                <div v-if="testId && test" class="form-group">
                  <label>Current Version</label>
                  <span class="version-display">v{{ test.version }}</span>
                </div>
                <div v-if="testId" class="form-group">
                  <label>Change Reason (optional)</label>
                  <input v-model="form.changeReason" type="text" placeholder="Describe what changed..." />
                </div>
              </div>

              <!-- Access Control Configuration -->
              <div v-if="form.testType === 'access-control'" class="form-section">
                <h3 class="section-title">Access Control Configuration</h3>
                
                <!-- Policy Selection -->
                <div class="form-group">
                  <label>Policies to Test *</label>
                  <p class="form-help">Select one or more policies to test against</p>
                  <div class="policy-selector">
                    <div class="policy-filters">
                      <select v-model="policyFilter" class="form-select">
                        <option value="">All Policies</option>
                        <option value="rbac">RBAC Only</option>
                        <option value="abac">ABAC Only</option>
                      </select>
                    </div>
                    <div class="policies-list">
                      <div
                        v-for="policy in filteredPolicies"
                        :key="policy.id"
                        class="policy-option"
                        :class="{ selected: form.policyIds.includes(policy.id) }"
                        @click="togglePolicy(policy.id)"
                      >
                        <input
                          type="checkbox"
                          :checked="form.policyIds.includes(policy.id)"
                          @change="togglePolicy(policy.id)"
                        />
                        <div class="policy-info">
                          <div class="policy-name-row">
                            <span class="policy-name">{{ policy.name }}</span>
                            <span class="policy-type-badge" :class="policy.type">
                              {{ policy.type.toUpperCase() }}
                            </span>
                          </div>
                          <p v-if="policy.description" class="policy-description">{{ policy.description }}</p>
                        </div>
                      </div>
                    </div>
                    <div v-if="filteredPolicies.length === 0" class="empty-policies">
                      <p>No policies found. <router-link to="/policies">Create a policy first</router-link></p>
                    </div>
                  </div>
                </div>

                <!-- Role -->
                <div class="form-group">
                  <label>Role *</label>
                  <select v-model="form.role" required class="form-select">
                    <option value="">Select a role...</option>
                    <option value="admin">Admin</option>
                    <option value="researcher">Researcher</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </div>

                <!-- Resource -->
                <div class="form-group">
                  <label>Resource *</label>
                  <div class="resource-config">
                    <div class="form-row">
                      <div class="form-group">
                        <label>Resource ID</label>
                        <input v-model="form.resource.id" type="text" required />
                      </div>
                      <div class="form-group">
                        <label>Resource Type</label>
                        <input v-model="form.resource.type" type="text" required />
                      </div>
                    </div>
                    <div class="form-group">
                      <label>Sensitivity</label>
                      <select v-model="form.resource.sensitivity" class="form-select">
                        <option value="public">Public</option>
                        <option value="internal">Internal</option>
                        <option value="confidential">Confidential</option>
                        <option value="restricted">Restricted</option>
                      </select>
                    </div>
                  </div>
                </div>

                <!-- Context -->
                <div class="form-group">
                  <label>Context (optional)</label>
                  <div class="context-config">
                    <div class="form-row">
                      <div class="form-group">
                        <label>IP Address</label>
                        <input v-model="form.context.ipAddress" type="text" />
                      </div>
                      <div class="form-group">
                        <label>Time of Day</label>
                        <input v-model="form.context.timeOfDay" type="text" />
                      </div>
                    </div>
                    <div class="form-group">
                      <label>Location</label>
                      <input v-model="form.context.location" type="text" />
                    </div>
                  </div>
                </div>

                <!-- Expected Decision -->
                <div class="form-group">
                  <label>Expected Decision *</label>
                  <select v-model="form.expectedDecision" required class="form-select">
                    <option :value="true">Allow</option>
                    <option :value="false">Deny</option>
                  </select>
                </div>
              </div>

              <!-- DLP Configuration -->
              <div v-if="form.testType === 'dlp'" class="form-section">
                <h3 class="section-title">DLP Configuration</h3>
                <div class="form-group">
                  <label>Test Type</label>
                  <select v-model="dlpTestType" class="form-select">
                    <option value="pattern">Pattern Detection</option>
                    <option value="bulk-export">Bulk Export Limit</option>
                    <option value="pii-detection">PII Detection Rule</option>
                    <option value="export-restrictions">Export Restrictions</option>
                    <option value="aggregation-requirements">Aggregation Requirements</option>
                    <option value="field-restrictions">Field Restrictions</option>
                    <option value="join-restrictions">Join Restrictions</option>
                    <option value="custom-check">Custom Check</option>
                  </select>
                </div>

                <!-- Pattern Test -->
                <div v-if="dlpTestType === 'pattern'" class="form-group">
                  <label>Pattern *</label>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Pattern Name</label>
                      <input v-model="form.pattern.name" type="text" />
                    </div>
                    <div class="form-group">
                      <label>Pattern Type</label>
                      <select v-model="form.pattern.type" class="form-select">
                        <option value="ssn">SSN</option>
                        <option value="credit-card">Credit Card</option>
                        <option value="email">Email</option>
                        <option value="phone">Phone</option>
                        <option value="custom">Custom</option>
                      </select>
                    </div>
                  </div>
                  <div class="form-group">
                    <label>Pattern (Regex)</label>
                    <input v-model="form.pattern.pattern" type="text" />
                  </div>
                  <div class="form-group">
                    <label>Expected Detection</label>
                    <select v-model="form.expectedDetection" class="form-select">
                      <option :value="true">Should Detect</option>
                      <option :value="false">Should Not Detect</option>
                    </select>
                  </div>
                </div>

                <!-- Bulk Export Test -->
                <div v-if="dlpTestType === 'bulk-export'" class="form-group">
                  <label>Bulk Export Configuration *</label>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Export Type</label>
                      <select v-model="form.bulkExportType" class="form-select">
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                        <option value="excel">Excel</option>
                        <option value="api">API</option>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Limit</label>
                      <input v-model.number="form.bulkExportLimit" type="number" />
                    </div>
                    <div class="form-group">
                      <label>Test Record Count</label>
                      <input v-model.number="form.testRecordCount" type="number" />
                    </div>
                  </div>
                  <div class="form-group">
                    <label>Expected Blocked</label>
                    <select v-model="form.expectedBlocked" class="form-select">
                      <option :value="true">Should Block</option>
                      <option :value="false">Should Allow</option>
                    </select>
                  </div>
                </div>

                <!-- Export Restrictions Test -->
                <div v-if="dlpTestType === 'export-restrictions'" class="form-group">
                  <label>Export Restrictions Configuration *</label>
                  <div class="form-group">
                    <label>Restricted Fields (comma-separated)</label>
                    <input 
                      v-model="exportRestrictionsFieldsInput" 
                      type="text" 
                      placeholder="email, ssn, phone"
                      @blur="updateExportRestrictionsFields"
                    />
                    <small>Fields that cannot be exported</small>
                  </div>
                  <div class="form-group">
                    <label>
                      <input v-model="form.exportRestrictions.requireMasking" type="checkbox" />
                      Require Masking for Restricted Fields
                    </label>
                  </div>
                  <div class="form-group">
                    <label>Allowed Export Formats (comma-separated)</label>
                    <input 
                      v-model="allowedFormatsInput" 
                      type="text" 
                      placeholder="csv, json"
                      @blur="updateAllowedFormats"
                    />
                    <small>Leave empty to allow all formats</small>
                  </div>
                </div>

                <!-- Aggregation Requirements Test -->
                <div v-if="dlpTestType === 'aggregation-requirements'" class="form-group">
                  <label>Aggregation Requirements Configuration *</label>
                  <div class="form-group">
                    <label>
                      <input v-model="form.aggregationRequirements.requireAggregation" type="checkbox" />
                      Require Aggregation
                    </label>
                  </div>
                  <div class="form-group">
                    <label>Minimum k (Records per Group)</label>
                    <input 
                      v-model.number="form.aggregationRequirements.minK" 
                      type="number" 
                      min="1"
                      placeholder="10"
                    />
                    <small>Minimum number of records required per aggregation group</small>
                  </div>
                </div>

                <!-- Field Restrictions Test -->
                <div v-if="dlpTestType === 'field-restrictions'" class="form-group">
                  <label>Field Restrictions Configuration *</label>
                  <div class="form-group">
                    <label>Disallowed Fields (comma-separated)</label>
                    <input 
                      v-model="disallowedFieldsInput" 
                      type="text" 
                      placeholder="ssn, credit_card"
                      @blur="updateDisallowedFields"
                    />
                    <small>Fields that cannot be accessed in queries</small>
                  </div>
                  <div class="form-group">
                    <label>Allowed Fields (comma-separated)</label>
                    <input 
                      v-model="allowedFieldsInput" 
                      type="text" 
                      placeholder="id, name, status"
                      @blur="updateAllowedFields"
                    />
                    <small>Whitelist of allowed fields (leave empty to allow all except disallowed)</small>
                  </div>
                </div>

                <!-- Join Restrictions Test -->
                <div v-if="dlpTestType === 'join-restrictions'" class="form-group">
                  <label>Join Restrictions Configuration *</label>
                  <div class="form-group">
                    <label>Disallowed Joins (comma-separated table names)</label>
                    <input 
                      v-model="disallowedJoinsInput" 
                      type="text" 
                      placeholder="users, user_profiles"
                      @blur="updateDisallowedJoins"
                    />
                    <small>Tables that cannot be joined in queries</small>
                  </div>
                </div>
              </div>

              <!-- API Security Configuration -->
              <div v-if="form.testType === 'api-security'" class="form-section">
                <h3 class="section-title">API Security Configuration</h3>
                <div class="form-group">
                  <label>Test Sub-Type *</label>
                  <select v-model="apiSecuritySubType" required class="form-select">
                    <option value="apiVersion">API Versioning</option>
                    <option value="gatewayPolicy">Gateway Policy</option>
                    <option value="webhook">Webhook Security</option>
                    <option value="graphql">GraphQL Security</option>
                    <option value="apiContract">API Contract</option>
                  </select>
                </div>

                <!-- API Versioning Fields -->
                <div v-if="apiSecuritySubType === 'apiVersion'" class="api-security-config">
                  <div class="form-group">
                    <label>Version *</label>
                    <input v-model="form.apiVersion.version" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Endpoint *</label>
                    <input v-model="form.apiVersion.endpoint" type="text" required placeholder="https://api.example.com/v1" />
                  </div>
                  <div class="form-group">
                    <label>
                      <input v-model="form.apiVersion.deprecated" type="checkbox" />
                      Deprecated
                    </label>
                  </div>
                  <div v-if="form.apiVersion.deprecated" class="form-group">
                    <label>Deprecation Date</label>
                    <input v-model="form.apiVersion.deprecationDate" type="date" />
                  </div>
                  <div v-if="form.apiVersion.deprecated" class="form-group">
                    <label>Sunset Date</label>
                    <input v-model="form.apiVersion.sunsetDate" type="date" />
                  </div>
                </div>

                <!-- Gateway Policy Fields -->
                <div v-if="apiSecuritySubType === 'gatewayPolicy'" class="api-security-config">
                  <div class="form-group">
                    <label>Gateway Type *</label>
                    <select v-model="form.gatewayPolicy.gatewayType" required class="form-select">
                      <option value="aws-api-gateway">AWS API Gateway</option>
                      <option value="azure-api-management">Azure API Management</option>
                      <option value="kong">Kong</option>
                      <option value="istio">Istio</option>
                      <option value="envoy">Envoy</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Policy ID *</label>
                    <input v-model="form.gatewayPolicy.policyId" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Policy Type *</label>
                    <select v-model="form.gatewayPolicy.policyType" required class="form-select">
                      <option value="authentication">Authentication</option>
                      <option value="authorization">Authorization</option>
                      <option value="rate-limit">Rate Limit</option>
                      <option value="transformation">Transformation</option>
                      <option value="caching">Caching</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Route Path (optional)</label>
                    <input v-model="form.gatewayPolicy.route.path" type="text" placeholder="/api/v1/users" />
                  </div>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Route Method (optional)</label>
                      <select v-model="form.gatewayPolicy.route.method" class="form-select">
                        <option value="">Select method...</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Route Target (optional)</label>
                      <input v-model="form.gatewayPolicy.route.target" type="text" placeholder="http://backend:8080" />
                    </div>
                  </div>
                </div>

                <!-- Webhook Fields -->
                <div v-if="apiSecuritySubType === 'webhook'" class="api-security-config">
                  <div class="form-group">
                    <label>Endpoint *</label>
                    <input v-model="form.webhook.endpoint" type="text" required placeholder="https://webhook.example.com/callback" />
                  </div>
                  <div class="form-row">
                    <div class="form-group">
                      <label>Authentication Type *</label>
                      <select v-model="form.webhook.authentication.type" required class="form-select">
                        <option value="signature">Signature</option>
                        <option value="token">Token</option>
                        <option value="oauth2">OAuth2</option>
                      </select>
                    </div>
                    <div class="form-group">
                      <label>Authentication Method *</label>
                      <input v-model="form.webhook.authentication.method" type="text" required placeholder="HMAC-SHA256" />
                    </div>
                  </div>
                  <div class="form-group">
                    <label>
                      <input v-model="form.webhook.encryption.enabled" type="checkbox" />
                      Encryption Enabled
                    </label>
                  </div>
                  <div v-if="form.webhook.encryption.enabled" class="form-group">
                    <label>Encryption Method</label>
                    <input v-model="form.webhook.encryption.method" type="text" placeholder="TLS 1.3" />
                  </div>
                  <div class="form-group">
                    <label>
                      <input v-model="form.webhook.rateLimiting.enabled" type="checkbox" />
                      Rate Limiting Enabled
                    </label>
                  </div>
                  <div v-if="form.webhook.rateLimiting.enabled" class="form-row">
                    <div class="form-group">
                      <label>Max Requests *</label>
                      <input v-model.number="form.webhook.rateLimiting.maxRequests" type="number" required />
                    </div>
                    <div class="form-group">
                      <label>Window Seconds *</label>
                      <input v-model.number="form.webhook.rateLimiting.windowSeconds" type="number" required />
                    </div>
                  </div>
                </div>

                <!-- GraphQL Fields -->
                <div v-if="apiSecuritySubType === 'graphql'" class="api-security-config">
                  <div class="form-group">
                    <label>Endpoint *</label>
                    <input v-model="form.graphql.endpoint" type="text" required placeholder="https://api.example.com/graphql" />
                  </div>
                  <div class="form-group">
                    <label>Schema *</label>
                    <textarea v-model="form.graphql.schema" rows="8" required class="code-input" placeholder="type Query { ... }"></textarea>
                  </div>
                  <div class="form-group">
                    <label>Test Type *</label>
                    <select v-model="form.graphql.testType" required class="form-select">
                      <option value="depth">Depth</option>
                      <option value="complexity">Complexity</option>
                      <option value="introspection">Introspection</option>
                      <option value="full">Full</option>
                    </select>
                  </div>
                  <div v-if="form.graphql.testType === 'depth'" class="form-group">
                    <label>Max Depth</label>
                    <input v-model.number="form.graphql.maxDepth" type="number" />
                  </div>
                  <div v-if="form.graphql.testType === 'complexity'" class="form-group">
                    <label>Max Complexity</label>
                    <input v-model.number="form.graphql.maxComplexity" type="number" />
                  </div>
                  <div v-if="form.graphql.testType === 'introspection'" class="form-group">
                    <label>
                      <input v-model="form.graphql.introspectionEnabled" type="checkbox" />
                      Introspection Enabled
                    </label>
                  </div>
                </div>

                <!-- API Contract Fields -->
                <div v-if="apiSecuritySubType === 'apiContract'" class="api-security-config">
                  <div class="form-group">
                    <label>Contract Version *</label>
                    <input v-model="form.apiContract.version" type="text" required placeholder="1.0.0" />
                  </div>
                  <div class="form-group">
                    <label>Schema (JSON) *</label>
                    <textarea v-model="form.apiContract.schemaText" rows="10" required class="code-input" placeholder='{"openapi": "3.0.0", ...}'></textarea>
                    <small>Enter OpenAPI/Swagger schema as JSON</small>
                  </div>
                  <div class="form-group">
                    <label>Endpoints (optional)</label>
                    <p class="form-help">Add endpoints to test against the contract</p>
                    <div v-for="(endpoint, index) in form.apiContract.endpoints" :key="index" class="endpoint-item">
                      <div class="form-row">
                        <div class="form-group">
                          <label>Path</label>
                          <input v-model="endpoint.path" type="text" placeholder="/api/v1/users" />
                        </div>
                        <div class="form-group">
                          <label>Method</label>
                          <select v-model="endpoint.method" class="form-select">
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                            <option value="PATCH">PATCH</option>
                          </select>
                        </div>
                        <button @click="removeEndpoint(index)" type="button" class="icon-btn-small">
                          <X class="icon" />
                        </button>
                      </div>
                    </div>
                    <button @click="addEndpoint" type="button" class="btn-add-small">
                      <Plus class="btn-icon" />
                      Add Endpoint
                    </button>
                  </div>
                </div>
              </div>

              <!-- Validation Errors -->
              <div v-if="validationErrors.length > 0" class="validation-errors">
                <AlertTriangle class="error-icon" />
                <ul>
                  <li v-for="error in validationErrors" :key="error">{{ error }}</li>
                </ul>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  {{ saving ? 'Saving...' : (testId ? 'Update Test' : 'Create Test') }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  TestTube,
  X,
  AlertTriangle,
  Plus,
} from 'lucide-vue-next';
import axios from 'axios';

const props = defineProps<{
  show: boolean;
  testId?: string | null;
}>();

const emit = defineEmits<{
  close: [];
  saved: [];
}>();

const router = useRouter();

const test = ref<any>(null);
const policies = ref<any[]>([]);
const loading = ref(false);
const saving = ref(false);
const validationErrors = ref<string[]>([]);
const policyFilter = ref('');
const dlpTestType = ref('pattern');

// Input fields for comma-separated values (contract rules)
const exportRestrictionsFieldsInput = ref('');
const allowedFormatsInput = ref('');
const disallowedFieldsInput = ref('');
const allowedFieldsInput = ref('');
const disallowedJoinsInput = ref('');

const updateExportRestrictionsFields = () => {
  form.value.exportRestrictions.restrictedFields = exportRestrictionsFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateAllowedFormats = () => {
  form.value.exportRestrictions.allowedFormats = allowedFormatsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateDisallowedFields = () => {
  form.value.fieldRestrictions.disallowedFields = disallowedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateAllowedFields = () => {
  form.value.fieldRestrictions.allowedFields = allowedFieldsInput.value
    .split(',')
    .map(f => f.trim())
    .filter(f => f.length > 0);
};

const updateDisallowedJoins = () => {
  form.value.joinRestrictions.disallowedJoins = disallowedJoinsInput.value
    .split(',')
    .map(j => j.trim())
    .filter(j => j.length > 0);
};
const apiSecuritySubType = ref('apiVersion');

const form = ref({
  name: '',
  description: '',
  testType: '',
  policyIds: [] as string[],
  role: '',
  resource: {
    id: '',
    type: '',
    sensitivity: 'public' as 'public' | 'internal' | 'confidential' | 'restricted',
  },
  context: {
    ipAddress: '',
    timeOfDay: '',
    location: '',
  },
  expectedDecision: true,
  testQuery: {
    name: '',
    sql: '',
  },
  pattern: {
    name: '',
    type: 'ssn' as 'ssn' | 'credit-card' | 'email' | 'phone' | 'custom',
    pattern: '',
  },
  bulkExportType: 'csv' as 'csv' | 'json' | 'excel' | 'api',
  bulkExportLimit: 10000,
  testRecordCount: 10001,
  expectedBlocked: true,
  expectedDetection: true,
  exportRestrictions: {
    restrictedFields: [] as string[],
    requireMasking: false,
    allowedFormats: [] as string[],
  },
  aggregationRequirements: {
    minK: undefined as number | undefined,
    requireAggregation: false,
  },
  fieldRestrictions: {
    disallowedFields: [] as string[],
    allowedFields: [] as string[],
  },
  joinRestrictions: {
    disallowedJoins: [] as string[],
  },
  changeReason: '',
  // API Security fields
  apiVersion: {
    version: '',
    endpoint: '',
    deprecated: false,
    deprecationDate: '',
    sunsetDate: '',
  },
  gatewayPolicy: {
    gatewayType: 'aws-api-gateway' as 'aws-api-gateway' | 'azure-api-management' | 'kong' | 'istio' | 'envoy',
    policyId: '',
    policyType: 'authentication' as 'authentication' | 'authorization' | 'rate-limit' | 'transformation' | 'caching',
    route: {
      path: '',
      method: '',
      target: '',
    },
  },
  webhook: {
    endpoint: '',
    authentication: {
      type: 'signature' as 'signature' | 'token' | 'oauth2',
      method: '',
    },
    encryption: {
      enabled: false,
      method: '',
    },
    rateLimiting: {
      enabled: false,
      maxRequests: 100,
      windowSeconds: 60,
    },
  },
  graphql: {
    endpoint: '',
    schema: '',
    testType: 'depth' as 'depth' | 'complexity' | 'introspection' | 'full',
    maxDepth: 10,
    maxComplexity: 100,
    introspectionEnabled: false,
  },
  apiContract: {
    version: '',
    schemaText: '',
    endpoints: [] as Array<{ path: string; method: string }>,
  },
});

const filteredPolicies = computed(() => {
  let filtered = policies.value;
  if (policyFilter.value) {
    filtered = filtered.filter(p => p.type === policyFilter.value);
  }
  return filtered;
});

const loadTest = async () => {
  if (!props.testId) return;
  
  loading.value = true;
  try {
    const response = await axios.get(`/api/tests/${props.testId}`);
    test.value = response.data;
    
    // Populate form
    form.value.name = test.value.name;
    form.value.description = test.value.description || '';
    form.value.testType = test.value.testType;
    
    if (test.value.testType === 'access-control') {
      form.value.policyIds = test.value.policyIds || [];
      form.value.role = test.value.role;
      form.value.resource = test.value.resource;
      form.value.context = test.value.context || {};
      form.value.expectedDecision = test.value.expectedDecision;
    } else if (test.value.testType === 'dlp') {
      if (test.value.pattern) {
        dlpTestType.value = 'pattern';
        form.value.pattern = test.value.pattern;
        form.value.expectedDetection = test.value.expectedDetection;
      } else if (test.value.bulkExportType) {
        dlpTestType.value = 'bulk-export';
        form.value.bulkExportType = test.value.bulkExportType;
        form.value.bulkExportLimit = test.value.bulkExportLimit;
        form.value.testRecordCount = test.value.testRecordCount;
        form.value.expectedBlocked = test.value.expectedBlocked;
      } else if (test.value.exportRestrictions) {
        dlpTestType.value = 'export-restrictions';
        form.value.exportRestrictions = {
          restrictedFields: test.value.exportRestrictions.restrictedFields || [],
          requireMasking: test.value.exportRestrictions.requireMasking || false,
          allowedFormats: test.value.exportRestrictions.allowedFormats || [],
        };
        exportRestrictionsFieldsInput.value = form.value.exportRestrictions.restrictedFields.join(', ');
        allowedFormatsInput.value = form.value.exportRestrictions.allowedFormats.join(', ');
      } else if (test.value.aggregationRequirements) {
        dlpTestType.value = 'aggregation-requirements';
        form.value.aggregationRequirements = {
          minK: test.value.aggregationRequirements.minK,
          requireAggregation: test.value.aggregationRequirements.requireAggregation || false,
        };
      } else if (test.value.fieldRestrictions) {
        dlpTestType.value = 'field-restrictions';
        form.value.fieldRestrictions = {
          disallowedFields: test.value.fieldRestrictions.disallowedFields || [],
          allowedFields: test.value.fieldRestrictions.allowedFields || [],
        };
        disallowedFieldsInput.value = form.value.fieldRestrictions.disallowedFields.join(', ');
        allowedFieldsInput.value = form.value.fieldRestrictions.allowedFields.join(', ');
      } else if (test.value.joinRestrictions) {
        dlpTestType.value = 'join-restrictions';
        form.value.joinRestrictions = {
          disallowedJoins: test.value.joinRestrictions.disallowedJoins || [],
        };
        disallowedJoinsInput.value = form.value.joinRestrictions.disallowedJoins.join(', ');
      }
    } else if (test.value.testType === 'api-security') {
      if (test.value.apiVersion) {
        apiSecuritySubType.value = 'apiVersion';
        form.value.apiVersion = {
          version: test.value.apiVersion.version || '',
          endpoint: test.value.apiVersion.endpoint || '',
          deprecated: test.value.apiVersion.deprecated || false,
          deprecationDate: test.value.apiVersion.deprecationDate ? new Date(test.value.apiVersion.deprecationDate).toISOString().split('T')[0] : '',
          sunsetDate: test.value.apiVersion.sunsetDate ? new Date(test.value.apiVersion.sunsetDate).toISOString().split('T')[0] : '',
        };
      } else if (test.value.gatewayPolicy) {
        apiSecuritySubType.value = 'gatewayPolicy';
        form.value.gatewayPolicy = {
          gatewayType: test.value.gatewayPolicy.gatewayType || 'aws-api-gateway',
          policyId: test.value.gatewayPolicy.policyId || '',
          policyType: test.value.gatewayPolicy.policyType || 'authentication',
          route: test.value.gatewayPolicy.route || { path: '', method: '', target: '' },
        };
      } else if (test.value.webhook) {
        apiSecuritySubType.value = 'webhook';
        form.value.webhook = {
          endpoint: test.value.webhook.endpoint || '',
          authentication: test.value.webhook.authentication || { type: 'signature', method: '' },
          encryption: test.value.webhook.encryption || { enabled: false, method: '' },
          rateLimiting: test.value.webhook.rateLimiting
            ? {
                enabled: true,
                maxRequests: test.value.webhook.rateLimiting.maxRequests || 100,
                windowSeconds: test.value.webhook.rateLimiting.windowSeconds || 60,
              }
            : { enabled: false, maxRequests: 100, windowSeconds: 60 },
        };
      } else if (test.value.graphql) {
        apiSecuritySubType.value = 'graphql';
        form.value.graphql = {
          endpoint: test.value.graphql.endpoint || '',
          schema: test.value.graphql.schema || '',
          testType: test.value.graphql.testType || 'depth',
          maxDepth: test.value.graphql.maxDepth || 10,
          maxComplexity: test.value.graphql.maxComplexity || 100,
          introspectionEnabled: test.value.graphql.introspectionEnabled || false,
        };
      } else if (test.value.apiContract) {
        apiSecuritySubType.value = 'apiContract';
        form.value.apiContract = {
          version: test.value.apiContract.version || '',
          schemaText: JSON.stringify(test.value.apiContract.schema || {}, null, 2),
          endpoints: test.value.apiContract.endpoints || [],
        };
      }
    }
  } catch (err: any) {
    console.error('Error loading test:', err);
  } finally {
    loading.value = false;
  }
};

const loadPolicies = async () => {
  try {
    const response = await axios.get('/api/policies');
    policies.value = response.data;
  } catch (err) {
    console.error('Error loading policies:', err);
  }
};

const togglePolicy = (policyId: string) => {
  const index = form.value.policyIds.indexOf(policyId);
  if (index > -1) {
    form.value.policyIds.splice(index, 1);
  } else {
    form.value.policyIds.push(policyId);
  }
};

const addEndpoint = () => {
  form.value.apiContract.endpoints.push({ path: '', method: 'GET' });
};

const removeEndpoint = (index: number) => {
  form.value.apiContract.endpoints.splice(index, 1);
};

const validate = (): boolean => {
  validationErrors.value = [];
  
  if (!form.value.name) {
    validationErrors.value.push('Test name is required');
  }
  
  if (!form.value.testType) {
    validationErrors.value.push('Test type is required');
  }
  
  if (form.value.testType === 'access-control') {
    if (form.value.policyIds.length === 0) {
      validationErrors.value.push('At least one policy must be selected');
    }
    if (!form.value.role) {
      validationErrors.value.push('Role is required');
    }
    if (!form.value.resource.id || !form.value.resource.type) {
      validationErrors.value.push('Resource ID and type are required');
    }
  }
  
  if (form.value.testType === 'api-security') {
    if (apiSecuritySubType.value === 'apiVersion') {
      if (!form.value.apiVersion.version || !form.value.apiVersion.endpoint) {
        validationErrors.value.push('Version and Endpoint are required for API Versioning test');
      }
    } else if (apiSecuritySubType.value === 'gatewayPolicy') {
      if (!form.value.gatewayPolicy.gatewayType || !form.value.gatewayPolicy.policyId || !form.value.gatewayPolicy.policyType) {
        validationErrors.value.push('Gateway Type, Policy ID, and Policy Type are required for Gateway Policy test');
      }
    } else if (apiSecuritySubType.value === 'webhook') {
      if (!form.value.webhook.endpoint || !form.value.webhook.authentication.type || !form.value.webhook.authentication.method) {
        validationErrors.value.push('Endpoint, Authentication Type, and Authentication Method are required for Webhook test');
      }
      if (form.value.webhook.rateLimiting.enabled && (!form.value.webhook.rateLimiting.maxRequests || !form.value.webhook.rateLimiting.windowSeconds)) {
        validationErrors.value.push('Max Requests and Window Seconds are required when Rate Limiting is enabled');
      }
    } else if (apiSecuritySubType.value === 'graphql') {
      if (!form.value.graphql.endpoint || !form.value.graphql.schema || !form.value.graphql.testType) {
        validationErrors.value.push('Endpoint, Schema, and Test Type are required for GraphQL test');
      }
    } else if (apiSecuritySubType.value === 'apiContract') {
      if (!form.value.apiContract.version || !form.value.apiContract.schemaText) {
        validationErrors.value.push('Contract Version and Schema are required for API Contract test');
      }
    }
  }
  
  return validationErrors.value.length === 0;
};

const save = async () => {
  if (!validate()) {
    return;
  }
  
  saving.value = true;
  try {
    const payload: any = {
      name: form.value.name,
      description: form.value.description,
      testType: form.value.testType,
    };
    
    if (form.value.testType === 'access-control') {
      payload.policyIds = form.value.policyIds;
      payload.role = form.value.role;
      payload.resource = form.value.resource;
      payload.context = form.value.context;
      payload.expectedDecision = form.value.expectedDecision;
    } else if (form.value.testType === 'dlp') {
      if (dlpTestType.value === 'pattern') {
        payload.pattern = form.value.pattern;
        payload.expectedDetection = form.value.expectedDetection;
      } else if (dlpTestType.value === 'bulk-export') {
        payload.bulkExportType = form.value.bulkExportType;
        payload.bulkExportLimit = form.value.bulkExportLimit;
        payload.testRecordCount = form.value.testRecordCount;
        payload.expectedBlocked = form.value.expectedBlocked;
      } else if (dlpTestType.value === 'export-restrictions') {
        // Update fields from inputs before saving
        updateExportRestrictionsFields();
        updateAllowedFormats();
        payload.exportRestrictions = {
          restrictedFields: form.value.exportRestrictions.restrictedFields,
          requireMasking: form.value.exportRestrictions.requireMasking,
          allowedFormats: form.value.exportRestrictions.allowedFormats.length > 0 
            ? form.value.exportRestrictions.allowedFormats 
            : undefined,
        };
      } else if (dlpTestType.value === 'aggregation-requirements') {
        payload.aggregationRequirements = {
          minK: form.value.aggregationRequirements.minK,
          requireAggregation: form.value.aggregationRequirements.requireAggregation,
        };
      } else if (dlpTestType.value === 'field-restrictions') {
        // Update fields from inputs before saving
        updateDisallowedFields();
        updateAllowedFields();
        payload.fieldRestrictions = {
          disallowedFields: form.value.fieldRestrictions.disallowedFields.length > 0
            ? form.value.fieldRestrictions.disallowedFields
            : undefined,
          allowedFields: form.value.fieldRestrictions.allowedFields.length > 0
            ? form.value.fieldRestrictions.allowedFields
            : undefined,
        };
      } else if (dlpTestType.value === 'join-restrictions') {
        // Update fields from inputs before saving
        updateDisallowedJoins();
        payload.joinRestrictions = {
          disallowedJoins: form.value.joinRestrictions.disallowedJoins,
        };
      }
    } else if (form.value.testType === 'api-security') {
      if (apiSecuritySubType.value === 'apiVersion') {
        payload.apiVersion = {
          version: form.value.apiVersion.version,
          endpoint: form.value.apiVersion.endpoint,
          deprecated: form.value.apiVersion.deprecated,
          deprecationDate: form.value.apiVersion.deprecationDate ? new Date(form.value.apiVersion.deprecationDate) : undefined,
          sunsetDate: form.value.apiVersion.sunsetDate ? new Date(form.value.apiVersion.sunsetDate) : undefined,
        };
      } else if (apiSecuritySubType.value === 'gatewayPolicy') {
        payload.gatewayPolicy = {
          gatewayType: form.value.gatewayPolicy.gatewayType,
          policyId: form.value.gatewayPolicy.policyId,
          policyType: form.value.gatewayPolicy.policyType,
          route: form.value.gatewayPolicy.route.path || form.value.gatewayPolicy.route.method || form.value.gatewayPolicy.route.target
            ? {
                path: form.value.gatewayPolicy.route.path,
                method: form.value.gatewayPolicy.route.method,
                target: form.value.gatewayPolicy.route.target,
              }
            : undefined,
        };
      } else if (apiSecuritySubType.value === 'webhook') {
        payload.webhook = {
          endpoint: form.value.webhook.endpoint,
          authentication: {
            type: form.value.webhook.authentication.type,
            method: form.value.webhook.authentication.method,
          },
          encryption: {
            enabled: form.value.webhook.encryption.enabled,
            method: form.value.webhook.encryption.enabled ? form.value.webhook.encryption.method : undefined,
          },
          rateLimiting: form.value.webhook.rateLimiting.enabled
            ? {
                maxRequests: form.value.webhook.rateLimiting.maxRequests,
                windowSeconds: form.value.webhook.rateLimiting.windowSeconds,
              }
            : undefined,
        };
      } else if (apiSecuritySubType.value === 'graphql') {
        payload.graphql = {
          endpoint: form.value.graphql.endpoint,
          schema: form.value.graphql.schema,
          testType: form.value.graphql.testType,
          maxDepth: form.value.graphql.testType === 'depth' ? form.value.graphql.maxDepth : undefined,
          maxComplexity: form.value.graphql.testType === 'complexity' ? form.value.graphql.maxComplexity : undefined,
          introspectionEnabled: form.value.graphql.testType === 'introspection' ? form.value.graphql.introspectionEnabled : undefined,
        };
      } else if (apiSecuritySubType.value === 'apiContract') {
        try {
          const schema = JSON.parse(form.value.apiContract.schemaText);
          payload.apiContract = {
            version: form.value.apiContract.version,
            schema: schema,
            endpoints: form.value.apiContract.endpoints.length > 0 ? form.value.apiContract.endpoints : undefined,
          };
        } catch (e) {
          validationErrors.value = ['Schema must be valid JSON'];
          saving.value = false;
          return;
        }
      }
    }
    
    if (props.testId) {
      if (form.value.changeReason) {
        payload.changeReason = form.value.changeReason;
      }
      await axios.put(`/api/tests/${props.testId}`, payload);
    } else {
      await axios.post('/api/tests', payload);
    }
    
    emit('saved');
    close();
  } catch (err: any) {
    validationErrors.value = [err.response?.data?.message || 'Failed to save test'];
    console.error('Error saving test:', err);
  } finally {
    saving.value = false;
  }
};

const close = () => {
  emit('close');
  // Reset input fields
  exportRestrictionsFieldsInput.value = '';
  allowedFormatsInput.value = '';
  disallowedFieldsInput.value = '';
  allowedFieldsInput.value = '';
  disallowedJoinsInput.value = '';
  dlpTestType.value = 'pattern';
  // Reset form
  form.value = {
    name: '',
    description: '',
    testType: '',
    policyIds: [],
    role: '',
    resource: {
      id: '',
      type: '',
      sensitivity: 'public',
    },
    context: {
      ipAddress: '',
      timeOfDay: '',
      location: '',
    },
    expectedDecision: true,
    testQuery: {
      name: '',
      sql: '',
    },
    pattern: {
      name: '',
      type: 'ssn',
      pattern: '',
    },
    bulkExportType: 'csv',
    bulkExportLimit: 10000,
    testRecordCount: 10001,
    expectedBlocked: true,
    expectedDetection: true,
    exportRestrictions: {
      restrictedFields: [],
      requireMasking: false,
      allowedFormats: [],
    },
    aggregationRequirements: {
      minK: undefined,
      requireAggregation: false,
    },
    fieldRestrictions: {
      disallowedFields: [],
      allowedFields: [],
    },
    joinRestrictions: {
      disallowedJoins: [],
    },
    changeReason: '',
    apiVersion: {
      version: '',
      endpoint: '',
      deprecated: false,
      deprecationDate: '',
      sunsetDate: '',
    },
    gatewayPolicy: {
      gatewayType: 'aws-api-gateway',
      policyId: '',
      policyType: 'authentication',
      route: {
        path: '',
        method: '',
        target: '',
      },
    },
    webhook: {
      endpoint: '',
      authentication: {
        type: 'signature',
        method: '',
      },
      encryption: {
        enabled: false,
        method: '',
      },
      rateLimiting: {
        enabled: false,
        maxRequests: 100,
        windowSeconds: 60,
      },
    },
    graphql: {
      endpoint: '',
      schema: '',
      testType: 'depth',
      maxDepth: 10,
      maxComplexity: 100,
      introspectionEnabled: false,
    },
    apiContract: {
      version: '',
      schemaText: '',
      endpoints: [],
    },
  };
  apiSecuritySubType.value = 'apiVersion';
  validationErrors.value = [];
  test.value = null;
};

watch(() => props.show, (newVal) => {
  if (newVal) {
    loadPolicies();
    if (props.testId) {
      loadTest();
    }
  }
});

onMounted(() => {
  if (props.show) {
    loadPolicies();
    if (props.testId) {
      loadTest();
    }
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
  padding: 2rem;
}

.modal-content {
  background: rgba(15, 20, 25, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  max-width: 900px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
}

.large-modal {
  max-width: 1200px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: transparent;
  border: none;
  color: rgba(255, 255, 255, 0.6);
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  transition: all 0.2s;
}

.modal-close:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #ffffff;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 1.5rem;
}

.test-form {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.form-section {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.4);
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 1rem 0;
  color: #ffffff;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.875rem;
  font-weight: 500;
}

.form-group input,
.form-group textarea,
.form-group select {
  width: 100%;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.5);
}

.form-group small {
  display: block;
  margin-top: 0.25rem;
  color: rgba(255, 255, 255, 0.5);
  font-size: 0.75rem;
}

.form-help {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
  margin: 0.25rem 0 0.5rem 0;
}

.form-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.policy-selector {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  background: rgba(15, 20, 25, 0.6);
  max-height: 400px;
  overflow-y: auto;
}

.policies-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-top: 1rem;
}

.policy-option {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.policy-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.policy-option.selected {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.policy-info {
  flex: 1;
}

.policy-name-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.25rem;
}

.policy-name {
  font-weight: 600;
  color: #ffffff;
}

.policy-type-badge {
  padding: 0.125rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.policy-type-badge.rbac {
  background: rgba(16, 185, 129, 0.2);
  color: #10b981;
}

.policy-type-badge.abac {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.policy-description {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
  margin: 0;
}

.empty-policies {
  text-align: center;
  padding: 2rem;
  color: rgba(255, 255, 255, 0.6);
}

.version-display {
  display: inline-block;
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 6px;
  font-weight: 600;
}

.validation-errors {
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  padding: 1rem;
  display: flex;
  gap: 0.75rem;
  color: #ef4444;
}

.validation-errors ul {
  margin: 0;
  padding-left: 1.5rem;
}

.error-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  padding: 0.75rem 1.5rem;
  border-radius: 6px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: #4facfe;
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  background: #3d8bfe;
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.code-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.api-security-config {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.endpoint-item {
  margin-bottom: 1rem;
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
}

.btn-add-small {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.btn-add-small:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.icon-btn-small {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 4px;
  color: #ef4444;
  cursor: pointer;
  transition: all 0.2s;
}

.icon-btn-small:hover {
  background: rgba(239, 68, 68, 0.2);
  border-color: rgba(239, 68, 68, 0.4);
}

.icon-btn-small .icon {
  width: 16px;
  height: 16px;
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

