<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Policies</h1>
          <p class="page-description">Manage RBAC and ABAC access control policies</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Policy
        </button>
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

    <!-- Filters (only show for Access Control tab) -->
    <div v-if="activeTab === 'access-control'" class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search policies..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <!-- Loading State -->
    <div v-if="loading && policies.length === 0" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading policies...</p>
    </div>

    <!-- Error State -->
    <div v-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadPolicies" class="btn-retry">Retry</button>
    </div>

    <!-- Tab Content -->
    <!-- Access Control Policies -->
    <div v-if="activeTab === 'access-control' && (!loading || policies.length > 0)" class="policies-grid">
      <div
        v-for="policy in filteredPolicies"
        :key="policy.id"
        class="policy-card"
        @click="viewPolicy(policy.id)"
      >
        <div class="policy-header">
          <div class="policy-title-row">
            <h3 class="policy-name">{{ policy.name }}</h3>
            <span class="policy-status" :class="`status-${policy.status}`">
              {{ policy.status }}
            </span>
          </div>
          <p class="policy-meta">
            {{ policy.type.toUpperCase() }} • v{{ policy.version }}
          </p>
        </div>

        <p class="policy-description">{{ policy.description }}</p>

        <div class="policy-stats">
          <div class="stat">
            <span class="stat-label">Rules</span>
            <span class="stat-value">{{ policy.ruleCount }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">Tests</span>
            <span class="stat-value">{{ getTestCount(policy.id) }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">Last Updated</span>
            <span class="stat-value">{{ formatDate(policy.lastUpdated) }}</span>
          </div>
        </div>

        <div class="policy-actions">
          <button @click.stop="editPolicy(policy.id)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click.stop="viewVersions(policy.id)" class="action-btn view-btn">
            <History class="action-icon" />
            Versions
          </button>
          <button @click.stop="testPolicy(policy.id)" class="action-btn test-btn">
            <TestTube class="action-icon" />
            Test
          </button>
          <button @click.stop="viewTestsUsingPolicy(policy.id)" class="action-btn view-btn" v-if="getTestCount(policy.id) > 0">
            <TestTube class="action-icon" />
            View Tests ({{ getTestCount(policy.id) }})
          </button>
          <button @click.stop="deletePolicy(policy.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="activeTab === 'access-control' && filteredPolicies.length === 0" class="empty-state">
      <Shield class="empty-icon" />
      <h3>No policies found</h3>
      <p>Create your first policy to get started</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Create Policy
      </button>
    </div>

    <!-- Data Classification Tab -->
    <div v-if="activeTab === 'data-classification'" class="tab-content">
      <div class="data-classification-content">
        <!-- Classification Levels Section -->
        <div class="classification-section">
          <div class="section-header">
            <h2 class="section-title">Classification Levels</h2>
            <button @click="showCreateLevelModal = true" class="btn-primary">
              <Plus class="btn-icon" />
              Create Level
            </button>
          </div>
          <div v-if="loadingLevels" class="loading-state">Loading levels...</div>
          <div v-else-if="levelsError" class="error-state">{{ levelsError }}</div>
          <div v-else-if="levels.length === 0" class="empty-state">
            <p>No classification levels defined</p>
            <button @click="showCreateLevelModal = true" class="btn-primary">Create First Level</button>
          </div>
          <div v-else class="levels-grid">
            <div
              v-for="level in levels"
              :key="level.id"
              class="level-card"
              :style="{ borderLeftColor: level.color || '#4facfe' }"
            >
              <div class="level-header">
                <h3 class="level-name">{{ level.name }}</h3>
                <span class="level-sensitivity">{{ level.sensitivity }}</span>
              </div>
              <p class="level-description">{{ level.description }}</p>
              <div class="level-actions">
                <button @click="editLevel(level)" class="action-btn edit-btn">
                  <Edit class="action-icon" />
                  Edit
                </button>
                <button @click="deleteLevel(level.id)" class="action-btn delete-btn">
                  <Trash2 class="action-icon" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Classification Rules Section -->
        <div class="classification-section" style="margin-top: 32px;">
          <div class="section-header">
            <h2 class="section-title">Classification Rules</h2>
            <button @click="showCreateRuleModal = true" class="btn-primary">
              <Plus class="btn-icon" />
              Create Rule
            </button>
          </div>
          <div class="filters">
            <input
              v-model="ruleSearchQuery"
              type="text"
              placeholder="Search rules..."
              class="search-input"
            />
            <Dropdown
              v-model="ruleFilterLevel"
              :options="levelFilterOptions"
              placeholder="All Levels"
              class="filter-dropdown"
            />
            <Dropdown
              v-model="ruleFilterEnabled"
              :options="enabledFilterOptions"
              placeholder="All Statuses"
              class="filter-dropdown"
            />
          </div>
          <div v-if="loadingRules" class="loading-state">Loading rules...</div>
          <div v-else-if="rulesError" class="error-state">{{ rulesError }}</div>
          <div v-else-if="filteredRules.length === 0" class="empty-state">
            <p>No classification rules found</p>
            <button @click="showCreateRuleModal = true" class="btn-primary">Create First Rule</button>
          </div>
          <div v-else class="rules-list">
            <div
              v-for="rule in filteredRules"
              :key="rule.id"
              class="rule-card"
              :class="{ disabled: !rule.enabled }"
            >
              <div class="rule-header">
                <div class="rule-title-row">
                  <h4 class="rule-name">{{ rule.name }}</h4>
                  <span class="rule-status" :class="rule.enabled ? 'enabled' : 'disabled'">
                    {{ rule.enabled ? 'Enabled' : 'Disabled' }}
                  </span>
                </div>
                <p class="rule-description">{{ rule.description }}</p>
              </div>
              <div class="rule-details">
                <div class="rule-detail-item">
                  <span class="detail-label">Level:</span>
                  <span class="detail-value">{{ getLevelName(rule.levelId) }}</span>
                </div>
                <div class="rule-detail-item">
                  <span class="detail-label">Condition:</span>
                  <span class="detail-value">{{ rule.condition }} "{{ rule.value }}"</span>
                </div>
                <div v-if="rule.field" class="rule-detail-item">
                  <span class="detail-label">Field:</span>
                  <span class="detail-value">{{ rule.field }}</span>
                </div>
              </div>
              <div class="rule-actions">
                <button @click="editRule(rule)" class="action-btn edit-btn">
                  <Edit class="action-icon" />
                  Edit
                </button>
                <button @click="toggleRule(rule)" class="action-btn" :class="rule.enabled ? 'disable-btn' : 'enable-btn'">
                  {{ rule.enabled ? 'Disable' : 'Enable' }}
                </button>
                <button @click="deleteRule(rule.id)" class="action-btn delete-btn">
                  <Trash2 class="action-icon" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Platform Config Tab -->
    <div v-if="activeTab === 'platform-config'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">Platform Configuration Baselines</h2>
        <button @click="showCreateBaselineModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
      <div v-if="loadingBaselines" class="loading-state">Loading baselines...</div>
      <div v-else-if="baselinesError" class="error-state">{{ baselinesError }}</div>
      <div v-else-if="baselines.length === 0" class="empty-state">
        <p>No baselines defined</p>
        <button @click="showCreateBaselineModal = true" class="btn-primary">Create First Baseline</button>
      </div>
      <div v-else class="baselines-grid">
        <div v-for="baseline in baselines" :key="baseline.id" class="baseline-card">
          <div class="baseline-header">
            <h3 class="baseline-name">{{ baseline.name }}</h3>
            <span class="baseline-environment">{{ baseline.environment }}</span>
          </div>
          <p class="baseline-description">{{ baseline.description }}</p>
          <div class="baseline-actions">
            <button @click="compareBaseline(baseline.id)" class="action-btn edit-btn">Compare</button>
            <button @click="detectDrift(baseline.id)" class="action-btn edit-btn">Detect Drift</button>
            <button @click="deleteBaseline(baseline.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Exceptions Tab -->
    <div v-if="activeTab === 'exceptions'" class="tab-content">
      <div class="exceptions-content">
        <div class="classification-section">
          <div class="section-header">
            <h2 class="section-title">Policy Exceptions</h2>
            <button @click="showCreateExceptionModal = true" class="btn-primary">
              <Plus class="btn-icon" />
              Request Exception
            </button>
          </div>
          <div v-if="loadingExceptions" class="loading-state">Loading exceptions...</div>
          <div v-else-if="exceptionsError" class="error-state">{{ exceptionsError }}</div>
          <div v-else-if="exceptions.length === 0" class="empty-state">
            <p>No exceptions found</p>
          </div>
          <div v-else class="exceptions-list">
            <div v-for="exception in exceptions" :key="exception.id" class="exception-card">
              <div class="exception-header">
                <h4 class="exception-name">{{ exception.name }}</h4>
                <span class="exception-status" :class="`status-${exception.status}`">{{ exception.status }}</span>
              </div>
              <p class="exception-description">{{ exception.description || exception.reason }}</p>
              <div class="exception-meta">
                <span>Requested by: {{ exception.requestedBy }}</span>
                <span>{{ formatDate(exception.requestedAt) }}</span>
              </div>
              <div class="exception-actions">
                <button v-if="exception.status === 'pending'" @click="approveException(exception.id)" class="action-btn enable-btn">Approve</button>
                <button @click="deleteException(exception.id)" class="action-btn delete-btn">
                  <Trash2 class="action-icon" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
        <div class="classification-section" style="margin-top: 32px;">
          <div class="section-header">
            <h2 class="section-title">Allowlists</h2>
            <button @click="showCreateAllowlistModal = true" class="btn-primary">
              <Plus class="btn-icon" />
              Create Allowlist
            </button>
          </div>
          <div v-if="loadingAllowlists" class="loading-state">Loading allowlists...</div>
          <div v-else-if="allowlistsError" class="error-state">{{ allowlistsError }}</div>
          <div v-else-if="allowlists.length === 0" class="empty-state">
            <p>No allowlists defined</p>
          </div>
          <div v-else class="allowlists-list">
            <div v-for="allowlist in allowlists" :key="allowlist.id" class="allowlist-card">
              <div class="allowlist-header">
                <h4 class="allowlist-name">{{ allowlist.name }}</h4>
                <span class="allowlist-status" :class="allowlist.enabled ? 'enabled' : 'disabled'">
                  {{ allowlist.enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </div>
              <p class="allowlist-description">{{ allowlist.description }}</p>
              <div class="allowlist-details">
                <span class="detail-label">Type:</span>
                <span class="detail-value">{{ allowlist.type }}</span>
                <span class="detail-label">Values:</span>
                <span class="detail-value">{{ allowlist.values.join(', ') }}</span>
              </div>
              <div class="allowlist-actions">
                <button @click="toggleAllowlist(allowlist)" class="action-btn" :class="allowlist.enabled ? 'disable-btn' : 'enable-btn'">
                  {{ allowlist.enabled ? 'Disable' : 'Enable' }}
                </button>
                <button @click="deleteAllowlist(allowlist.id)" class="action-btn delete-btn">
                  <Trash2 class="action-icon" />
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Standards Mapping Tab -->
    <div v-if="activeTab === 'standards-mapping'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">Compliance Standards</h2>
      </div>
      <div v-if="loadingStandards" class="loading-state">Loading standards...</div>
      <div v-else-if="standardsError" class="error-state">{{ standardsError }}</div>
      <div v-else-if="standards.length === 0" class="empty-state">
        <p>No compliance standards available</p>
      </div>
      <div v-else class="standards-grid">
        <div v-for="standard in standards" :key="standard.id" class="standard-card">
          <div class="standard-header">
            <h3 class="standard-name">{{ standard.name }}</h3>
            <span class="standard-version">{{ standard.version }}</span>
          </div>
          <p class="standard-description">{{ standard.description }}</p>
          <div class="standard-mappings">
            <span class="mapping-count">{{ getMappingCount(standard.id) }} policy mappings</span>
          </div>
          <div class="standard-actions">
            <button @click="viewMappings(standard.id)" class="action-btn edit-btn">View Mappings</button>
            <button @click="createMapping(standard.id)" class="action-btn enable-btn">Add Mapping</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Data Contracts Tab -->
    <div v-if="activeTab === 'data-contracts'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">Data Contracts Configuration</h2>
        <button @click="showCreateDataContractModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Contract
        </button>
      </div>
      <div class="config-sections">
        <div class="config-section">
          <h3 class="config-section-title">Contract Registry</h3>
          <p class="config-description">Manage registered data contracts and their versions</p>
          <div v-if="dataContracts.length === 0" class="empty-state">
            <p>No data contracts registered</p>
          </div>
          <div v-else class="config-list">
            <div v-for="contract in dataContracts" :key="contract.id" class="config-item">
              <div class="config-item-header">
                <h4>{{ contract.name }}</h4>
                <span class="config-version">v{{ contract.version }}</span>
              </div>
              <p class="config-description">{{ contract.description }}</p>
            </div>
          </div>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Baseline Schemas</h3>
          <p class="config-description">Define baseline schemas for contract validation</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Classification Policies</h3>
          <p class="config-description">Configure PII and data classification policies</p>
        </div>
      </div>
    </div>

    <!-- Salesforce Baselines Tab -->
    <div v-if="activeTab === 'salesforce'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">Salesforce Baselines</h2>
        <button @click="showCreateSalesforceBaselineModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
      <div class="config-sections">
        <div class="config-section">
          <h3 class="config-section-title">Baseline Metadata</h3>
          <p class="config-description">Manage baseline Salesforce metadata configurations</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Permission Sets</h3>
          <p class="config-description">Define expected permission set configurations</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Profile Configs</h3>
          <p class="config-description">Configure baseline profile settings</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Sharing Model</h3>
          <p class="config-description">Define expected sharing model configurations</p>
        </div>
      </div>
    </div>

    <!-- Elastic Baselines Tab -->
    <div v-if="activeTab === 'elastic'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">Elastic Baselines</h2>
        <button @click="showCreateElasticBaselineModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
      <div class="config-sections">
        <div class="config-section">
          <h3 class="config-section-title">Cluster Settings Baseline</h3>
          <p class="config-description">Define baseline cluster settings configurations</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Index Templates</h3>
          <p class="config-description">Manage baseline index template configurations</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">ILM Policies</h3>
          <p class="config-description">Configure baseline Index Lifecycle Management policies</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Role Definitions</h3>
          <p class="config-description">Define baseline Elasticsearch role configurations</p>
        </div>
      </div>
    </div>

    <!-- IDP / Kubernetes Baselines Tab -->
    <div v-if="activeTab === 'idp-platform'" class="tab-content">
      <div class="section-header">
        <h2 class="section-title">IDP / Kubernetes Baselines</h2>
        <button @click="showCreateIDPBaselineModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
      <div class="config-sections">
        <div class="config-section">
          <h3 class="config-section-title">Golden Path Templates</h3>
          <p class="config-description">Manage golden path service templates</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Pod Security Standards</h3>
          <p class="config-description">Configure Kubernetes Pod Security Standards</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Approved Registries</h3>
          <p class="config-description">Define approved container image registries</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Allowed Sidecars</h3>
          <p class="config-description">Configure approved sidecar containers</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Cluster-wide Policies</h3>
          <p class="config-description">Manage cluster-wide policy configurations</p>
        </div>
        <div class="config-section">
          <h3 class="config-section-title">Network Policy Baselines</h3>
          <p class="config-description">Define baseline network policy configurations</p>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal || editingPolicy" class="modal-overlay" @click="closeModal">
          <div class="modal-content policy-editor" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Shield class="modal-title-icon" />
                <h2>{{ editingPolicy ? 'Edit Policy' : 'Create Policy' }}</h2>
              </div>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="savePolicy" class="policy-form">
                <!-- Editor Tabs -->
                <div class="editor-tabs">
                  <button
                    type="button"
                    @click="editorTab = 'basic'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'basic' }"
                  >
                    Basic Info
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'rules'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'rules' }"
                  >
                    {{ policyForm.type === 'rbac' ? 'Rules' : 'Conditions' }}
                  </button>
                  <button
                    type="button"
                    @click="editorTab = 'preview'"
                    class="editor-tab"
                    :class="{ active: editorTab === 'preview' }"
                  >
                    Preview
                  </button>
                </div>

                <!-- Basic Info Tab -->
                <div v-if="editorTab === 'basic'" class="editor-content">
                  <div class="form-group">
                    <label>Policy Name</label>
                    <input v-model="policyForm.name" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Description</label>
                    <textarea v-model="policyForm.description" rows="3"></textarea>
                  </div>
                    <div class="form-row">
                    <div class="form-group">
                      <label>Policy Type</label>
                      <Dropdown
                        v-model="policyForm.type"
                        :options="policyTypeOptions"
                        placeholder="Select type..."
                      />
                    </div>
                    <div class="form-group">
                      <label>Version</label>
                      <input v-model="policyForm.version" type="text" required />
                    </div>
                  </div>
                  <div v-if="policyForm.type === 'abac'" class="form-row">
                    <div class="form-group">
                      <label>Effect</label>
                      <Dropdown
                        v-model="policyForm.effect"
                        :options="effectOptions"
                        placeholder="Select effect..."
                      />
                    </div>
                    <div class="form-group">
                      <label>Priority</label>
                      <input v-model.number="policyForm.priority" type="number" min="0" />
                      <small>Higher priority policies are evaluated first</small>
                    </div>
                  </div>
                  <div class="form-group">
                    <label>Status</label>
                    <Dropdown
                      v-model="policyForm.status"
                      :options="policyStatusOptions"
                      placeholder="Select status..."
                    />
                  </div>
                </div>

                <!-- Rules/Conditions Tab -->
                <div v-if="editorTab === 'rules'" class="editor-content">
                  <!-- RBAC Rules -->
                  <div v-if="policyForm.type === 'rbac'">
                    <div class="section-header">
                      <h3>Policy Rules</h3>
                      <button type="button" @click="addRBACRule" class="btn-add">
                        <Plus class="btn-icon" />
                        Add Rule
                      </button>
                    </div>
                    <div class="rules-list">
                      <div
                        v-for="(rule, index) in policyForm.rules"
                        :key="index"
                        class="rule-card"
                      >
                        <div class="rule-header">
                          <h4>Rule {{ index + 1 }}</h4>
                          <button
                            type="button"
                            @click="removeRule(index)"
                            class="btn-remove"
                          >
                            <Trash2 class="icon" />
                          </button>
                        </div>
                        <div class="form-group">
                          <label>Rule ID</label>
                          <input
                            v-model="rule.id"
                            type="text"
                            placeholder="e.g., admin-full-access"
                            required
                          />
                        </div>
                        <div class="form-group">
                          <label>Description</label>
                          <textarea
                            v-model="rule.description"
                            rows="2"
                            placeholder="Describe what this rule does"
                          ></textarea>
                        </div>
                        <div class="form-group">
                          <label>Effect</label>
                          <Dropdown
                            v-model="rule.effect"
                            :options="effectOptions"
                            placeholder="Select effect..."
                          />
                        </div>
                        <div class="form-group">
                          <label>Conditions</label>
                          <div class="conditions-list">
                            <div
                              v-for="(value, key, condIndex) in rule.conditions"
                              :key="condIndex"
                              class="condition-item"
                            >
                              <input
                                v-model="conditionKeys[index][condIndex]"
                                type="text"
                                placeholder="e.g., subject.role"
                                class="condition-key"
                                @input="updateConditionKey(index, condIndex, $event)"
                              />
                              <span class="condition-separator">:</span>
                              <input
                                v-model="conditionValues[index][condIndex]"
                                type="text"
                                placeholder="e.g., admin or [admin, viewer]"
                                class="condition-value"
                                @input="updateConditionValue(index, condIndex, $event)"
                              />
                              <button
                                type="button"
                                @click="removeCondition(index, condIndex)"
                                class="btn-remove-small"
                              >
                                <X class="icon" />
                              </button>
                            </div>
                            <button
                              type="button"
                              @click="addCondition(index)"
                              class="btn-add-condition"
                            >
                              <Plus class="icon" />
                              Add Condition
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <!-- ABAC Conditions -->
                  <div v-if="policyForm.type === 'abac'">
                    <div class="section-header">
                      <h3>Policy Conditions</h3>
                      <button type="button" @click="addABACCondition" class="btn-add">
                        <Plus class="btn-icon" />
                        Add Condition
                      </button>
                    </div>
                    <div class="conditions-list">
                      <div
                        v-for="(condition, index) in policyForm.conditions"
                        :key="index"
                        class="condition-card"
                      >
                        <div class="condition-header">
                          <h4>Condition {{ index + 1 }}</h4>
                          <button
                            type="button"
                            @click="removeABACCondition(index)"
                            class="btn-remove"
                          >
                            <Trash2 class="icon" />
                          </button>
                        </div>
                        <div class="form-group">
                          <label>Attribute</label>
                          <Dropdown
                            v-model="condition.attribute"
                            :options="attributeOptions"
                            placeholder="Select attribute..."
                          />
                        </div>
                        <div class="form-row">
                          <div class="form-group">
                            <label>Operator</label>
                            <Dropdown
                              v-model="condition.operator"
                              :options="operatorOptions"
                              placeholder="Select operator..."
                            />
                          </div>
                          <div class="form-group">
                            <label>Logical Operator</label>
                            <Dropdown
                              v-model="condition.logicalOperator"
                              :options="logicalOperatorOptions"
                              placeholder="None (First Condition)"
                            />
                            <small>How to combine with previous condition</small>
                          </div>
                        </div>
                        <div class="form-group">
                          <label>Value</label>
                          <input
                            v-model="condition.value"
                            type="text"
                            placeholder="e.g., admin or [admin, viewer] or {{resource.department}}"
                            required
                          />
                          <small>Use {{resource.attribute}} or {{subject.attribute}} for dynamic values</small>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Preview Tab -->
                <div v-if="editorTab === 'preview'" class="editor-content">
                  <div class="preview-section">
                    <h3>Policy Preview</h3>
                    <pre class="policy-preview">{{ JSON.stringify(getPolicyJSON(), null, 2) }}</pre>
                  </div>
                  <div class="preview-section">
                    <h3>Validation</h3>
                    <div v-if="validationErrors.length > 0" class="validation-errors">
                      <div
                        v-for="(error, index) in validationErrors"
                        :key="index"
                        class="validation-error"
                      >
                        <AlertTriangle class="error-icon" />
                        {{ error }}
                      </div>
                    </div>
                    <div v-else class="validation-success">
                      <CheckCircle2 class="success-icon" />
                      Policy is valid
                    </div>
                  </div>
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="validationErrors.length > 0">
                    Save Policy
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  Shield,
  Plus,
  Edit,
  History,
  TestTube,
  X,
  FileText,
  ShieldCheck,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  Settings,
  Database,
  Cloud,
  Server,
  Container
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies' }
];

const activeTab = ref<'access-control' | 'data-classification' | 'platform-config' | 'exceptions' | 'standards-mapping' | 'data-contracts' | 'salesforce' | 'elastic' | 'idp-platform'>('access-control');
const searchQuery = ref('');
const filterType = ref('');
const filterStatus = ref('');
const showCreateModal = ref(false);
const editingPolicy = ref<string | null>(null);
const editorTab = ref<'basic' | 'rules' | 'preview'>('basic');
const loading = ref(false);
const error = ref<string | null>(null);

// Policies data from API
const policies = ref<any[]>([]);
const tests = ref<any[]>([]);
const testCountsByPolicy = ref<Record<string, number>>({});

// Data Classification data
const levels = ref<any[]>([]);
const rules = ref<any[]>([]);
const loadingLevels = ref(false);
const loadingRules = ref(false);
const levelsError = ref<string | null>(null);
const rulesError = ref<string | null>(null);
const ruleSearchQuery = ref('');
const ruleFilterLevel = ref('');
const ruleFilterEnabled = ref('');
const showCreateLevelModal = ref(false);
const showCreateRuleModal = ref(false);
const editingLevel = ref<any>(null);
const editingRule = ref<any>(null);
const showCreateBaselineModal = ref(false);
const showCreateExceptionModal = ref(false);
const showCreateAllowlistModal = ref(false);
const showCreateDataContractModal = ref(false);
const showCreateSalesforceBaselineModal = ref(false);
const showCreateElasticBaselineModal = ref(false);
const showCreateIDPBaselineModal = ref(false);

// Domain-specific configuration data
const dataContracts = ref<any[]>([]);
const salesforceBaselines = ref<any[]>([]);
const elasticBaselines = ref<any[]>([]);
const idpBaselines = ref<any[]>([]);

const tabs = computed(() => [
  { id: 'access-control', label: 'Access Control', icon: Shield, badge: policies.value.length },
  { id: 'data-classification', label: 'Data Classification', icon: FileText },
  { id: 'platform-config', label: 'Platform Config', icon: Settings },
  { id: 'exceptions', label: 'Exceptions', icon: AlertTriangle },
  { id: 'standards-mapping', label: 'Standards Mapping', icon: CheckCircle2 },
  { id: 'data-contracts', label: 'Data Contracts', icon: Database },
  { id: 'salesforce', label: 'Salesforce Baselines', icon: Cloud },
  { id: 'elastic', label: 'Elastic Baselines', icon: Server },
  { id: 'idp-platform', label: 'IDP / Kubernetes', icon: Container }
]);

const levelFilterOptions = computed(() => [
  { label: 'All Levels', value: '' },
  ...levels.value.map(level => ({ label: level.name, value: level.id }))
]);

const enabledFilterOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Enabled', value: 'true' },
  { label: 'Disabled', value: 'false' },
];

const filteredRules = computed(() => {
  let filtered = rules.value;
  if (ruleFilterLevel.value) {
    filtered = filtered.filter(r => r.levelId === ruleFilterLevel.value);
  }
  if (ruleFilterEnabled.value) {
    const enabled = ruleFilterEnabled.value === 'true';
    filtered = filtered.filter(r => r.enabled === enabled);
  }
  if (ruleSearchQuery.value) {
    const query = ruleSearchQuery.value.toLowerCase();
    filtered = filtered.filter(r =>
      r.name.toLowerCase().includes(query) ||
      r.description?.toLowerCase().includes(query) ||
      r.value.toLowerCase().includes(query)
    );
  }
  return filtered;
});

const getLevelName = (levelId: string): string => {
  const level = levels.value.find(l => l.id === levelId);
  return level?.name || 'Unknown';
};

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'RBAC', value: 'rbac' },
  { label: 'ABAC', value: 'abac' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Active', value: 'active' },
  { label: 'Draft', value: 'draft' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const filteredPolicies = computed(() => {
  let filtered = policies.value;

  // Filter by tab (only for access-control tab)
  if (activeTab.value === 'access-control') {
    // Show all policies (RBAC/ABAC) - can be further filtered by type dropdown
    if (filterType.value === 'rbac') {
      filtered = filtered.filter(p => p.type === 'rbac');
    } else if (filterType.value === 'abac') {
      filtered = filtered.filter(p => p.type === 'abac');
    }
  } else {
    // For other tabs, return empty (they have their own data)
    return [];
  }

  // Apply other filters
  return filtered.filter(policy => {
    const matchesSearch = policy.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         policy.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || policy.type === filterType.value;
    const matchesStatus = !filterStatus.value || policy.status === filterStatus.value;
    return matchesSearch && matchesType && matchesStatus;
  });
});

const policyForm = ref({
  name: '',
  description: '',
  type: 'rbac',
  version: '1.0.0',
  status: 'draft',
  effect: 'allow',
  priority: 100,
  rules: [] as any[],
  conditions: [] as any[]
});

// For RBAC condition management
const conditionKeys = ref<Record<number, string[]>>({});
const conditionValues = ref<Record<number, string[]>>({});

const viewPolicy = (id: string) => {
  router.push(`/policies/${id}`);
};

const editPolicy = async (id: string) => {
  try {
    loading.value = true;
    const response = await axios.get(`/api/policies/${id}`);
    const policy = response.data;
    
    editingPolicy.value = id;
    editorTab.value = 'basic';
    policyForm.value = {
      name: policy.name,
      description: policy.description || '',
      type: policy.type,
      version: policy.version,
      status: policy.status,
      effect: policy.effect || 'allow',
      priority: policy.priority || 100,
      rules: policy.rules || [],
      conditions: policy.conditions || []
    };
    initializeConditionArrays();
    showCreateModal.value = true;
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load policy';
    console.error('Error loading policy:', err);
  } finally {
    loading.value = false;
  }
};

const viewVersions = (id: string) => {
  router.push(`/policies/${id}?tab=changelog`);
};

const testPolicy = (id: string) => {
  router.push(`/policies/${id}?tab=overview`);
  // In a real app, this might trigger a test modal or navigate to tests page
};

const viewTestsUsingPolicy = (policyId: string) => {
  router.push(`/tests/individual?policyId=${policyId}`);
};

const loadPolicies = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/policies');
    policies.value = response.data.map((p: any) => ({
      ...p,
      lastUpdated: new Date(p.updatedAt),
      ruleCount: p.ruleCount || (p.type === 'rbac' ? (p.rules?.length || 0) : (p.conditions?.length || 0))
    }));
    await loadTests();
  } catch (err: any) {
    error.value = err.message || 'Failed to load policies';
    console.error('Error loading policies:', err);
  } finally {
    loading.value = false;
  }
};

const loadTests = async () => {
  try {
    const response = await axios.get('/api/v1/tests?testType=access-control');
    tests.value = response.data;
    
    // Count tests per policy
    testCountsByPolicy.value = {};
    policies.value.forEach(policy => {
      const count = tests.value.filter(test => 
        test.testType === 'access-control' && 
        test.policyIds && 
        test.policyIds.includes(policy.id)
      ).length;
      testCountsByPolicy.value[policy.id] = count;
    });
  } catch (err) {
    console.error('Error loading tests:', err);
  }
};

const getTestCount = (policyId: string): number => {
  return testCountsByPolicy.value[policyId] || 0;
};

const savePolicy = async () => {
  if (validationErrors.value.length > 0) {
    editorTab.value = 'preview';
    return;
  }
  
  try {
    loading.value = true;
    error.value = null;
    
    const policyData = {
      name: policyForm.value.name,
      description: policyForm.value.description,
      type: policyForm.value.type,
      version: policyForm.value.version,
      status: policyForm.value.status,
      effect: policyForm.value.effect,
      priority: policyForm.value.priority,
      rules: policyForm.value.rules,
      conditions: policyForm.value.conditions,
    };
    
    if (editingPolicy.value) {
      await axios.patch(`/api/policies/${editingPolicy.value}`, policyData);
    } else {
      await axios.post('/api/policies', policyData);
    }
    
    await loadPolicies();
    closeModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to save policy';
    console.error('Error saving policy:', err);
  } finally {
    loading.value = false;
  }
};

const deletePolicy = async (id: string) => {
  if (!confirm('Are you sure you want to delete this policy?')) {
    return;
  }
  
  try {
    loading.value = true;
    await axios.delete(`/api/policies/${id}`);
    await loadPolicies();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to delete policy';
    console.error('Error deleting policy:', err);
  } finally {
    loading.value = false;
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingPolicy.value = null;
  editorTab.value = 'basic';
  policyForm.value = {
    name: '',
    description: '',
    type: 'rbac',
    version: '1.0.0',
    status: 'draft',
    effect: 'allow',
    priority: 100,
    rules: [],
    conditions: []
  };
  conditionKeys.value = {};
  conditionValues.value = {};
};

// RBAC Rule Management
const addRBACRule = () => {
  const newRule = {
    id: `rule-${Date.now()}`,
    description: '',
    effect: 'allow',
    conditions: {}
  };
  policyForm.value.rules.push(newRule);
  const index = policyForm.value.rules.length - 1;
  conditionKeys.value[index] = [];
  conditionValues.value[index] = [];
};

const removeRule = (index: number) => {
  policyForm.value.rules.splice(index, 1);
  delete conditionKeys.value[index];
  delete conditionValues.value[index];
  // Reindex
  const newKeys: Record<number, string[]> = {};
  const newValues: Record<number, string[]> = {};
  Object.keys(conditionKeys.value).forEach((key, i) => {
    newKeys[i] = conditionKeys.value[Number(key)];
    newValues[i] = conditionValues.value[Number(key)];
  });
  conditionKeys.value = newKeys;
  conditionValues.value = newValues;
};

const addCondition = (ruleIndex: number) => {
  if (!conditionKeys.value[ruleIndex]) {
    conditionKeys.value[ruleIndex] = [];
    conditionValues.value[ruleIndex] = [];
  }
  conditionKeys.value[ruleIndex].push('');
  conditionValues.value[ruleIndex].push('');
  updateRuleConditions(ruleIndex);
};

const removeCondition = (ruleIndex: number, condIndex: number) => {
  conditionKeys.value[ruleIndex].splice(condIndex, 1);
  conditionValues.value[ruleIndex].splice(condIndex, 1);
  updateRuleConditions(ruleIndex);
};

const updateConditionKey = (ruleIndex: number, condIndex: number, event: Event) => {
  const target = event.target as HTMLInputElement;
  conditionKeys.value[ruleIndex][condIndex] = target.value;
  updateRuleConditions(ruleIndex);
};

const updateConditionValue = (ruleIndex: number, condIndex: number, event: Event) => {
  const target = event.target as HTMLInputElement;
  conditionValues.value[ruleIndex][condIndex] = target.value;
  updateRuleConditions(ruleIndex);
};

const updateRuleConditions = (ruleIndex: number) => {
  const conditions: Record<string, any> = {};
  const keys = conditionKeys.value[ruleIndex] || [];
  const values = conditionValues.value[ruleIndex] || [];
  
  keys.forEach((key, index) => {
    if (key && values[index]) {
      const value = values[index];
      // Try to parse as array if it looks like one
      if (value.startsWith('[') && value.endsWith(']')) {
        try {
          conditions[key] = JSON.parse(value);
        } catch {
          conditions[key] = value;
        }
      } else {
        conditions[key] = value;
      }
    }
  });
  
  policyForm.value.rules[ruleIndex].conditions = conditions;
};

const initializeConditionArrays = () => {
  policyForm.value.rules.forEach((rule, index) => {
    const keys = Object.keys(rule.conditions);
    const values = Object.values(rule.conditions);
    conditionKeys.value[index] = keys;
    conditionValues.value[index] = values.map(v => 
      Array.isArray(v) ? JSON.stringify(v) : String(v)
    );
  });
};

// ABAC Condition Management
const addABACCondition = () => {
  policyForm.value.conditions.push({
    attribute: '',
    operator: 'equals',
    value: '',
    logicalOperator: ''
  });
};

const removeABACCondition = (index: number) => {
  policyForm.value.conditions.splice(index, 1);
};

const handleTypeChange = () => {
  if (policyForm.value.type === 'rbac') {
    if (policyForm.value.rules.length === 0) {
      addRBACRule();
    }
  } else {
    if (policyForm.value.conditions.length === 0) {
      addABACCondition();
    }
  }
};

// Validation
const validationErrors = computed(() => {
  const errors: string[] = [];
  
  if (!policyForm.value.name) {
    errors.push('Policy name is required');
  }
  
  if (policyForm.value.type === 'rbac') {
    if (policyForm.value.rules.length === 0) {
      errors.push('At least one rule is required for RBAC policies');
    }
    policyForm.value.rules.forEach((rule, index) => {
      if (!rule.id) {
        errors.push(`Rule ${index + 1}: ID is required`);
      }
      if (Object.keys(rule.conditions).length === 0) {
        errors.push(`Rule ${index + 1}: At least one condition is required`);
      }
    });
  } else {
    if (policyForm.value.conditions.length === 0) {
      errors.push('At least one condition is required for ABAC policies');
    }
    policyForm.value.conditions.forEach((condition, index) => {
      if (!condition.attribute) {
        errors.push(`Condition ${index + 1}: Attribute is required`);
      }
      if (!condition.operator) {
        errors.push(`Condition ${index + 1}: Operator is required`);
      }
      if (!condition.value) {
        errors.push(`Condition ${index + 1}: Value is required`);
      }
    });
  }
  
  return errors;
});

// Policy JSON Generation
const getPolicyJSON = () => {
  if (policyForm.value.type === 'rbac') {
    return {
      name: policyForm.value.name,
      version: policyForm.value.version,
      rules: policyForm.value.rules.map(rule => ({
        id: rule.id,
        description: rule.description,
        effect: rule.effect,
        conditions: rule.conditions
      }))
    };
  } else {
    return {
      id: editingPolicy.value || `policy-${Date.now()}`,
      name: policyForm.value.name,
      description: policyForm.value.description,
      effect: policyForm.value.effect,
      priority: policyForm.value.priority,
      conditions: policyForm.value.conditions
    };
  }
};

// Dropdown options
const policyTypeOptions = computed(() => [
  { label: 'RBAC', value: 'rbac' },
  { label: 'ABAC', value: 'abac' }
]);

const effectOptions = computed(() => [
  { label: 'Allow', value: 'allow' },
  { label: 'Deny', value: 'deny' }
]);

const policyStatusOptions = computed(() => [
  { label: 'Draft', value: 'draft' },
  { label: 'Active', value: 'active' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const attributeOptions = computed(() => ({
  'Subject Attributes': [
    { label: 'subject.department', value: 'subject.department' },
    { label: 'subject.clearanceLevel', value: 'subject.clearanceLevel' },
    { label: 'subject.projectAccess', value: 'subject.projectAccess' },
    { label: 'subject.dataClassification', value: 'subject.dataClassification' },
    { label: 'subject.location', value: 'subject.location' },
    { label: 'subject.employmentType', value: 'subject.employmentType' },
    { label: 'subject.certifications', value: 'subject.certifications' }
  ],
  'Resource Attributes': [
    { label: 'resource.dataClassification', value: 'resource.dataClassification' },
    { label: 'resource.department', value: 'resource.department' },
    { label: 'resource.project', value: 'resource.project' },
    { label: 'resource.region', value: 'resource.region' },
    { label: 'resource.requiresCertification', value: 'resource.requiresCertification' },
    { label: 'resource.minClearanceLevel', value: 'resource.minClearanceLevel' }
  ],
  'Context Attributes': [
    { label: 'context.location', value: 'context.location' },
    { label: 'context.timeOfDay', value: 'context.timeOfDay' },
    { label: 'context.ipAddress', value: 'context.ipAddress' }
  ]
}));

const operatorOptions = computed(() => [
  { label: 'Equals', value: 'equals' },
  { label: 'Not Equals', value: 'notEquals' },
  { label: 'In', value: 'in' },
  { label: 'Not In', value: 'notIn' },
  { label: 'Contains', value: 'contains' },
  { label: 'Starts With', value: 'startsWith' },
  { label: 'Ends With', value: 'endsWith' },
  { label: 'Regex Match', value: 'regex' },
  { label: 'Greater Than', value: 'greaterThan' },
  { label: 'Less Than', value: 'lessThan' }
]);

const logicalOperatorOptions = computed(() => [
  { label: 'None (First Condition)', value: '' },
  { label: 'AND', value: 'AND' },
  { label: 'OR', value: 'OR' }
]);

// Watch for type changes to initialize appropriate structure
watch(() => policyForm.value.type, () => {
  if (policyForm.value.type === 'rbac' && policyForm.value.rules.length === 0) {
    addRBACRule();
  } else if (policyForm.value.type === 'abac' && policyForm.value.conditions.length === 0) {
    addABACCondition();
  }
});

const formatDate = (date: Date | string): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffDays = Math.floor((now.getTime() - dateObj.getTime()) / (24 * 60 * 60 * 1000));
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  if (diffDays < 7) return `${diffDays} days ago`;
  return dateObj.toLocaleDateString();
};

// Platform Config data
const baselines = ref<any[]>([]);
const loadingBaselines = ref(false);
const baselinesError = ref<string | null>(null);

// Exceptions data
const exceptions = ref<any[]>([]);
const allowlists = ref<any[]>([]);
const loadingExceptions = ref(false);
const loadingAllowlists = ref(false);
const exceptionsError = ref<string | null>(null);
const allowlistsError = ref<string | null>(null);

// Standards Mapping data
const standards = ref<any[]>([]);
const mappings = ref<any[]>([]);
const loadingStandards = ref(false);
const loadingMappings = ref(false);
const standardsError = ref<string | null>(null);
const mappingsError = ref<string | null>(null);

const loadLevels = async () => {
  loadingLevels.value = true;
  levelsError.value = null;
  try {
    const response = await axios.get('/api/v1/data-classification/levels');
    levels.value = response.data || [];
  } catch (err: any) {
    levelsError.value = err.response?.data?.message || 'Failed to load classification levels';
    console.error('Error loading levels:', err);
  } finally {
    loadingLevels.value = false;
  }
};

const loadRules = async () => {
  loadingRules.value = true;
  rulesError.value = null;
  try {
    const response = await axios.get('/api/v1/data-classification/rules');
    rules.value = response.data || [];
  } catch (err: any) {
    rulesError.value = err.response?.data?.message || 'Failed to load classification rules';
    console.error('Error loading rules:', err);
  } finally {
    loadingRules.value = false;
  }
};

const editLevel = (level: any) => {
  editingLevel.value = { ...level };
  showCreateLevelModal.value = true;
};

const deleteLevel = async (id: string) => {
  if (confirm('Are you sure you want to delete this classification level? This will also delete all associated rules.')) {
    try {
      await axios.delete(`/api/v1/data-classification/levels/${id}`);
      await loadLevels();
      await loadRules();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete level');
      console.error('Error deleting level:', err);
    }
  }
};

const editRule = (rule: any) => {
  editingRule.value = { ...rule };
  showCreateRuleModal.value = true;
};

const toggleRule = async (rule: any) => {
  try {
    await axios.put(`/api/v1/data-classification/rules/${rule.id}`, {
      enabled: !rule.enabled
    });
    await loadRules();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to toggle rule');
    console.error('Error toggling rule:', err);
  }
};

const deleteRule = async (id: string) => {
  if (confirm('Are you sure you want to delete this classification rule?')) {
    try {
      await axios.delete(`/api/v1/data-classification/rules/${id}`);
      await loadRules();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete rule');
      console.error('Error deleting rule:', err);
    }
  }
};

const loadBaselines = async () => {
  loadingBaselines.value = true;
  baselinesError.value = null;
  try {
    const response = await axios.get('/api/v1/platform-config/baselines');
    baselines.value = response.data || [];
  } catch (err: any) {
    baselinesError.value = err.response?.data?.message || 'Failed to load baselines';
    console.error('Error loading baselines:', err);
  } finally {
    loadingBaselines.value = false;
  }
};

const loadExceptions = async () => {
  loadingExceptions.value = true;
  exceptionsError.value = null;
  try {
    const response = await axios.get('/api/v1/exceptions');
    exceptions.value = response.data || [];
  } catch (err: any) {
    exceptionsError.value = err.response?.data?.message || 'Failed to load exceptions';
    console.error('Error loading exceptions:', err);
  } finally {
    loadingExceptions.value = false;
  }
};

const loadAllowlists = async () => {
  loadingAllowlists.value = true;
  allowlistsError.value = null;
  try {
    const response = await axios.get('/api/v1/exceptions/allowlists');
    allowlists.value = response.data || [];
  } catch (err: any) {
    allowlistsError.value = err.response?.data?.message || 'Failed to load allowlists';
    console.error('Error loading allowlists:', err);
  } finally {
    loadingAllowlists.value = false;
  }
};

const loadStandards = async () => {
  loadingStandards.value = true;
  standardsError.value = null;
  try {
    const response = await axios.get('/api/v1/standards');
    standards.value = response.data || [];
  } catch (err: any) {
    standardsError.value = err.response?.data?.message || 'Failed to load standards';
    console.error('Error loading standards:', err);
  } finally {
    loadingStandards.value = false;
  }
};

const loadMappings = async () => {
  loadingMappings.value = true;
  mappingsError.value = null;
  try {
    // Load mappings for all standards
    const allMappings: any[] = [];
    for (const standard of standards.value) {
      try {
        const response = await axios.get(`/api/v1/standards/${standard.id}/mappings`);
        allMappings.push(...(response.data || []).map((m: any) => ({ ...m, standardId: standard.id })));
      } catch (err) {
        console.error(`Error loading mappings for ${standard.id}:`, err);
      }
    }
    mappings.value = allMappings;
  } catch (err: any) {
    mappingsError.value = err.response?.data?.message || 'Failed to load mappings';
    console.error('Error loading mappings:', err);
  } finally {
    loadingMappings.value = false;
  }
};

const compareBaseline = async (id: string) => {
  alert(`Compare baseline ${id} - Feature coming soon`);
};

const detectDrift = async (id: string) => {
  alert(`Detect drift for baseline ${id} - Feature coming soon`);
};

const deleteBaseline = async (id: string) => {
  if (confirm('Are you sure you want to delete this baseline?')) {
    try {
      await axios.delete(`/api/v1/platform-config/baselines/${id}`);
      await loadBaselines();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete baseline');
      console.error('Error deleting baseline:', err);
    }
  }
};

const approveException = async (id: string) => {
  try {
    await axios.post(`/api/v1/exceptions/${id}/approve`, { approver: 'current-user' });
    await loadExceptions();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to approve exception');
    console.error('Error approving exception:', err);
  }
};

const deleteException = async (id: string) => {
  if (confirm('Are you sure you want to delete this exception?')) {
    try {
      await axios.delete(`/api/v1/exceptions/${id}`);
      await loadExceptions();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete exception');
      console.error('Error deleting exception:', err);
    }
  }
};

const toggleAllowlist = async (allowlist: any) => {
  try {
    await axios.put(`/api/v1/exceptions/allowlists/${allowlist.id}`, {
      enabled: !allowlist.enabled
    });
    await loadAllowlists();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to toggle allowlist');
    console.error('Error toggling allowlist:', err);
  }
};

const deleteAllowlist = async (id: string) => {
  if (confirm('Are you sure you want to delete this allowlist?')) {
    try {
      await axios.delete(`/api/v1/exceptions/allowlists/${id}`);
      await loadAllowlists();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete allowlist');
      console.error('Error deleting allowlist:', err);
    }
  }
};

const getMappingCount = (standardId: string): number => {
  return mappings.value.filter(m => m.standardId === standardId).length;
};

const viewMappings = (standardId: string) => {
  alert(`View mappings for standard ${standardId} - Feature coming soon`);
};

const createMapping = (standardId: string) => {
  alert(`Create mapping for standard ${standardId} - Feature coming soon`);
};

// Watch for tab changes to load appropriate data
watch(activeTab, (newTab) => {
  if (newTab === 'access-control') {
    loadPolicies();
  } else if (newTab === 'data-classification') {
    loadLevels();
    loadRules();
  } else if (newTab === 'platform-config') {
    loadBaselines();
  } else if (newTab === 'exceptions') {
    loadExceptions();
    loadAllowlists();
  } else if (newTab === 'standards-mapping') {
    loadStandards();
    loadMappings();
  }
  // Clear filters when switching tabs
  searchQuery.value = '';
  filterType.value = '';
  filterStatus.value = '';
  ruleSearchQuery.value = '';
  ruleFilterLevel.value = '';
  ruleFilterEnabled.value = '';
});

// Load policies on mount
onMounted(() => {
  loadPolicies();
});
</script>

<style scoped>
.policies-page {
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

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 18px;
  height: 18px;
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
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-badge {
  padding: 2px 8px;
  border-radius: 10px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.policies-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.policy-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.policy-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.policy-header {
  margin-bottom: 16px;
}

.policy-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.policy-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.policy-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-draft {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-deprecated {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.policy-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.policy-description {
  font-size: 0.9rem;
  color: #a0aec0;
  line-height: 1.5;
  margin-bottom: 16px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.policy-stats {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.stat {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.stat-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.policy-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
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
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.edit-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.view-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.test-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.policy-editor {
  max-width: 900px;
  max-height: 90vh;
}

.editor-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.editor-tab {
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.editor-tab:hover {
  color: #4facfe;
}

.editor-tab.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.editor-content {
  max-height: 60vh;
  overflow-y: auto;
  padding-right: 8px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.section-header h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-add {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-add:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.rules-list,
.conditions-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.rule-card,
.condition-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.rule-header,
.condition-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.rule-header h4,
.condition-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-remove {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  color: #fc8181;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-remove:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.btn-remove .icon {
  width: 16px;
  height: 16px;
}

.condition-item {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.condition-key,
.condition-value {
  flex: 1;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
}

.condition-key:focus,
.condition-value:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.condition-separator {
  color: #718096;
  font-weight: 600;
}

.btn-remove-small {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  color: #fc8181;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-remove-small:hover {
  background: rgba(252, 129, 129, 0.1);
}

.btn-remove-small .icon {
  width: 14px;
  height: 14px;
}

.btn-add-condition {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  background: transparent;
  border: 1px dashed rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
  width: 100%;
  justify-content: center;
}

.btn-add-condition:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-add-condition .icon {
  width: 14px;
  height: 14px;
}

.preview-section {
  margin-bottom: 24px;
}

.preview-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.policy-preview {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #a0aec0;
  line-height: 1.6;
  max-height: 300px;
  overflow-y: auto;
}

.validation-errors {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.validation-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  color: #fc8181;
  font-size: 0.875rem;
}

.error-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.validation-success {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 8px;
  color: #22c55e;
  font-size: 0.875rem;
}

.success-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
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
  flex-shrink: 0;
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

.modal-body {
  padding: 24px;
}

.policy-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #4facfe;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 24px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: #a0aec0;
  font-size: 1rem;
}

.error-state {
  text-align: center;
  padding: 40px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 12px;
  margin-bottom: 24px;
}

.error-icon {
  width: 48px;
  height: 48px;
  color: #fc8181;
  margin: 0 auto 16px;
}

.error-state p {
  color: #fc8181;
  font-size: 1rem;
  margin-bottom: 16px;
}

.btn-retry {
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

/* Data Classification Styles */
.data-classification-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.classification-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.levels-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
}

.level-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-left: 4px solid;
  border-radius: 8px;
  padding: 16px;
}

.level-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.level-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.level-sensitivity {
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  text-transform: uppercase;
}

.level-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.level-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.rules-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.rule-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.rule-card.disabled {
  opacity: 0.6;
}

.rule-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.rule-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.rule-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.rule-status.enabled {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.rule-status.disabled {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
}

.rule-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.rule-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin: 12px 0;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
}

.rule-detail-item {
  display: flex;
  gap: 8px;
}

.detail-label {
  font-weight: 500;
  color: #a0aec0;
  min-width: 80px;
}

.detail-value {
  color: #ffffff;
}

.rule-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.action-btn {
  padding: 6px 12px;
  border-radius: 6px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: rgba(15, 20, 25, 0.6);
  color: #ffffff;
  cursor: pointer;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
  gap: 4px;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.action-icon {
  width: 14px;
  height: 14px;
}

.enable-btn {
  color: #22c55e;
  border-color: rgba(34, 197, 94, 0.3);
}

.disable-btn {
  color: #fbbf24;
  border-color: rgba(251, 191, 36, 0.3);
}

.delete-btn {
  color: #fc8181;
  border-color: rgba(252, 129, 129, 0.3);
}

/* Platform Config, Exceptions, Standards Mapping Styles */
.baselines-grid,
.standards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.baseline-card,
.standard-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.baseline-header,
.standard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.baseline-name,
.standard-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.baseline-environment,
.standard-version {
  padding: 4px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
}

.baseline-description,
.standard-description {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 8px 0;
}

.baseline-actions,
.standard-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}

.standard-mappings {
  margin: 8px 0;
  color: #a0aec0;
  font-size: 0.875rem;
}

.exceptions-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.exceptions-list,
.allowlists-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.exception-card,
.allowlist-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
}

.exception-header,
.allowlist-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.exception-name,
.allowlist-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.exception-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.exception-status.status-pending {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.exception-status.status-approved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.exception-status.status-rejected {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.exception-meta {
  display: flex;
  gap: 16px;
  margin: 8px 0;
  font-size: 0.875rem;
  color: #a0aec0;
}

.allowlist-details {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 8px 0;
  font-size: 0.875rem;
}

.exception-actions,
.allowlist-actions {
  display: flex;
  gap: 8px;
  margin-top: 12px;
}
</style>
