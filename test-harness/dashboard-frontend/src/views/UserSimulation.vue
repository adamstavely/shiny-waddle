<template>
  <div class="user-simulation-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">User Simulation</h1>
          <p class="page-description">Manage user roles, attributes, and generate test users</p>
        </div>
        <button @click="showCreateUserModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Generate Test Users
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

    <!-- User Roles Tab -->
    <div v-if="activeTab === 'roles'" class="tab-content">
      <div class="section-header">
        <h2>User Roles</h2>
        <button @click="showRoleModal = true" class="btn-secondary">
          <Plus class="btn-icon" />
          Add Role
        </button>
      </div>

      <div class="roles-grid">
        <div
          v-for="role in userRoles"
          :key="role.id"
          class="role-card"
        >
          <div class="role-header">
            <h3 class="role-name">{{ role.name }}</h3>
            <div class="role-actions">
              <button @click="editRole(role.id)" class="action-btn-icon">
                <Edit class="icon" />
              </button>
              <button @click="deleteRole(role.id)" class="action-btn-icon delete">
                <Trash2 class="icon" />
              </button>
            </div>
          </div>
          <div class="role-details">
            <div class="detail-item">
              <span class="detail-label">Permissions:</span>
              <div class="permissions-list">
                <span
                  v-for="perm in role.permissions"
                  :key="perm"
                  class="permission-badge"
                >
                  {{ perm }}
                </span>
              </div>
            </div>
            <div class="detail-item" v-if="role.description">
              <span class="detail-label">Description:</span>
              <span class="detail-value">{{ role.description }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Users with this role:</span>
              <span class="detail-value">{{ getUsersWithRole(role.name).length }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- User Attributes Tab -->
    <div v-if="activeTab === 'attributes'" class="tab-content">
      <div class="section-header">
        <h2>ABAC Attributes</h2>
        <button @click="showAttributeTemplateModal = true" class="btn-secondary">
          <Plus class="btn-icon" />
          Add Attribute Template
        </button>
      </div>

      <div class="attributes-section">
        <div class="attribute-templates">
          <h3>Attribute Templates</h3>
          <div class="templates-grid">
            <div
              v-for="template in attributeTemplates"
              :key="template.id"
              class="template-card"
            >
              <div class="template-header">
                <h4>{{ template.name }}</h4>
                <div class="template-actions">
                  <button @click="editTemplate(template.id)" class="action-btn-icon">
                    <Edit class="icon" />
                  </button>
                  <button @click="deleteTemplate(template.id)" class="action-btn-icon delete">
                    <Trash2 class="icon" />
                  </button>
                </div>
              </div>
              <div class="template-details">
                <div class="detail-item">
                  <span class="detail-label">Type:</span>
                  <span class="detail-value">{{ template.type }}</span>
                </div>
                <div class="detail-item" v-if="template.validationRules">
                  <span class="detail-label">Validation:</span>
                  <span class="detail-value">{{ template.validationRules }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="attribute-validation">
          <h3>Attribute Validation Rules</h3>
          <div class="validation-rules-list">
            <div
              v-for="rule in validationRules"
              :key="rule.id"
              class="rule-item"
            >
              <div class="rule-header">
                <span class="rule-attribute">{{ rule.attribute }}</span>
                <span class="rule-operator">{{ rule.operator }}</span>
                <span class="rule-value">{{ rule.value }}</span>
                <button @click="deleteValidationRule(rule.id)" class="action-btn-icon delete">
                  <Trash2 class="icon" />
                </button>
              </div>
            </div>
          </div>
          <button @click="showValidationRuleModal = true" class="btn-secondary">
            <Plus class="btn-icon" />
            Add Validation Rule
          </button>
        </div>
      </div>
    </div>

    <!-- Generated Users Tab -->
    <div v-if="activeTab === 'users'" class="tab-content">
      <div class="section-header">
        <h2>Generated Test Users</h2>
        <div class="header-actions">
          <button @click="exportUsers" class="btn-secondary">
            <Download class="btn-icon" />
            Export Users
          </button>
          <button @click="showCreateUserModal = true" class="btn-primary">
            <Plus class="btn-icon" />
            Generate New Users
          </button>
        </div>
      </div>

      <div class="filters">
        <input
          v-model="userSearchQuery"
          type="text"
          placeholder="Search users..."
          class="search-input"
        />
        <Dropdown
          v-model="userFilterRole"
          :options="roleFilterOptions"
          placeholder="All Roles"
          class="filter-dropdown"
        />
      </div>

      <div class="users-grid">
        <div
          v-for="user in filteredUsers"
          :key="user.id"
          class="user-card"
          @click="viewUserDetails(user.id)"
        >
          <div class="user-header">
            <div class="user-avatar">
              <User class="avatar-icon" />
            </div>
            <div class="user-info">
              <h3 class="user-name">{{ user.email }}</h3>
              <span class="user-role">{{ user.role }}</span>
            </div>
          </div>
          <div class="user-attributes">
            <div class="attribute-item" v-if="user.abacAttributes?.department">
              <span class="attr-label">Department:</span>
              <span class="attr-value">{{ user.abacAttributes.department }}</span>
            </div>
            <div class="attribute-item" v-if="user.abacAttributes?.clearanceLevel">
              <span class="attr-label">Clearance:</span>
              <span class="attr-value">{{ user.abacAttributes.clearanceLevel }}</span>
            </div>
            <div class="attribute-item" v-if="user.abacAttributes?.location">
              <span class="attr-label">Location:</span>
              <span class="attr-value">{{ user.abacAttributes.location }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Modals -->
    <RoleModal
      :show="showRoleModal || editingRole"
      :role="editingRoleData"
      @close="closeRoleModal"
      @save="saveRole"
    />

    <AttributeTemplateModal
      :show="showAttributeTemplateModal || editingTemplate"
      :template="editingTemplateData"
      @close="closeTemplateModal"
      @save="saveTemplate"
    />

    <ValidationRuleModal
      :show="showValidationRuleModal"
      @close="closeValidationRuleModal"
      @save="saveValidationRule"
    />

    <GenerateUsersModal
      :show="showCreateUserModal"
      :roles="userRoles"
      @close="closeCreateUserModal"
      @generate="generateUsers"
    />

    <UserDetailModal
      :show="showUserDetail"
      :user="selectedUser"
      @close="closeUserDetail"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  User,
  Plus,
  Edit,
  Trash2,
  Download,
  Shield,
  Settings,
  Users
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import RoleModal from '../components/RoleModal.vue';
import AttributeTemplateModal from '../components/AttributeTemplateModal.vue';
import ValidationRuleModal from '../components/ValidationRuleModal.vue';
import GenerateUsersModal from '../components/GenerateUsersModal.vue';
import UserDetailModal from '../components/UserDetailModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'User Simulation' }
];

const activeTab = ref<'roles' | 'attributes' | 'users'>('roles');
const userSearchQuery = ref('');
const userFilterRole = ref('');
const showRoleModal = ref(false);
const showAttributeTemplateModal = ref(false);
const showValidationRuleModal = ref(false);
const showCreateUserModal = ref(false);
const showUserDetail = ref(false);
const editingRole = ref<string | null>(null);
const editingTemplate = ref<string | null>(null);
const editingRoleData = ref<any>(null);
const editingTemplateData = ref<any>(null);
const selectedUser = ref<any>(null);

const tabs = computed(() => [
  { id: 'roles', label: 'User Roles', icon: Shield, badge: userRoles.value.length },
  { id: 'attributes', label: 'Attributes', icon: Settings, badge: attributeTemplates.value.length },
  { id: 'users', label: 'Generated Users', icon: Users, badge: generatedUsers.value.length }
]);

// User roles data
const userRoles = ref([
  {
    id: '1',
    name: 'admin',
    description: 'Full system access with all permissions',
    permissions: ['read', 'write', 'delete', 'export', 'manage-users', 'manage-policies']
  },
  {
    id: '2',
    name: 'researcher',
    description: 'Access to research data and analysis tools',
    permissions: ['read', 'write', 'analyze', 'export-research']
  },
  {
    id: '3',
    name: 'analyst',
    description: 'Read access with analysis capabilities',
    permissions: ['read', 'analyze']
  },
  {
    id: '4',
    name: 'viewer',
    description: 'Read-only access',
    permissions: ['read']
  }
]);

// Attribute templates
const attributeTemplates = ref([
  {
    id: '1',
    name: 'Department',
    type: 'string',
    validationRules: 'Must be one of: IT, Research, Analytics, Finance'
  },
  {
    id: '2',
    name: 'Clearance Level',
    type: 'enum',
    validationRules: 'Must be: low, medium, high, top-secret'
  },
  {
    id: '3',
    name: 'Project Access',
    type: 'array',
    validationRules: 'Array of project IDs'
  }
]);

// Validation rules
const validationRules = ref([
  {
    id: '1',
    attribute: 'clearanceLevel',
    operator: 'in',
    value: ['low', 'medium', 'high', 'top-secret']
  },
  {
    id: '2',
    attribute: 'department',
    operator: 'in',
    value: ['IT', 'Research', 'Analytics', 'Finance']
  }
]);

// Generated users
const generatedUsers = ref([
  {
    id: '1',
    email: 'admin@example.com',
    role: 'admin',
    abacAttributes: {
      department: 'IT',
      clearanceLevel: 'high',
      projectAccess: ['*'],
      location: 'headquarters',
      employmentType: 'full-time',
      certifications: ['security-admin']
    }
  },
  {
    id: '2',
    email: 'researcher@example.com',
    role: 'researcher',
    abacAttributes: {
      department: 'Research',
      clearanceLevel: 'medium',
      projectAccess: ['project-alpha', 'project-beta'],
      location: 'research-lab',
      employmentType: 'full-time'
    }
  }
]);

const roleFilterOptions = computed(() => [
  { label: 'All Roles', value: '' },
  ...userRoles.value.map(role => ({ label: role.name, value: role.name }))
]);

const filteredUsers = computed(() => {
  return generatedUsers.value.filter(user => {
    const matchesSearch = user.email.toLowerCase().includes(userSearchQuery.value.toLowerCase());
    const matchesRole = !userFilterRole.value || user.role === userFilterRole.value;
    return matchesSearch && matchesRole;
  });
});

function getUsersWithRole(roleName: string): any[] {
  return generatedUsers.value.filter(u => u.role === roleName);
}

function editRole(id: string) {
  const role = userRoles.value.find(r => r.id === id);
  if (role) {
    editingRole.value = id;
    editingRoleData.value = role;
    showRoleModal.value = true;
  }
}

function deleteRole(id: string) {
  if (confirm('Are you sure you want to delete this role?')) {
    const index = userRoles.value.findIndex(r => r.id === id);
    if (index !== -1) {
      userRoles.value.splice(index, 1);
    }
  }
}

function saveRole(roleData: any) {
  if (editingRole.value) {
    const index = userRoles.value.findIndex(r => r.id === editingRole.value);
    if (index !== -1) {
      userRoles.value[index] = { ...userRoles.value[index], ...roleData };
    }
  } else {
    userRoles.value.push({
      id: String(userRoles.value.length + 1),
      ...roleData
    });
  }
  closeRoleModal();
}

function closeRoleModal() {
  showRoleModal.value = false;
  editingRole.value = null;
  editingRoleData.value = null;
}

function editTemplate(id: string) {
  const template = attributeTemplates.value.find(t => t.id === id);
  if (template) {
    editingTemplate.value = id;
    editingTemplateData.value = template;
    showAttributeTemplateModal.value = true;
  }
}

function deleteTemplate(id: string) {
  if (confirm('Are you sure you want to delete this template?')) {
    const index = attributeTemplates.value.findIndex(t => t.id === id);
    if (index !== -1) {
      attributeTemplates.value.splice(index, 1);
    }
  }
}

function saveTemplate(templateData: any) {
  if (editingTemplate.value) {
    const index = attributeTemplates.value.findIndex(t => t.id === editingTemplate.value);
    if (index !== -1) {
      attributeTemplates.value[index] = { ...attributeTemplates.value[index], ...templateData };
    }
  } else {
    attributeTemplates.value.push({
      id: String(attributeTemplates.value.length + 1),
      ...templateData
    });
  }
  closeTemplateModal();
}

function closeTemplateModal() {
  showAttributeTemplateModal.value = false;
  editingTemplate.value = null;
  editingTemplateData.value = null;
}

function saveValidationRule(ruleData: any) {
  validationRules.value.push({
    id: String(validationRules.value.length + 1),
    ...ruleData
  });
  closeValidationRuleModal();
}

function closeValidationRuleModal() {
  showValidationRuleModal.value = false;
}

function deleteValidationRule(id: string) {
  const index = validationRules.value.findIndex(r => r.id === id);
  if (index !== -1) {
    validationRules.value.splice(index, 1);
  }
}

function generateUsers(config: any) {
  // Generate users based on config
  const newUsers = [];
  for (let i = 0; i < config.count; i++) {
    const role = userRoles.value.find(r => r.name === config.role);
    if (role) {
      newUsers.push({
        id: String(generatedUsers.value.length + i + 1),
        email: `${config.role}${i + 1}@example.com`,
        role: config.role,
        abacAttributes: generateAttributesForRole(config.role)
      });
    }
  }
  generatedUsers.value.push(...newUsers);
  closeCreateUserModal();
}

function generateAttributesForRole(role: string): any {
  const roleAttributes: Record<string, any> = {
    admin: {
      department: 'IT',
      clearanceLevel: 'high',
      projectAccess: ['*'],
      location: 'headquarters',
      employmentType: 'full-time',
      certifications: ['security-admin']
    },
    researcher: {
      department: 'Research',
      clearanceLevel: 'medium',
      projectAccess: ['project-alpha', 'project-beta'],
      location: 'research-lab',
      employmentType: 'full-time'
    },
    analyst: {
      department: 'Analytics',
      clearanceLevel: 'medium',
      projectAccess: ['project-alpha'],
      location: 'office',
      employmentType: 'full-time'
    },
    viewer: {
      department: 'General',
      clearanceLevel: 'low',
      projectAccess: [],
      location: 'office',
      employmentType: 'full-time'
    }
  };
  return roleAttributes[role] || {};
}

function closeCreateUserModal() {
  showCreateUserModal.value = false;
}

function viewUserDetails(id: string) {
  const user = generatedUsers.value.find(u => u.id === id);
  if (user) {
    selectedUser.value = user;
    showUserDetail.value = true;
  }
}

function closeUserDetail() {
  showUserDetail.value = false;
  selectedUser.value = null;
}

function exportUsers() {
  const dataStr = JSON.stringify(generatedUsers.value, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `test-users-${new Date().toISOString()}.json`;
  link.click();
  URL.revokeObjectURL(url);
}
</script>

<style scoped>
.user-simulation-page {
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

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
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

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
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

.tab-content {
  min-height: 400px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.roles-grid,
.users-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 24px;
}

.role-card,
.user-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.3s;
}

.user-card {
  cursor: pointer;
}

.user-card:hover,
.role-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.role-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.role-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.role-actions {
  display: flex;
  gap: 8px;
}

.action-btn-icon {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.action-btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-btn-icon.delete {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.action-btn-icon.delete:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.action-btn-icon .icon {
  width: 16px;
  height: 16px;
}

.role-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.75rem;
  color: #718096;
  font-weight: 500;
}

.detail-value {
  font-size: 0.875rem;
  color: #ffffff;
}

.permissions-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.permission-badge {
  padding: 4px 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.attributes-section {
  display: flex;
  flex-direction: column;
  gap: 32px;
}

.attribute-templates h3,
.attribute-validation h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.templates-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.template-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
}

.template-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.template-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.template-actions {
  display: flex;
  gap: 6px;
}

.template-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.validation-rules-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 16px;
}

.rule-item {
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.rule-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.rule-attribute {
  font-weight: 600;
  color: #4facfe;
}

.rule-operator {
  color: #a0aec0;
}

.rule-value {
  color: #ffffff;
  font-family: monospace;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-dropdown {
  min-width: 150px;
}

.user-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
}

.user-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: rgba(79, 172, 254, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
}

.avatar-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.user-info {
  flex: 1;
}

.user-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.user-role {
  padding: 2px 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.user-attributes {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.attribute-item {
  display: flex;
  justify-content: space-between;
  padding: 6px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.attribute-item:last-child {
  border-bottom: none;
}

.attr-label {
  font-size: 0.75rem;
  color: #718096;
}

.attr-value {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 500;
}
</style>

