<template>
  <div class="settings-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Settings</h1>
          <p class="page-description">Manage application settings, notifications, and security</p>
        </div>
      </div>
    </div>

    <!-- Settings Tabs -->
    <div class="settings-tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <!-- General Settings -->
    <div v-if="activeTab === 'general'" class="settings-content">
      <div class="settings-section">
        <h2 class="section-title">
          <Settings class="title-icon" />
          Application Settings
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Application Name</label>
            <input v-model="generalSettings.appName" type="text" placeholder="Sentinel Dashboard" />
          </div>
          <div class="setting-item">
            <label>Default Timezone</label>
            <Dropdown
              v-model="generalSettings.timezone"
              :options="timezoneOptions"
              placeholder="Select timezone..."
            />
          </div>
          <div class="setting-item">
            <label>Date Format</label>
            <Dropdown
              v-model="generalSettings.dateFormat"
              :options="dateFormatOptions"
              placeholder="Select format..."
            />
          </div>
          <div class="setting-item">
            <label>Items Per Page</label>
            <input v-model.number="generalSettings.itemsPerPage" type="number" min="10" max="100" />
          </div>
          <div class="setting-item">
            <label>Auto-refresh Interval (seconds)</label>
            <input v-model.number="generalSettings.autoRefreshInterval" type="number" min="0" />
            <small>Set to 0 to disable auto-refresh</small>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <User class="title-icon" />
          User Preferences
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Language</label>
            <Dropdown
              v-model="generalSettings.language"
              :options="languageOptions"
              placeholder="Select language..."
            />
          </div>
          <div class="setting-item">
            <label>Email Notifications</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="generalSettings.emailNotifications"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Enable email notifications</span>
              </label>
            </div>
          </div>
          <div class="setting-item">
            <label>Dashboard Default View</label>
            <Dropdown
              v-model="generalSettings.defaultView"
              :options="defaultViewOptions"
              placeholder="Select default view..."
            />
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <Settings class="title-icon" />
          Theme Settings
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Theme</label>
            <div class="theme-options">
              <button
                v-for="theme in themeOptions"
                :key="theme.value"
                @click="generalSettings.theme = theme.value"
                class="theme-button"
                :class="{ active: generalSettings.theme === theme.value }"
              >
                <span>{{ theme.label }}</span>
              </button>
            </div>
          </div>
          <div class="setting-item">
            <label>Accent Color</label>
            <div class="color-picker-group">
              <input v-model="generalSettings.accentColor" type="color" class="color-picker" />
              <input v-model="generalSettings.accentColor" type="text" class="color-input" />
            </div>
          </div>
          <div class="setting-item">
            <label>Compact Mode</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="generalSettings.compactMode"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Use compact layout</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Notification Settings -->
    <div v-if="activeTab === 'notifications'" class="settings-content">
      <div class="settings-section">
        <h2 class="section-title">
          <Mail class="title-icon" />
          Email Notifications
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>SMTP Server</label>
            <input v-model="notificationSettings.smtpServer" type="text" placeholder="smtp.example.com" />
          </div>
          <div class="setting-item">
            <label>SMTP Port</label>
            <input v-model.number="notificationSettings.smtpPort" type="number" placeholder="587" />
          </div>
          <div class="setting-item">
            <label>SMTP Username</label>
            <input v-model="notificationSettings.smtpUsername" type="text" placeholder="user@example.com" />
          </div>
          <div class="setting-item">
            <label>SMTP Password</label>
            <input v-model="notificationSettings.smtpPassword" type="password" placeholder="••••••••" />
          </div>
          <div class="setting-item">
            <label>From Email</label>
            <input v-model="notificationSettings.fromEmail" type="email" placeholder="noreply@example.com" />
          </div>
          <div class="setting-item">
            <label>Enable TLS</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="notificationSettings.enableTLS"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Use TLS encryption</span>
              </label>
            </div>
          </div>
          <div class="setting-item full-width">
            <button @click="testEmail" class="btn-secondary">Test Email Connection</button>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <MessageSquare class="title-icon" />
          Slack Integration
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Webhook URL</label>
            <input v-model="notificationSettings.slackWebhookUrl" type="url" placeholder="https://hooks.slack.com/services/..." />
            <small>Get your webhook URL from Slack App settings</small>
          </div>
          <div class="setting-item">
            <label>Channel</label>
            <input v-model="notificationSettings.slackChannel" type="text" placeholder="#alerts" />
          </div>
          <div class="setting-item">
            <label>Username</label>
            <input v-model="notificationSettings.slackUsername" type="text" placeholder="Sentinel Bot" />
          </div>
          <div class="setting-item">
            <label>Enable Slack Notifications</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="notificationSettings.slackEnabled"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Send notifications to Slack</span>
              </label>
            </div>
          </div>
          <div class="setting-item full-width">
            <button @click="testSlack" class="btn-secondary">Test Slack Connection</button>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <MessageSquare class="title-icon" />
          Webhook Integration
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Webhook URL</label>
            <input v-model="notificationSettings.webhookUrl" type="url" placeholder="https://api.example.com/webhook" />
          </div>
          <div class="setting-item">
            <label>Secret Key</label>
            <input v-model="notificationSettings.webhookSecret" type="password" placeholder="••••••••" />
          </div>
          <div class="setting-item">
            <label>Enable Webhooks</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="notificationSettings.webhookEnabled"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Send webhook notifications</span>
              </label>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <Bell class="title-icon" />
          Notification Rules
        </h2>
        <div class="rules-list">
          <div
            v-for="(rule, index) in notificationSettings.rules"
            :key="index"
            class="rule-card"
          >
            <div class="rule-header">
              <h4>Rule {{ index + 1 }}</h4>
              <button @click="removeNotificationRule(index)" class="btn-remove">
                <Trash2 class="icon" />
              </button>
            </div>
            <div class="rule-content">
              <div class="form-group">
                <label>Event Type</label>
                <Dropdown
                  v-model="rule.eventType"
                  :options="eventTypeOptions"
                  placeholder="Select event..."
                />
              </div>
              <div class="form-group">
                <label>Severity</label>
                <Dropdown
                  v-model="rule.severity"
                  :options="severityOptions"
                  placeholder="Select severity..."
                />
              </div>
              <div class="form-group">
                <label>Channels</label>
                <div class="checkbox-group">
                  <label class="checkbox-label">
                    <input v-model="rule.channels" type="checkbox" value="email" />
                    <span>Email</span>
                  </label>
                  <label class="checkbox-label">
                    <input v-model="rule.channels" type="checkbox" value="slack" />
                    <span>Slack</span>
                  </label>
                  <label class="checkbox-label">
                    <input v-model="rule.channels" type="checkbox" value="webhook" />
                    <span>Webhook</span>
                  </label>
                </div>
              </div>
            </div>
          </div>
          <button @click="addNotificationRule" class="btn-add-rule">
            <Plus class="icon" />
            Add Notification Rule
          </button>
        </div>
      </div>
    </div>

    <!-- Security Settings -->
    <div v-if="activeTab === 'security'" class="settings-content">
      <div class="settings-section">
        <h2 class="section-title">
          <Shield class="title-icon" />
          Authentication
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Session Timeout (minutes)</label>
            <input v-model.number="securitySettings.sessionTimeout" type="number" min="5" max="1440" />
          </div>
          <div class="setting-item">
            <label>Require Two-Factor Authentication</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="securitySettings.require2FA"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Force 2FA for all users</span>
              </label>
            </div>
          </div>
          <div class="setting-item">
            <label>Password Policy</label>
            <Dropdown
              v-model="securitySettings.passwordPolicy"
              :options="passwordPolicyOptions"
              placeholder="Select policy..."
            />
          </div>
          <div class="setting-item">
            <label>Maximum Login Attempts</label>
            <input v-model.number="securitySettings.maxLoginAttempts" type="number" min="3" max="10" />
          </div>
          <div class="setting-item">
            <label>Lockout Duration (minutes)</label>
            <input v-model.number="securitySettings.lockoutDuration" type="number" min="5" max="1440" />
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <Key class="title-icon" />
          API Keys
        </h2>
        <div class="api-keys-list">
          <div
            v-for="(key, index) in securitySettings.apiKeys"
            :key="index"
            class="api-key-card"
          >
            <div class="key-header">
              <div class="key-info">
                <h4>{{ key.name }}</h4>
                <p class="key-preview">{{ key.key.substring(0, 8) }}••••••••</p>
              </div>
              <div class="key-actions">
                <span class="key-status" :class="key.active ? 'active' : 'inactive'">
                  {{ key.active ? 'Active' : 'Inactive' }}
                </span>
                <button @click="copyApiKey(key.key)" class="btn-icon">
                  <Copy class="icon" />
                </button>
                <button @click="toggleApiKey(index)" class="btn-icon">
                  <component :is="key.active ? EyeOff : Eye" class="icon" />
                </button>
                <button @click="deleteApiKey(index)" class="btn-icon delete">
                  <Trash2 class="icon" />
                </button>
              </div>
            </div>
            <div class="key-meta">
              <span>Created: {{ formatDate(key.createdAt) }}</span>
              <span v-if="key.lastUsed">Last used: {{ formatDate(key.lastUsed) }}</span>
            </div>
          </div>
          <button @click="showAddApiKeyModal = true" class="btn-add-key">
            <Plus class="icon" />
            Add API Key
          </button>
        </div>
      </div>

      <div class="settings-section">
        <h2 class="section-title">
          <Lock class="title-icon" />
          Access Control
        </h2>
        <div class="settings-grid">
          <div class="setting-item">
            <label>Default User Role</label>
            <Dropdown
              v-model="securitySettings.defaultRole"
              :options="roleOptions"
              placeholder="Select role..."
            />
          </div>
          <div class="setting-item">
            <label>Allow Public Access</label>
            <div class="toggle-group">
              <label class="toggle-label">
                <input
                  v-model="securitySettings.allowPublicAccess"
                  type="checkbox"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">Allow unauthenticated access</span>
              </label>
            </div>
          </div>
          <div class="setting-item">
            <label>IP Whitelist</label>
            <textarea
              v-model="securitySettings.ipWhitelist"
              rows="4"
              placeholder="Enter IP addresses, one per line&#10;192.168.1.1&#10;10.0.0.0/8"
            ></textarea>
            <small>One IP address or CIDR range per line</small>
          </div>
        </div>
      </div>
    </div>

    <!-- Action Buttons -->
    <div class="settings-actions">
      <button @click="resetSettings" class="btn-secondary">Reset to Defaults</button>
      <button @click="saveSettings" class="btn-primary" :disabled="saving">
        <span v-if="saving">Saving...</span>
        <span v-else>Save Settings</span>
      </button>
    </div>

    <!-- Add API Key Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddApiKeyModal" class="modal-overlay" @click="showAddApiKeyModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Key class="modal-title-icon" />
                <h2>Add API Key</h2>
              </div>
              <button @click="showAddApiKeyModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="form-group">
                <label>Key Name</label>
                <input v-model="newApiKey.name" type="text" placeholder="e.g., Production API Key" required />
              </div>
              <div class="form-group">
                <label>Permissions</label>
                <div class="checkbox-group">
                  <label class="checkbox-label">
                    <input v-model="newApiKey.permissions" type="checkbox" value="read" />
                    <span>Read</span>
                  </label>
                  <label class="checkbox-label">
                    <input v-model="newApiKey.permissions" type="checkbox" value="write" />
                    <span>Write</span>
                  </label>
                  <label class="checkbox-label">
                    <input v-model="newApiKey.permissions" type="checkbox" value="admin" />
                    <span>Admin</span>
                  </label>
                </div>
              </div>
              <div class="form-actions">
                <button @click="showAddApiKeyModal = false" class="btn-secondary">Cancel</button>
                <button @click="addApiKey" class="btn-primary">Create API Key</button>
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
import {
  Settings,
  User,
  Mail,
  MessageSquare,
  Bell,
  Shield,
  Key,
  Lock,
  Plus,
  Trash2,
  Copy,
  Eye,
  EyeOff,
  X
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Settings', icon: Settings }
];

const activeTab = ref<'general' | 'notifications' | 'security'>('general');
const saving = ref(false);
const showAddApiKeyModal = ref(false);

const tabs = [
  { id: 'general', label: 'General', icon: Settings },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Shield }
];

// General Settings
const generalSettings = ref({
  appName: 'Sentinel Dashboard',
  timezone: 'UTC',
  dateFormat: 'MM/DD/YYYY',
  itemsPerPage: 25,
  autoRefreshInterval: 30,
  language: 'en',
  emailNotifications: true,
  defaultView: 'dashboard',
  theme: 'dark',
  accentColor: '#4facfe',
  compactMode: false
});

// Notification Settings
const notificationSettings = ref({
  smtpServer: '',
  smtpPort: 587,
  smtpUsername: '',
  smtpPassword: '',
  fromEmail: '',
  enableTLS: true,
  slackWebhookUrl: '',
  slackChannel: '',
  slackUsername: 'Sentinel Bot',
  slackEnabled: false,
  webhookUrl: '',
  webhookSecret: '',
  webhookEnabled: false,
  rules: [] as any[]
});

// Security Settings
const securitySettings = ref({
  sessionTimeout: 60,
  require2FA: false,
  passwordPolicy: 'medium',
  maxLoginAttempts: 5,
  lockoutDuration: 15,
  defaultRole: 'viewer',
  allowPublicAccess: false,
  ipWhitelist: '',
  apiKeys: [] as any[]
});

const newApiKey = ref({
  name: '',
  permissions: [] as string[]
});

// Dropdown Options
const timezoneOptions = [
  { label: 'UTC', value: 'UTC' },
  { label: 'America/New_York', value: 'America/New_York' },
  { label: 'America/Los_Angeles', value: 'America/Los_Angeles' },
  { label: 'Europe/London', value: 'Europe/London' },
  { label: 'Asia/Tokyo', value: 'Asia/Tokyo' }
];

const dateFormatOptions = [
  { label: 'MM/DD/YYYY', value: 'MM/DD/YYYY' },
  { label: 'DD/MM/YYYY', value: 'DD/MM/YYYY' },
  { label: 'YYYY-MM-DD', value: 'YYYY-MM-DD' }
];

const languageOptions = [
  { label: 'English', value: 'en' },
  { label: 'Spanish', value: 'es' },
  { label: 'French', value: 'fr' },
  { label: 'German', value: 'de' }
];

const defaultViewOptions = [
  { label: 'Dashboard', value: 'dashboard' },
  { label: 'Tests', value: 'tests' },
  { label: 'Reports', value: 'reports' }
];

const themeOptions = [
  { label: 'Dark', value: 'dark' },
  { label: 'Light', value: 'light' },
  { label: 'Auto', value: 'auto' }
];

const eventTypeOptions = [
  { label: 'Test Failure', value: 'test_failure' },
  { label: 'Policy Violation', value: 'policy_violation' },
  { label: 'Compliance Score Drop', value: 'compliance_drop' },
  { label: 'System Alert', value: 'system_alert' }
];

const severityOptions = [
  { label: 'Low', value: 'low' },
  { label: 'Medium', value: 'medium' },
  { label: 'High', value: 'high' },
  { label: 'Critical', value: 'critical' }
];

const passwordPolicyOptions = [
  { label: 'Weak', value: 'weak' },
  { label: 'Medium', value: 'medium' },
  { label: 'Strong', value: 'strong' }
];

const roleOptions = [
  { label: 'Viewer', value: 'viewer' },
  { label: 'Editor', value: 'editor' },
  { label: 'Admin', value: 'admin' }
];

const loadSettings = async () => {
  try {
    // In a real app, load from API
    // const response = await axios.get('/api/settings');
    // generalSettings.value = response.data.general;
    // notificationSettings.value = response.data.notifications;
    // securitySettings.value = response.data.security;
  } catch (err) {
    console.error('Error loading settings:', err);
  }
};

const saveSettings = async () => {
  try {
    saving.value = true;
    // In a real app, save to API
    // await axios.post('/api/settings', {
    //   general: generalSettings.value,
    //   notifications: notificationSettings.value,
    //   security: securitySettings.value
    // });
    await new Promise(resolve => setTimeout(resolve, 500)); // Simulate API call
    alert('Settings saved successfully!');
  } catch (err) {
    console.error('Error saving settings:', err);
    alert('Failed to save settings');
  } finally {
    saving.value = false;
  }
};

const resetSettings = () => {
  if (!confirm('Are you sure you want to reset all settings to defaults?')) {
    return;
  }
  // Reset to defaults
  generalSettings.value = {
    appName: 'Sentinel Dashboard',
    timezone: 'UTC',
    dateFormat: 'MM/DD/YYYY',
    itemsPerPage: 25,
    autoRefreshInterval: 30,
    language: 'en',
    emailNotifications: true,
    defaultView: 'dashboard',
    theme: 'dark',
    accentColor: '#4facfe',
    compactMode: false
  };
  notificationSettings.value = {
    smtpServer: '',
    smtpPort: 587,
    smtpUsername: '',
    smtpPassword: '',
    fromEmail: '',
    enableTLS: true,
    slackWebhookUrl: '',
    slackChannel: '',
    slackUsername: 'Sentinel Bot',
    slackEnabled: false,
    webhookUrl: '',
    webhookSecret: '',
    webhookEnabled: false,
    rules: []
  };
  securitySettings.value = {
    sessionTimeout: 60,
    require2FA: false,
    passwordPolicy: 'medium',
    maxLoginAttempts: 5,
    lockoutDuration: 15,
    defaultRole: 'viewer',
    allowPublicAccess: false,
    ipWhitelist: '',
    apiKeys: []
  };
};

const testEmail = async () => {
  try {
    // await axios.post('/api/settings/test-email');
    alert('Test email sent! Check your inbox.');
  } catch (err) {
    alert('Failed to send test email');
  }
};

const testSlack = async () => {
  try {
    // await axios.post('/api/settings/test-slack');
    alert('Test message sent to Slack!');
  } catch (err) {
    alert('Failed to send test message to Slack');
  }
};

const addNotificationRule = () => {
  notificationSettings.value.rules.push({
    eventType: '',
    severity: '',
    channels: []
  });
};

const removeNotificationRule = (index: number) => {
  notificationSettings.value.rules.splice(index, 1);
};

const addApiKey = () => {
  const key = {
    name: newApiKey.value.name,
    key: `sk_${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
    permissions: newApiKey.value.permissions,
    active: true,
    createdAt: new Date(),
    lastUsed: null
  };
  securitySettings.value.apiKeys.push(key);
  newApiKey.value = { name: '', permissions: [] };
  showAddApiKeyModal.value = false;
};

const deleteApiKey = (index: number) => {
  if (!confirm('Are you sure you want to delete this API key?')) {
    return;
  }
  securitySettings.value.apiKeys.splice(index, 1);
};

const toggleApiKey = (index: number) => {
  securitySettings.value.apiKeys[index].active = !securitySettings.value.apiKeys[index].active;
};

const copyApiKey = async (key: string) => {
  try {
    await navigator.clipboard.writeText(key);
    alert('API key copied to clipboard!');
  } catch (err) {
    console.error('Failed to copy:', err);
  }
};

const formatDate = (date: Date | string): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date;
  return dateObj.toLocaleDateString();
};

onMounted(() => {
  loadSettings();
});
</script>

<style scoped>
.settings-page {
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

.settings-tabs {
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

.settings-content {
  margin-bottom: 48px;
}

.settings-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.settings-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.setting-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.setting-item.full-width {
  grid-column: 1 / -1;
}

.setting-item label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.setting-item input,
.setting-item textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.setting-item textarea {
  resize: vertical;
  min-height: 100px;
}

.setting-item input:focus,
.setting-item textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.setting-item small {
  font-size: 0.75rem;
  color: #718096;
}

.toggle-group {
  margin-top: 8px;
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 12px;
  cursor: pointer;
}

.toggle-input {
  display: none;
}

.toggle-slider {
  position: relative;
  width: 44px;
  height: 24px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  transition: all 0.3s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #ffffff;
  top: 3px;
  left: 3px;
  transition: all 0.3s;
}

.toggle-input:checked + .toggle-slider {
  background: #4facfe;
}

.toggle-input:checked + .toggle-slider::before {
  transform: translateX(20px);
}

.toggle-text {
  color: #a0aec0;
  font-size: 0.9rem;
}

.theme-options {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.theme-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #a0aec0;
  cursor: pointer;
  transition: all 0.2s;
}

.theme-button:hover {
  border-color: rgba(79, 172, 254, 0.5);
  color: #4facfe;
}

.theme-button.active {
  background: rgba(79, 172, 254, 0.1);
  border-color: #4facfe;
  color: #4facfe;
}


.color-picker-group {
  display: flex;
  gap: 12px;
  align-items: center;
}

.color-picker {
  width: 60px;
  height: 40px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
}

.color-input {
  flex: 1;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.checkbox-label span {
  color: #a0aec0;
  font-size: 0.9rem;
}

.rules-list,
.api-keys-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.rule-card,
.api-key-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.rule-header,
.key-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.rule-header h4,
.key-info h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.key-preview {
  font-size: 0.875rem;
  color: #718096;
  font-family: 'Courier New', monospace;
}

.key-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.key-status {
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
}

.key-status.active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.key-status.inactive {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.btn-icon {
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

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon.delete:hover {
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.btn-icon .icon {
  width: 16px;
  height: 16px;
}

.key-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #718096;
}

.rule-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
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
}

.btn-remove .icon {
  width: 16px;
  height: 16px;
}

.btn-add-rule,
.btn-add-key {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: 2px dashed rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  width: 100%;
  justify-content: center;
}

.btn-add-rule:hover,
.btn-add-key:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-add-rule .icon,
.btn-add-key .icon {
  width: 18px;
  height: 18px;
}

.settings-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
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
  max-width: 500px;
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

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
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

