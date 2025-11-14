<template>
  <div class="tests-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Tests</h1>
          <p class="page-description">Manage and view compliance test suites</p>
        </div>
        <button @click="router.push({ name: 'TestSuiteCreate' })" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Suite
        </button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="switchTab(tab.id)"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
        <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
      </button>
    </div>

    <!-- Test Batteries Tab -->
    <div v-if="activeTab === 'batteries'" class="tab-content">
      <div class="section-header">
        <div>
          <h2>Test Batteries</h2>
          <p class="section-description">Collections of test harnesses that can be executed together</p>
        </div>
        <button @click="createBattery" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Battery
        </button>
      </div>
      <div class="info-banner">
        <AlertCircle class="info-icon" />
        <p>Tests run automatically in CI/CD during builds. This UI is for viewing and managing test organization.</p>
      </div>
      <div v-if="loadingBatteries" class="loading">Loading test batteries...</div>
      <div v-if="batteriesError" class="error">{{ batteriesError }}</div>
      <div v-if="!loadingBatteries && !batteriesError && testBatteries.length === 0" class="empty-state">
        <Battery class="empty-icon" />
        <h3>No test batteries found</h3>
        <p>Create a test battery to organize your test harnesses</p>
        <button @click="createBattery" class="btn-primary">
          Create Test Battery
        </button>
      </div>
      <div v-if="!loadingBatteries && !batteriesError && testBatteries.length > 0" class="batteries-grid">
        <div
          v-for="battery in testBatteries"
          :key="battery.id"
          class="battery-card"
        >
          <div class="battery-content" @click="viewBattery(battery.id)">
            <div class="battery-header">
              <h3 class="battery-name">{{ battery.name }}</h3>
              <span class="battery-badge">{{ battery.harnessIds?.length || 0 }} harnesses</span>
            </div>
            <p v-if="battery.description" class="battery-description">{{ battery.description }}</p>
            <div class="battery-meta">
              <span v-if="battery.team" class="team-badge">{{ battery.team }}</span>
              <span class="execution-mode">{{ battery.executionConfig?.executionMode || 'sequential' }}</span>
            </div>
          </div>
          <div class="battery-actions" @click.stop>
            <button @click="editBattery(battery)" class="btn-icon" title="Edit">
              <Edit class="icon-small" />
            </button>
            <button @click="viewBattery(battery.id)" class="btn-icon" title="View Details">
              <FileText class="icon-small" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Harnesses Tab -->
    <div v-if="activeTab === 'harnesses'" class="tab-content">
      <div class="section-header">
        <div>
          <h2>Test Harnesses</h2>
          <p class="section-description">Collections of test suites assigned to applications</p>
        </div>
        <button @click="createHarness" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Harness
        </button>
      </div>
      <div class="info-banner">
        <AlertCircle class="info-icon" />
        <p>Tests run automatically in CI/CD during builds. This UI is for viewing and managing test organization.</p>
      </div>
      <div v-if="loadingHarnesses" class="loading">Loading test harnesses...</div>
      <div v-if="harnessesError" class="error">{{ harnessesError }}</div>
      <div v-if="!loadingHarnesses && !harnessesError && testHarnesses.length === 0" class="empty-state">
        <Layers class="empty-icon" />
        <h3>No test harnesses found</h3>
        <p>Create a test harness to organize your test suites</p>
        <button @click="createHarness" class="btn-primary">
          Create Test Harness
        </button>
      </div>
      <div v-if="!loadingHarnesses && !harnessesError && testHarnesses.length > 0" class="harnesses-grid">
        <div
          v-for="harness in testHarnesses"
          :key="harness.id"
          class="harness-card"
        >
          <div class="harness-content" @click="viewHarness(harness.id)">
            <div class="harness-header">
              <h3 class="harness-name">{{ harness.name }}</h3>
              <div class="harness-badges">
                <span class="badge">{{ harness.testSuiteIds?.length || 0 }} suites</span>
                <span class="badge">{{ harness.applicationIds?.length || 0 }} applications</span>
              </div>
            </div>
            <p v-if="harness.description" class="harness-description">{{ harness.description }}</p>
            <div class="harness-meta">
              <span v-if="harness.team" class="team-badge">{{ harness.team }}</span>
            </div>
          </div>
          <div class="harness-actions" @click.stop>
            <button @click="editHarness(harness)" class="btn-icon" title="Edit">
              <Edit class="icon-small" />
            </button>
            <button @click="viewHarness(harness.id)" class="btn-icon" title="View Details">
              <FileText class="icon-small" />
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Suites Tab -->
    <div v-if="activeTab === 'suites'" class="tab-content">
      <!-- Quick Stats -->
      <div class="stats-cards">
          <div class="stat-card">
            <div class="stat-icon-wrapper">
              <List class="stat-icon" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ testSuites.length || 0 }}</div>
              <div class="stat-label">Test Suites</div>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-icon-wrapper">
              <TestTube class="stat-icon" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ testTypes.length }}</div>
              <div class="stat-label">Test Types</div>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-icon-wrapper">
              <Settings class="stat-icon" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ configurationsCount }}</div>
              <div class="stat-label">Configurations</div>
            </div>
          </div>
          <div class="stat-card">
            <div class="stat-icon-wrapper">
              <CheckCircle2 class="stat-icon" />
            </div>
            <div class="stat-content">
              <div class="stat-value">{{ testResults.length || 0 }}</div>
              <div class="stat-label">Test Results</div>
            </div>
          </div>
        </div>

        <!-- Quick Actions -->
        <div class="quick-actions">
          <h3 class="section-title">Quick Actions</h3>
          <div class="actions-grid">
            <button @click="router.push({ name: 'TestSuiteCreate' })" class="action-card">
              <Plus class="action-icon" />
              <span>Create Test Suite</span>
            </button>
            <button @click="switchTab('library')" class="action-card">
              <BookOpen class="action-icon" />
              <span>Browse Test Library</span>
            </button>
            <button @click="switchTab('findings')" class="action-card">
              <AlertCircle class="action-icon" />
              <span>View Findings</span>
            </button>
          </div>
        </div>

        <!-- Recent Test Runs -->
        <div class="recent-runs">
          <h3 class="section-title">Recent Test Runs</h3>
          <div v-if="!testResults || testResults.length === 0" class="empty-state-small">
            <p>No recent test runs</p>
          </div>
          <div v-else class="runs-list">
            <div
              v-for="result in (testResults || []).slice(0, 5)"
              :key="result.id"
              class="run-item"
              @click="viewResultDetails(result.id)"
            >
              <div class="run-info">
                <span class="run-name">{{ result.testName }}</span>
                <span class="run-type">{{ result.testType }}</span>
              </div>
              <span class="run-status" :class="result.passed ? 'passed' : 'failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
              <span class="run-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>
        </div>

        <!-- Test Health Dashboard -->
        <div class="health-dashboard">
          <h3 class="section-title">Test Health</h3>
          <div class="health-stats">
            <div class="health-item">
              <div class="health-label">Pass Rate</div>
              <div class="health-value" :class="getHealthClass(passRate)">
                {{ passRate.toFixed(1) }}%
              </div>
            </div>
            <div class="health-item">
              <div class="health-label">Active Suites</div>
              <div class="health-value">
                {{ activeSuitesCount }}
              </div>
            </div>
            <div class="health-item">
              <div class="health-label">Last 24h Runs</div>
              <div class="health-value">
                {{ last24hRuns }}
              </div>
            </div>
          </div>
        </div>

        <!-- How It Works -->
        <div class="how-it-works">
          <h3 class="section-title">How It Works</h3>
          <div class="relationship-explanation">
            <div class="relationship-item">
              <div class="relationship-icon">
                <TestTube class="icon" />
              </div>
              <div class="relationship-content">
                <h4>Test Types</h4>
                <p>Different categories of security tests (API Gateway, DLP, Network Policies, etc.). Each test type has specific test functions you can run.</p>
              </div>
            </div>
            <div class="relationship-arrow">→</div>
            <div class="relationship-item">
              <div class="relationship-icon">
                <Settings class="icon" />
              </div>
              <div class="relationship-content">
                <h4>Configurations</h4>
                <p>Test parameters and settings for each test type. Configurations define how tests should run and what to check for.</p>
              </div>
            </div>
            <div class="relationship-arrow">→</div>
            <div class="relationship-item">
              <div class="relationship-icon">
                <List class="icon" />
              </div>
              <div class="relationship-content">
                <h4>Test Suites</h4>
                <p>Collections of configurations grouped together. Test suites allow you to organize multiple tests and track results automatically in CI/CD.</p>
              </div>
            </div>
          </div>
        </div>

      <!-- Test Suites List -->
      <div v-if="loadingSuites" class="loading">Loading test suites...</div>
      <div v-else-if="suitesError" class="error">{{ suitesError }}</div>
      <div v-else>
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search test suites..."
          class="search-input"
        />
        <Dropdown
          v-model="filterApplication"
          :options="applicationOptions"
          placeholder="All Applications"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterTeam"
          :options="teamOptions"
          placeholder="All Teams"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterStatus"
          :options="statusOptions"
          placeholder="All Statuses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterValidator"
          :options="validatorOptions"
          placeholder="All Validators"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterHarness"
          :options="harnessOptions"
          placeholder="All Harnesses"
          class="filter-dropdown"
        />
      </div>

      <div class="test-suites-grid">
        <div
          v-for="suite in filteredTestSuites"
          :key="suite.id"
          class="test-suite-card"
          @click="viewTestSuite(suite.id)"
        >
          <div class="suite-header">
            <div class="suite-title-row">
              <h3 class="suite-name">{{ suite.name }}</h3>
              <div class="suite-status-badges">
                <span 
                  v-if="suite.sourceType"
                  class="source-type-badge"
                  :class="suite.sourceType === 'typescript' ? 'typescript' : 'json'"
                  :title="suite.sourceType === 'typescript' ? 'TypeScript source file' : 'JSON configuration'"
                >
                  {{ suite.sourceType === 'typescript' ? 'TS' : 'JSON' }}
                </span>
                <span 
                  class="enabled-badge"
                  :class="suite.enabled ? 'enabled' : 'disabled'"
                  :title="suite.enabled ? 'Enabled' : 'Disabled'"
                >
                  {{ suite.enabled ? 'Enabled' : 'Disabled' }}
                </span>
                <span class="suite-status" :class="`status-${suite.status}`">
                  {{ suite.status }}
                </span>
              </div>
            </div>
            <p class="suite-meta">
              {{ suite.application }} • {{ suite.team }}
              <span v-if="suite.sourcePath" class="source-path" :title="suite.sourcePath">
                • {{ suite.sourcePath }}
              </span>
            </p>
            <div v-if="suite.harnessNames && suite.harnessNames.length > 0" class="suite-harnesses">
              <span class="harness-label">In harnesses:</span>
              <span
                v-for="harnessName in suite.harnessNames"
                :key="harnessName.id"
                class="harness-badge"
                @click.stop="viewHarness(harnessName.id)"
                :title="`View ${harnessName.name} harness`"
              >
                {{ harnessName.name }}
              </span>
            </div>
          </div>
          
          <div class="suite-stats">
            <div class="stat">
              <span class="stat-label">Last Run</span>
              <span class="stat-value">{{ formatDate(suite.lastRun) }}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Tests</span>
              <span class="stat-value">{{ suite.testCount }}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Score</span>
              <span class="stat-value score" :class="getScoreClass(suite.score)">
                {{ suite.score }}%
              </span>
            </div>
          </div>

          <div class="suite-types">
            <span
              v-for="type in suite.testTypes"
              :key="type"
              class="test-type-badge"
            >
              {{ type }}
            </span>
          </div>

          <div class="suite-actions">
            <button 
              @click.stop="toggleTestSuite(suite)" 
              class="action-btn"
              :class="{ 'warning-btn': !suite.enabled }"
              :title="suite.enabled ? 'Disable' : 'Enable'"
            >
              <Power class="action-icon" />
              {{ suite.enabled ? 'Disable' : 'Enable' }}
            </button>
            <button @click.stop="viewTestSuite(suite.id)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button 
              v-if="suite.sourceType === 'typescript'"
              @click.stop="editSource(suite.id)" 
              class="action-btn source-btn"
              title="Edit source file"
            >
              <Code class="action-icon" />
              Source
            </button>
            <button @click.stop="viewResults(suite.id)" class="action-btn view-btn">
              <FileText class="action-icon" />
              Results
            </button>
            <button @click.stop="deleteTestSuite(suite.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredTestSuites.length === 0" class="empty-state">
        <TestTube class="empty-icon" />
        <h3>No test suites found</h3>
        <p>Create your first test suite to get started</p>
        <button @click="router.push({ name: 'TestSuiteCreate' })" class="btn-primary">
          Create Test Suite
        </button>
      </div>
      </div>
    </div>

    <!-- Test Execution -->

    <!-- Test Types Tab -->
    <!-- Test Library Tab -->
    <div v-if="activeTab === 'library'" class="tab-content">
      <div class="test-types-grid">
        <TestTypeCard
          v-for="testType in testTypes"
          :key="testType.type"
          :name="testType.name"
          :type="testType.type"
          :description="testType.description"
          :icon="testType.icon"
          :config-count="getConfigCountForType(testType.type)"
          :last-run-status="getLastRunStatusForType(testType.type)"
          @edit-config="handleEditConfig"
          @view-result="handleViewResult"
        />
      </div>
    </div>

    <!-- Configurations Tab -->
    <div v-if="activeTab === 'configurations'" class="tab-content">
      <div class="configurations-header">
        <div class="header-actions">
          <button @click="showCreateConfigModal = true" class="btn-primary">
            <Plus class="btn-icon" />
            Create Configuration
          </button>
        </div>
        <div class="filters">
          <input
            v-model="configSearchQuery"
            type="text"
            placeholder="Search configurations..."
            class="search-input"
          />
          <Dropdown
            v-model="configFilterType"
            :options="configTypeOptions"
            placeholder="All Types"
            class="filter-dropdown"
          />
        </div>
      </div>

      <div v-if="loadingConfigs" class="loading">Loading configurations...</div>
      <div v-else-if="configsError" class="error">{{ configsError }}</div>
      <div v-else class="configurations-grid">
        <div
          v-for="config in filteredConfigurations"
          :key="config.id"
          class="configuration-card"
          @click="editConfiguration(config)"
        >
          <div class="config-card-header">
            <div class="config-title-section">
              <h3 class="config-name">{{ config.name }}</h3>
              <span class="config-type-badge" :class="`type-${config.type}`">
                {{ getTypeLabel(config.type) }}
              </span>
            </div>
            <div class="config-status-badges">
              <span
                class="enabled-badge"
                :class="config.enabled ? 'enabled' : 'disabled'"
              >
                {{ config.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
          </div>
          <p class="config-description">{{ config.description || 'No description' }}</p>
          <div class="config-meta">
            <span class="meta-item">
              <span class="meta-label">Used by:</span>
              <span class="meta-value">{{ getUsedByCount(config.id) }} test suite(s)</span>
              <span v-if="getUsedByCount(config.id) > 0" class="used-by-list">
                <span
                  v-for="suiteId in getUsedBySuites(config.id)"
                  :key="suiteId"
                  class="suite-badge"
                  :title="getSuiteName(suiteId)"
                >
                  {{ getSuiteName(suiteId) }}
                </span>
              </span>
            </span>
            <span class="meta-item">
              <span class="meta-label">Last run:</span>
              <span class="meta-value">{{ getLastRunForConfig(config.id) }}</span>
            </span>
          </div>
          <div class="config-actions" @click.stop>
            <button @click.stop="editConfiguration(config)" class="action-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click.stop="deleteConfiguration(config.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="!loadingConfigs && filteredConfigurations.length === 0" class="empty-state">
        <Settings class="empty-icon" />
        <h3>No configurations found</h3>
        <p>Create your first configuration to get started</p>
        <button @click="showCreateConfigModal = true" class="btn-primary">
          Create Configuration
        </button>
      </div>

      <!-- Configuration Modal -->
      <ConfigurationModal
        v-if="showCreateConfigModal || editingConfig"
        :show="showCreateConfigModal || !!editingConfig"
        :config="editingConfig"
        :type="editingConfig?.type"
        @close="closeConfigModal"
        @save="handleSaveConfig"
      />
    </div>

    <!-- Test Results -->
    <!-- Findings Tab -->
    <div v-if="activeTab === 'findings'" class="tab-content">
      <div class="findings-tabs">
        <button 
          @click="findingsView = 'list'"
          class="view-tab"
          :class="{ active: findingsView === 'list' }"
        >
          <FileText class="tab-icon" />
          List View
        </button>
        <button 
          @click="findingsView = 'timeline'"
          class="view-tab"
          :class="{ active: findingsView === 'timeline' }"
        >
          <Clock class="tab-icon" />
          Timeline
        </button>
      </div>

      <!-- List View -->
      <div v-if="findingsView === 'list'">
      <div class="results-filters">
        <Dropdown
          v-model="resultsFilterSuite"
          :options="testSuiteOptions"
          placeholder="All Test Suites"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterHarness"
          :options="harnessFilterOptions"
          placeholder="All Harnesses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterBattery"
          :options="batteryFilterOptions"
          placeholder="All Batteries"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterApplication"
          :options="applicationFilterOptions"
          placeholder="All Applications"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterStatus"
          :options="resultsStatusOptions"
          placeholder="All Results"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterType"
          :options="resultsTypeOptions"
          placeholder="All Types"
          class="filter-dropdown"
        />
      </div>

      <div class="results-list">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result.id)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h4 class="result-name">{{ result.testName }}</h4>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <div class="result-meta">
              <span class="result-type">{{ result.testType }}</span>
              <span v-if="result.validatorName" class="result-validator">{{ result.validatorName }}</span>
              <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>
          <div v-if="result.error" class="result-error">
            <AlertTriangle class="error-icon" />
            <span>{{ result.error }}</span>
          </div>
          <div v-if="!result.passed" class="result-risk-management">
            <div v-if="result.riskStatus" class="risk-badge" :class="`risk-${result.riskStatus}`">
              <Shield v-if="result.riskStatus === 'accepted'" class="badge-icon" />
              <AlertCircle v-else-if="result.riskStatus === 'pending'" class="badge-icon" />
              <CheckCircle v-else-if="result.riskStatus === 'remediated'" class="badge-icon" />
              {{ getRiskStatusLabel(result.riskStatus) }}
            </div>
            <div v-if="result.remediationStatus" class="remediation-badge" :class="`remediation-${result.remediationStatus}`">
              <Wrench class="badge-icon" />
              {{ getRemediationStatusLabel(result.remediationStatus) }}
              <span v-if="result.remediationProgress !== undefined" class="progress-text">
                ({{ result.remediationProgress }}%)
              </span>
            </div>
            <div v-if="result.ticketId" class="ticket-link">
              <ExternalLink class="ticket-icon" />
              <a :href="result.ticketUrl" target="_blank" @click.stop>{{ result.ticketId }}</a>
            </div>
          </div>
          <div class="result-actions" @click.stop>
            <button 
              v-if="!result.passed && !result.riskStatus" 
              @click="openRiskAcceptanceModal(result)" 
              class="btn-icon btn-warning" 
              title="Accept Risk"
            >
              <Shield class="icon" />
            </button>
            <button 
              v-if="!result.passed && !result.ticketId" 
              @click="openTicketLinkModal(result)" 
              class="btn-icon btn-secondary" 
              title="Link Ticket"
            >
              <ExternalLink class="icon" />
            </button>
            <button 
              v-if="!result.passed && !result.remediationStatus" 
              @click="openRemediationModal(result)" 
              class="btn-icon btn-primary" 
              title="Start Remediation"
            >
              <Wrench class="icon" />
            </button>
            <button 
              v-if="!result.passed && result.remediationStatus === 'in-progress'" 
              @click="openRemediationModal(result)" 
              class="btn-icon btn-primary" 
              title="Update Remediation"
            >
              <Wrench class="icon" />
            </button>
            <button @click="deleteTestResult(result.id)" class="btn-icon btn-danger" title="Delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredResults.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No test results found</h3>
        <p>Test results will appear here after CI/CD runs</p>
      </div>
      </div>

      <!-- Timeline View -->
      <div v-if="findingsView === 'timeline'" class="timeline-view">
        <div class="timeline-container">
          <div
            v-for="(group, index) in timelineGroups"
            :key="index"
            class="timeline-group"
          >
            <div class="timeline-date-header">
              <Clock class="date-icon" />
              <h3>{{ group.date }}</h3>
              <span class="date-count">{{ group.results.length }} result(s)</span>
            </div>
            <div class="timeline-items">
              <div
                v-for="result in group.results"
                :key="result.id"
                class="timeline-item"
                :class="{ 'passed': result.passed, 'failed': !result.passed }"
              >
                <div class="timeline-marker">
                  <CheckCircle v-if="result.passed" class="marker-icon" />
                  <XCircle v-else class="marker-icon" />
                </div>
                <div class="timeline-content">
                  <div class="timeline-time">{{ formatTime(result.timestamp) }}</div>
                  <div class="timeline-title">{{ result.testName }}</div>
                  <div class="timeline-meta">
                    <span class="timeline-type">{{ result.testType }}</span>
                    <span v-if="result.validatorName" class="timeline-validator">{{ result.validatorName }}</span>
                  </div>
                  <div v-if="result.error" class="timeline-error">
                    <AlertTriangle class="error-icon-small" />
                    {{ result.error }}
                  </div>
                  <div v-if="!result.passed" class="timeline-actions">
                    <button @click="viewResultDetails(result.id)" class="btn-link">View Details</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div v-if="timelineGroups.length === 0" class="empty-state">
            <Clock class="empty-icon" />
            <h3>No test execution history</h3>
            <p>Test runs will appear here in chronological order</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Suite Builder Modal -->
    <TestSuiteBuilderModal
      :show="showCreateModal || !!editingSuite"
      :editing-suite="editingSuiteData"
      @close="closeModal"
      @save="handleSaveTestSuite"
      @save-draft="handleSaveDraft"
    />

    <!-- Test Result Detail Modal -->
    <TestResultDetailModal
      :show="showResultDetail"
      :result="selectedResult"
      :previous-result="previousResult"
      @close="closeResultDetail"
      @export="exportTestResult"
    />

    <!-- Source Editor Modal -->
    <TestSuiteSourceEditor
      :show="showSourceEditor"
      :suite-id="editingSourceSuiteId || ''"
      @close="closeSourceEditor"
      @saved="handleSourceSaved"
    />

    <!-- Test Battery Modal -->
    <TestBatteryModal
      :show="showBatteryModal"
      :editing-battery="editingBattery"
      @close="closeBatteryModal"
      @saved="handleBatterySaved"
    />

    <!-- Test Harness Modal -->
    <TestHarnessModal
      :show="showHarnessModal"
      :editing-harness="editingHarness"
      @close="closeHarnessModal"
      @saved="handleHarnessSaved"
    />

    <!-- Risk Acceptance Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showRiskAcceptanceModal" class="modal-overlay" @click="closeRiskAcceptanceModal">
          <div class="modal-content risk-modal" @click.stop>
            <div class="modal-header">
              <h2>Request Risk Acceptance</h2>
              <button @click="closeRiskAcceptanceModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForRisk" class="risk-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForRisk.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForRisk.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="risk-reason">Reason for Risk Acceptance *</label>
                  <textarea
                    id="risk-reason"
                    v-model="riskReason"
                    rows="3"
                    placeholder="Explain why this risk should be accepted..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-group">
                  <label for="risk-justification">Justification *</label>
                  <textarea
                    id="risk-justification"
                    v-model="riskJustification"
                    rows="3"
                    placeholder="Provide business or technical justification..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeRiskAcceptanceModal" class="btn-secondary">Cancel</button>
                  <button @click="handleSubmitRiskAcceptance" class="btn-primary">Submit Request</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Ticket Link Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showTicketLinkModal" class="modal-overlay" @click="closeTicketLinkModal">
          <div class="modal-content ticket-modal" @click.stop>
            <div class="modal-header">
              <h2>Link Ticket</h2>
              <button @click="closeTicketLinkModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForTicket" class="ticket-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForTicket.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForTicket.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="ticket-id">Ticket ID *</label>
                  <input
                    id="ticket-id"
                    v-model="ticketId"
                    type="text"
                    placeholder="e.g., JIRA-123, GH-456"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label for="ticket-url">Ticket URL (optional)</label>
                  <input
                    id="ticket-url"
                    v-model="ticketUrl"
                    type="url"
                    placeholder="https://..."
                    class="form-input"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeTicketLinkModal" class="btn-secondary">Cancel</button>
                  <button @click="submitTicketLink" class="btn-primary">Link Ticket</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Remediation Tracking Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showRemediationModal" class="modal-overlay" @click="closeRemediationModal">
          <div class="modal-content remediation-modal" @click.stop>
            <div class="modal-header">
              <h2>Remediation Tracking</h2>
              <button @click="closeRemediationModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForRemediation" class="remediation-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForRemediation.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForRemediation.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="remediation-progress">Progress (%)</label>
                  <input
                    id="remediation-progress"
                    v-model.number="remediationProgress"
                    type="number"
                    min="0"
                    max="100"
                    class="form-input"
                  />
                  <div class="progress-bar-container">
                    <div class="progress-bar" :style="{ width: `${remediationProgress}%` }"></div>
                  </div>
                </div>
                <div class="form-group">
                  <label for="remediation-step">Current Step</label>
                  <input
                    id="remediation-step"
                    v-model="remediationCurrentStep"
                    type="text"
                    placeholder="e.g., Fixing access control policy..."
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label for="remediation-notes">Notes</label>
                  <textarea
                    id="remediation-notes"
                    v-model="remediationNotes"
                    rows="4"
                    placeholder="Add notes about remediation progress..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeRemediationModal" class="btn-secondary">Cancel</button>
                  <button 
                    v-if="remediationProgress === 100"
                    @click="completeRemediation"
                    class="btn-primary"
                  >
                    Mark Complete
                  </button>
                  <button @click="submitRemediation" class="btn-primary">Update Progress</button>
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
import { ref, computed, onMounted, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { Teleport } from 'vue';
import {
  TestTube,
  Play,
  FileText,
  Edit,
  Plus,
  X,
  AlertTriangle,
  List,
  Clock,
  CheckCircle2,
  XCircle,
  Trash2,
  Power,
  Code,
  LayoutDashboard,
  Settings,
  Server,
  FileX,
  Network,
  Shield,
  Lock,
  Database,
  Battery,
  Layers,
  BookOpen,
  AlertCircle,
  ExternalLink,
  CheckCircle,
  X,
  Wrench,
  Clock
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestSuiteBuilderModal from '../components/TestSuiteBuilderModal.vue';
import TestResultDetailModal from '../components/TestResultDetailModal.vue';
import TestSuiteSourceEditor from '../components/TestSuiteSourceEditor.vue';
import TestTypeCard from '../components/TestTypeCard.vue';
import ConfigurationModal from '../components/configurations/ConfigurationModal.vue';
import TestBatteryModal from '../components/TestBatteryModal.vue';
import TestHarnessModal from '../components/TestHarnessModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests' }
];

const router = useRouter();
const route = useRoute();

// Initialize active tab from query parameter or default to overview
const getInitialTab = (): 'batteries' | 'harnesses' | 'suites' | 'library' | 'findings' => {
  const tab = route.query.tab as string;
  const validTabs = ['batteries', 'harnesses', 'suites', 'library', 'findings'];
  if (tab && validTabs.includes(tab)) {
    return tab as any;
  }
  return 'batteries';
};

const activeTab = ref<'batteries' | 'harnesses' | 'suites' | 'library' | 'findings'>(getInitialTab());
const searchQuery = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterStatus = ref('');
const filterValidator = ref('');
const filterHarness = ref('');
const showCreateModal = ref(false);
const editingSuite = ref<string | null>(null);
const editingSuiteData = ref<any>(null);
const validators = ref<any[]>([]);
const showResultDetail = ref(false);
const selectedResult = ref<any>(null);
const previousResult = ref<any>(null);
const showSourceEditor = ref(false);
const editingSourceSuiteId = ref<string | null>(null);
const showBatteryModal = ref(false);
const editingBattery = ref<any>(null);
const showHarnessModal = ref(false);
const editingHarness = ref<any>(null);

// Test execution removed - tests run automatically in CI/CD

// Test Types data
const testTypes = [
  { name: 'API Gateway', type: 'api-gateway', description: 'Test API gateway policies, rate limiting, and service authentication', icon: Server },
  { name: 'DLP', type: 'dlp', description: 'Test data exfiltration detection, API response validation, and bulk export controls', icon: FileX },
  { name: 'Network Policies', type: 'network-policy', description: 'Test firewall rules, network segmentation, and service mesh policies', icon: Network },
  { name: 'API Security', type: 'api-security', description: 'Test REST and GraphQL API security', icon: Lock },
  { name: 'RLS/CLS', type: 'rls-cls', description: 'Test row-level and column-level security', icon: Database },
];

// Configurations data
const configurations = ref<any[]>([]);
const loadingConfigs = ref(false);
const configsError = ref<string | null>(null);
const configSearchQuery = ref('');
const configFilterType = ref('');
const showCreateConfigModal = ref(false);
const editingConfig = ref<any>(null);

// Test suites data
const testSuites = ref<any[]>([]);
const loadingSuites = ref(false);
const suitesError = ref<string | null>(null);

// Test batteries data
const testBatteries = ref<any[]>([]);
const loadingBatteries = ref(false);
const batteriesError = ref<string | null>(null);

// Test harnesses data
const testHarnesses = ref<any[]>([]);
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);

const applications = computed(() => {
  return [...new Set(testSuites.value.map(s => s.application))];
});

const teams = computed(() => {
  return [...new Set(testSuites.value.map(s => s.team))];
});

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const teamOptions = computed(() => {
  return [
    { label: 'All Teams', value: '' },
    ...teams.value.map(team => ({ label: team, value: team }))
  ];
});

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Passing', value: 'passing' },
  { label: 'Failing', value: 'failing' },
  { label: 'Pending', value: 'pending' }
]);

const testSuiteOptions = computed(() => {
  return [
    { label: 'All Test Suites', value: '' },
    ...testSuites.value.map(suite => ({ label: suite.name, value: suite.id }))
  ];
});

const resultsStatusOptions = computed(() => [
  { label: 'All Results', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' }
]);

const resultsTypeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Access Control', value: 'access-control' },
  { label: 'Data Behavior', value: 'data-behavior' },
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' }
]);

const validatorOptions = computed(() => {
  return [
    { label: 'All Validators', value: '' },
    ...validators.value.map(v => ({ label: v.name, value: v.id }))
  ];
});

const harnessOptions = computed(() => {
  return [
    { label: 'All Harnesses', value: '' },
    ...testHarnesses.value.map(h => ({ label: h.name, value: h.id }))
  ];
});

const filteredTestSuites = computed(() => {
  return testSuites.value.filter(suite => {
    const matchesSearch = !searchQuery.value || suite.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         (suite.application && suite.application.toLowerCase().includes(searchQuery.value.toLowerCase()));
    const matchesApp = !filterApplication.value || suite.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || suite.team === filterTeam.value;
    const matchesStatus = !filterStatus.value || suite.status === filterStatus.value;
    const matchesValidator = !filterValidator.value || (suite.validatorId === filterValidator.value);
    const matchesHarness = !filterHarness.value || (suite.harnessIds && suite.harnessIds.includes(filterHarness.value));
    return matchesSearch && matchesApp && matchesTeam && matchesStatus && matchesValidator && matchesHarness;
  });
});

// Test execution removed - tests run automatically in CI/CD

// Test results
const testResults = ref([
  {
    id: '1',
    testName: 'PDP Decision: admin accessing report',
    testType: 'access-control',
    passed: true,
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    error: null,
    validatorId: 'access-control-validator',
    validatorName: 'Access Control Validator'
  },
  {
    id: '2',
    testName: 'Query Validation: viewer executing Get all reports',
    testType: 'data-behavior',
    passed: true,
    timestamp: new Date(Date.now() - 35 * 60 * 1000),
    error: null,
    validatorId: 'data-behavior-validator',
    validatorName: 'Data Behavior Validator'
  },
  {
    id: '3',
    testName: 'Contract: No Raw Email Export',
    testType: 'contract',
    passed: false,
    timestamp: new Date(Date.now() - 40 * 60 * 1000),
    error: 'Raw email export detected in query results',
    validatorId: 'contract-validator',
    validatorName: 'Contract Validator'
  }
]);

const resultsFilterSuite = ref('');
const resultsFilterHarness = ref('');
const resultsFilterBattery = ref('');
const resultsFilterApplication = ref('');
const resultsFilterStatus = ref('');
const resultsFilterType = ref('');

const applications = ref<any[]>([]);

const harnessFilterOptions = computed(() => {
  return [
    { label: 'All Harnesses', value: '' },
    ...testHarnesses.value.map(h => ({ label: h.name, value: h.id }))
  ];
});

const batteryFilterOptions = computed(() => {
  return [
    { label: 'All Batteries', value: '' },
    ...testBatteries.value.map(b => ({ label: b.name, value: b.id }))
  ];
});

const applicationFilterOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(a => ({ label: a.name, value: a.id }))
  ];
});

const filteredResults = computed(() => {
  if (!testResults.value) return [];
  return testResults.value.filter(result => {
    const matchesSuite = !resultsFilterSuite.value || (result.testSuiteId === resultsFilterSuite.value);
    const matchesHarness = !resultsFilterHarness.value || 
      (result.harnessId === resultsFilterHarness.value || 
       (result.harnessIds && result.harnessIds.includes(resultsFilterHarness.value)));
    const matchesBattery = !resultsFilterBattery.value ||
      (result.batteryId === resultsFilterBattery.value ||
       (result.batteryIds && result.batteryIds.includes(resultsFilterBattery.value)));
    const matchesApplication = !resultsFilterApplication.value ||
      (result.applicationId === resultsFilterApplication.value ||
       (result.application && result.application === resultsFilterApplication.value));
    const matchesStatus = !resultsFilterStatus.value ||
      (resultsFilterStatus.value === 'passed' && result.passed) ||
      (resultsFilterStatus.value === 'failed' && !result.passed);
    const matchesType = !resultsFilterType.value || result.testType === resultsFilterType.value;
    return matchesSuite && matchesHarness && matchesBattery && matchesApplication && matchesStatus && matchesType;
  });
});

const timelineGroups = computed(() => {
  if (!filteredResults.value || filteredResults.value.length === 0) return [];
  
  // Group results by date
  const groups = new Map<string, any[]>();
  
  filteredResults.value.forEach(result => {
    const date = new Date(result.timestamp);
    const dateKey = date.toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
    
    if (!groups.has(dateKey)) {
      groups.set(dateKey, []);
    }
    groups.get(dateKey)!.push(result);
  });
  
  // Convert to array and sort by date (newest first)
  return Array.from(groups.entries())
    .map(([date, results]) => ({
      date,
      results: results.sort((a, b) => 
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ),
    }))
    .sort((a, b) => 
      new Date(b.date).getTime() - new Date(a.date).getTime()
    );
});

const formatTime = (timestamp: Date | string): string => {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  return date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
};

// Form data - removed, now handled by TestSuiteBuilderModal

const tabs = computed(() => [
  { id: 'batteries', label: 'Test Batteries', icon: Battery },
  { id: 'harnesses', label: 'Test Harnesses', icon: Layers },
  { id: 'suites', label: 'Test Suites', icon: List, badge: testSuites.value?.length || 0 },
  { id: 'library', label: 'Test Library', icon: BookOpen },
  { id: 'findings', label: 'Findings', icon: AlertCircle, badge: testResults.value?.filter(r => !r.passed).length || 0 }
]);

const switchTab = (tabId: string) => {
  activeTab.value = tabId as any;
  // Update URL without navigation
  router.replace({ query: { ...route.query, tab: tabId } });
};

const viewTestSuite = (id: string) => {
  router.push({ name: 'TestSuiteDetail', params: { id } });
};

// Load test batteries
const loadTestBatteries = async () => {
  try {
    loadingBatteries.value = true;
    batteriesError.value = null;
    const response = await axios.get('/api/test-batteries');
    testBatteries.value = response.data;
  } catch (err: any) {
    batteriesError.value = err.response?.data?.message || 'Failed to load test batteries';
    console.error('Error loading test batteries:', err);
  } finally {
    loadingBatteries.value = false;
  }
};

// Load test harnesses
const loadTestHarnesses = async () => {
  try {
    loadingHarnesses.value = true;
    harnessesError.value = null;
    const response = await axios.get('/api/test-harnesses');
    testHarnesses.value = response.data;
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load test harnesses';
    console.error('Error loading test harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

// Battery and harness actions
const createBattery = () => {
  editingBattery.value = null;
  showBatteryModal.value = true;
};

const editBattery = (battery: any) => {
  editingBattery.value = battery;
  showBatteryModal.value = true;
};

const handleBatterySaved = async (battery: any) => {
  await loadTestBatteries();
};

const closeBatteryModal = () => {
  showBatteryModal.value = false;
  editingBattery.value = null;
};

const viewBattery = (id: string) => {
  // TODO: Navigate to battery detail view
  router.push({ path: `/tests/batteries/${id}` });
};

const createHarness = () => {
  editingHarness.value = null;
  showHarnessModal.value = true;
};

const editHarness = (harness: any) => {
  editingHarness.value = harness;
  showHarnessModal.value = true;
};

const handleHarnessSaved = async (harness: any) => {
  await loadTestHarnesses();
};

const closeHarnessModal = () => {
  showHarnessModal.value = false;
  editingHarness.value = null;
};

const viewHarness = (id: string) => {
  // TODO: Navigate to harness detail view
  router.push({ path: `/tests/harnesses/${id}` });
};

// Test execution removed - tests run automatically in CI/CD during builds

const formatDuration = (ms: number): string => {
  if (!ms) return '0s';
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
};

const loadTestSuites = async () => {
  loadingSuites.value = true;
  suitesError.value = null;
  try {
    const [suitesResponse, harnessesResponse] = await Promise.all([
      axios.get('/api/test-suites'),
      axios.get('/api/test-harnesses'),
    ]);
    
    const allHarnesses = harnessesResponse.data || [];
    const harnessMap = new Map(allHarnesses.map((h: any) => [h.id, h]));
    
    testSuites.value = suitesResponse.data.map((s: any) => {
      // Find which harnesses contain this suite
      const containingHarnesses = allHarnesses.filter((h: any) => 
        h.testSuiteIds && h.testSuiteIds.includes(s.id)
      );
      
      return {
        ...s,
        application: s.application || s.applicationId,
        lastRun: s.lastRun ? new Date(s.lastRun) : undefined,
        createdAt: s.createdAt ? new Date(s.createdAt) : new Date(),
        updatedAt: s.updatedAt ? new Date(s.updatedAt) : new Date(),
        sourceType: s.sourceType || 'json',
        sourcePath: s.sourcePath,
        harnessIds: containingHarnesses.map((h: any) => h.id),
        harnessNames: containingHarnesses.map((h: any) => ({ id: h.id, name: h.name })),
      };
    });
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to load test suites';
    console.error('Error loading test suites:', err);
  } finally {
    loadingSuites.value = false;
  }
};


const deleteTestSuite = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test suite? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-suites/${id}`);
    await loadTestSuites();
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to delete test suite';
    console.error('Error deleting test suite:', err);
    alert(err.response?.data?.message || 'Failed to delete test suite');
  }
};

const toggleTestSuite = async (suite: any) => {
  try {
    if (suite.enabled) {
      await axios.patch(`/api/test-suites/${suite.id}/disable`);
    } else {
      await axios.patch(`/api/test-suites/${suite.id}/enable`);
    }
    await loadTestSuites();
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to toggle test suite';
    console.error('Error toggling test suite:', err);
    alert(err.response?.data?.message || 'Failed to toggle test suite');
  }
};

const viewResults = (id: string) => {
  switchTab('results');
  resultsFilterSuite.value = id;
};

const viewResultDetails = (id: string) => {
  const result = testResults.value.find(r => r.id === id);
  if (result) {
    selectedResult.value = result;
    // Find previous result for comparison
    const previous = testResults.value
      .filter(r => r.testName === result.testName && r.id !== id)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];
    previousResult.value = previous || null;
    showResultDetail.value = true;
  }
};

const deleteTestResult = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test result? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-results/${id}`);
    // Remove from local array if it exists
    const index = testResults.value.findIndex(r => r.id === id);
    if (index !== -1) {
      testResults.value.splice(index, 1);
    }
  } catch (err: any) {
    console.error('Error deleting test result:', err);
    alert(err.response?.data?.message || 'Failed to delete test result');
  }
};

const openRiskAcceptanceModal = (result: any) => {
  selectedResultForRisk.value = result;
  showRiskAcceptanceModal.value = true;
};

const closeRiskAcceptanceModal = () => {
  showRiskAcceptanceModal.value = false;
  selectedResultForRisk.value = null;
};

const submitRiskAcceptance = async (reason: string, justification: string) => {
  if (!selectedResultForRisk.value) return;
  
  try {
    await axios.post('/api/finding-approvals/request', {
      findingId: selectedResultForRisk.value.id,
      type: 'risk-acceptance',
      reason,
      justification,
    });
    // Update local result
    const index = testResults.value.findIndex(r => r.id === selectedResultForRisk.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        riskStatus: 'pending',
      };
    }
    closeRiskAcceptanceModal();
  } catch (err: any) {
    console.error('Error submitting risk acceptance:', err);
    alert(err.response?.data?.message || 'Failed to submit risk acceptance request');
  }
};

const openTicketLinkModal = (result: any) => {
  selectedResultForTicket.value = result;
  ticketId.value = result.ticketId || '';
  ticketUrl.value = result.ticketUrl || '';
  showTicketLinkModal.value = true;
};

const closeTicketLinkModal = () => {
  showTicketLinkModal.value = false;
  selectedResultForTicket.value = null;
  ticketId.value = '';
  ticketUrl.value = '';
};

const submitTicketLink = async () => {
  if (!selectedResultForTicket.value || !ticketId.value) {
    alert('Please enter a ticket ID');
    return;
  }
  
  try {
    // Update the result with ticket information
    const index = testResults.value.findIndex(r => r.id === selectedResultForTicket.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        ticketId: ticketId.value,
        ticketUrl: ticketUrl.value || `https://tickets.example.com/${ticketId.value}`,
      };
    }
    closeTicketLinkModal();
  } catch (err: any) {
    console.error('Error linking ticket:', err);
    alert(err.response?.data?.message || 'Failed to link ticket');
  }
};

const getRiskStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    'pending': 'Risk Acceptance Pending',
    'accepted': 'Risk Accepted',
    'rejected': 'Risk Rejected',
    'remediated': 'Remediated',
  };
  return labels[status] || status;
};

const getRemediationStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    'not-started': 'Not Started',
    'in-progress': 'In Progress',
    'completed': 'Completed',
    'verified': 'Verified',
  };
  return labels[status] || status;
};

const showRemediationModal = ref(false);
const selectedResultForRemediation = ref<any>(null);
const remediationProgress = ref(0);
const remediationCurrentStep = ref('');
const remediationNotes = ref('');

const openRemediationModal = async (result: any) => {
  selectedResultForRemediation.value = result;
  
  // Try to load existing remediation tracking
  try {
    const response = await axios.get(`/api/remediation-tracking/violation/${result.id}`);
    if (response.data) {
      remediationProgress.value = response.data.progress || 0;
      remediationCurrentStep.value = response.data.currentStep || '';
      remediationNotes.value = response.data.notes || '';
    } else {
      remediationProgress.value = 0;
      remediationCurrentStep.value = '';
      remediationNotes.value = '';
    }
  } catch (err) {
    // No existing tracking, start fresh
    remediationProgress.value = 0;
    remediationCurrentStep.value = '';
    remediationNotes.value = '';
  }
  
  showRemediationModal.value = true;
};

const closeRemediationModal = () => {
  showRemediationModal.value = false;
  selectedResultForRemediation.value = null;
  remediationProgress.value = 0;
  remediationCurrentStep.value = '';
  remediationNotes.value = '';
};

const submitRemediation = async () => {
  if (!selectedResultForRemediation.value) return;
  
  try {
    // Check if remediation tracking already exists
    let trackingId = null;
    try {
      const existingResponse = await axios.get(`/api/remediation-tracking/violation/${selectedResultForRemediation.value.id}`);
      if (existingResponse.data) {
        trackingId = existingResponse.data.id;
      }
    } catch (err) {
      // No existing tracking
    }
    
    if (trackingId) {
      // Update existing tracking
      await axios.patch(`/api/remediation-tracking/${trackingId}/progress`, {
        progress: remediationProgress.value,
        currentStep: remediationCurrentStep.value,
      });
    } else {
      // Create new tracking
      const response = await axios.post('/api/remediation-tracking', {
        violationId: selectedResultForRemediation.value.id,
        findingId: selectedResultForRemediation.value.id,
        description: `Remediation for ${selectedResultForRemediation.value.testName}`,
      });
      trackingId = response.data.id;
      
      // Start remediation
      await axios.post(`/api/remediation-tracking/${trackingId}/start`, {
        actor: 'current-user', // Would use actual user context
      });
      
      // Update progress
      if (remediationProgress.value > 0) {
        await axios.patch(`/api/remediation-tracking/${trackingId}/progress`, {
          progress: remediationProgress.value,
          currentStep: remediationCurrentStep.value,
        });
      }
    }
    
    // Update local result
    const index = testResults.value.findIndex(r => r.id === selectedResultForRemediation.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        remediationStatus: remediationProgress.value === 100 ? 'completed' : 'in-progress',
        remediationProgress: remediationProgress.value,
      };
    }
    
    closeRemediationModal();
  } catch (err: any) {
    console.error('Error submitting remediation:', err);
    alert(err.response?.data?.message || 'Failed to submit remediation tracking');
  }
};

const completeRemediation = async () => {
  if (!selectedResultForRemediation.value) return;
  
  try {
    // Get tracking ID
    let trackingId = null;
    try {
      const existingResponse = await axios.get(`/api/remediation-tracking/violation/${selectedResultForRemediation.value.id}`);
      if (existingResponse.data) {
        trackingId = existingResponse.data.id;
      }
    } catch (err) {
      alert('Remediation tracking not found. Please update progress first.');
      return;
    }
    
    if (trackingId) {
      await axios.post(`/api/remediation-tracking/${trackingId}/complete`, {
        actor: 'current-user',
        effectiveness: 'effective',
      });
      
      // Update local result
      const index = testResults.value.findIndex(r => r.id === selectedResultForRemediation.value.id);
      if (index !== -1) {
        testResults.value[index] = {
          ...testResults.value[index],
          remediationStatus: 'completed',
          remediationProgress: 100,
        };
      }
    }
    
    closeRemediationModal();
  } catch (err: any) {
    console.error('Error completing remediation:', err);
    alert(err.response?.data?.message || 'Failed to complete remediation');
  }
};

const closeResultDetail = () => {
  showResultDetail.value = false;
  selectedResult.value = null;
  previousResult.value = null;
};

const exportTestResult = (result: any) => {
  const dataStr = JSON.stringify(result, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `test-result-${result.id}.json`;
  link.click();
  URL.revokeObjectURL(url);
};

const handleSaveTestSuite = async (suiteData: any) => {
  try {
    const testTypes = getTestTypes(suiteData);
    const currentSuite = editingSuite.value ? testSuites.value.find(s => s.id === editingSuite.value) : null;
    
    // If editing a TypeScript suite, convert to TypeScript and update source file
    if (currentSuite?.sourceType === 'typescript' && currentSuite.sourcePath) {
      try {
        // Get the original source to preserve structure
        const sourceResponse = await axios.get(`/api/test-suites/${editingSuite.value}/source`);
        const originalContent = sourceResponse.data.content;
        
        // Convert suiteData to TypeScript format
        // This is a simplified conversion - in production, use proper TS parser
        const tsContent = convertJSONToTypeScript(suiteData, currentSuite.sourcePath, originalContent);
        
        // Update the source file
        await axios.put(`/api/test-suites/${editingSuite.value}/source`, {
          content: tsContent,
        });
        
        await loadTestSuites();
        closeModal();
        return;
      } catch (err: any) {
        console.error('Error updating TypeScript source:', err);
        alert('Failed to update TypeScript source file. Please use the source editor instead.');
        return;
      }
    }
    
    // For JSON-based suites, use the regular update/create flow
    const payload = {
      ...suiteData,
      applicationId: suiteData.applicationId || suiteData.application,
      testTypes,
    };

    if (editingSuite.value) {
      await axios.put(`/api/test-suites/${editingSuite.value}`, payload);
    } else {
      await axios.post('/api/test-suites', {
        ...payload,
        status: 'pending',
        testCount: 0,
        score: 0,
      });
    }
    await loadTestSuites();
    closeModal();
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to save test suite';
    console.error('Error saving test suite:', err);
    alert(err.response?.data?.message || 'Failed to save test suite');
  }
};

// Helper function to convert JSON suite data to TypeScript
function convertJSONToTypeScript(suiteData: any, sourcePath: string, originalContent?: string): string {
  const suiteName = suiteData.name
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/^[a-z]/, (c: string) => c.toUpperCase())
    .replace(/-([a-z])/g, (_, c: string) => c.toUpperCase()) + 'TestSuite';

  // Try to preserve original variable name if available
  let varName = suiteName;
  if (originalContent) {
    const constMatch = originalContent.match(/export\s+const\s+(\w+)\s*:\s*TestSuite/);
    if (constMatch) {
      varName = constMatch[1];
    }
  }

  // Build the TestSuite object
  const config: any = {
    name: suiteData.name,
    application: suiteData.application || suiteData.applicationId,
    team: suiteData.team,
    includeAccessControlTests: suiteData.includeAccessControlTests || false,
    includeDataBehaviorTests: suiteData.includeDataBehaviorTests || false,
    includeContractTests: suiteData.includeContractTests || false,
    includeDatasetHealthTests: suiteData.includeDatasetHealthTests || false,
    userRoles: suiteData.userRoles || [],
    resources: suiteData.resources || [],
    contexts: suiteData.contexts || [],
  };

  if (suiteData.expectedDecisions) config.expectedDecisions = suiteData.expectedDecisions;
  if (suiteData.testQueries) config.testQueries = suiteData.testQueries;
  if (suiteData.allowedFields) config.allowedFields = suiteData.allowedFields;
  if (suiteData.requiredFilters) config.requiredFilters = suiteData.requiredFilters;
  if (suiteData.disallowedJoins) config.disallowedJoins = suiteData.disallowedJoins;
  if (suiteData.contracts) config.contracts = suiteData.contracts;
  if (suiteData.datasets) config.datasets = suiteData.datasets;
  if (suiteData.privacyThresholds) config.privacyThresholds = suiteData.privacyThresholds;
  if (suiteData.statisticalFidelityTargets) config.statisticalFidelityTargets = suiteData.statisticalFidelityTargets;

  const configStr = JSON.stringify(config, null, 2);
  
  return `/**
 * ${suiteData.name}
 * ${suiteData.description || `Test suite for ${suiteData.application || suiteData.applicationId}`}
 */

import { TestSuite } from '../core/types';

export const ${varName}: TestSuite = ${configStr};
`;
}

const handleSaveDraft = (suiteData: any) => {
  // Same as save, but could mark as draft
  handleSaveTestSuite(suiteData);
};

const getTestTypes = (suiteData: any): string[] => {
  const types: string[] = [];
  if (suiteData.includeAccessControlTests) types.push('Access Control');
  if (suiteData.includeDataBehaviorTests) types.push('Data Behavior');
  if (suiteData.includeContractTests) types.push('Contract');
  if (suiteData.includeDatasetHealthTests) types.push('Dataset Health');
  return types;
};

const closeModal = () => {
  showCreateModal.value = false;
  editingSuite.value = null;
  editingSuiteData.value = null;
};

const editSource = (id: string) => {
  editingSourceSuiteId.value = id;
  showSourceEditor.value = true;
};

const closeSourceEditor = () => {
  showSourceEditor.value = false;
  editingSourceSuiteId.value = null;
};

const handleSourceSaved = async () => {
  await loadTestSuites();
};

const formatDate = (date: Date | undefined): string => {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const formatTime = (date: Date | undefined): string => {
  if (!date) return 'N/A';
  return date.toLocaleTimeString();
};

const formatRelativeTime = (date: Date | undefined): string => {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data;
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

// Watch for route query changes to update active tab
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    const validTabs = ['batteries', 'harnesses', 'suites', 'library', 'findings'];
    if (validTabs.includes(newTab)) {
      activeTab.value = newTab as any;
    }
  }
});

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/applications');
    applications.value = response.data || [];
  } catch (err) {
    console.error('Error loading applications:', err);
    applications.value = [];
  }
};

onMounted(async () => {
  await Promise.all([
    loadValidators(),
    loadTestSuites(),
    loadConfigurations(),
    loadTestResults(),
    loadTestBatteries(),
    loadTestHarnesses(),
    loadApplications()
  ]);
  
  // Load last run statuses for all test types
  await loadLastRunStatusForTypes();
  
  // If there's a type query parameter, ensure we're on library tab
  if (route.query.type && activeTab.value !== 'library') {
    switchTab('library');
  }
});

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

// Overview computed properties
const configurationsCount = computed(() => configurations.value.length);

const passRate = computed(() => {
  if (!testResults.value || testResults.value.length === 0) return 0;
  const passed = testResults.value.filter(r => r.passed).length;
  return (passed / testResults.value.length) * 100;
});

const activeSuitesCount = computed(() => {
  if (!testSuites.value) return 0;
  return testSuites.value.filter(s => s.enabled).length;
});

const last24hRuns = computed(() => {
  if (!testResults.value) return 0;
  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  return testResults.value.filter(r => {
    const timestamp = r.timestamp instanceof Date ? r.timestamp : new Date(r.timestamp);
    return timestamp >= yesterday;
  }).length;
});

const getHealthClass = (rate: number): string => {
  if (rate >= 90) return 'health-excellent';
  if (rate >= 70) return 'health-good';
  if (rate >= 50) return 'health-warning';
  return 'health-poor';
};

// Test Types computed properties
const getConfigCountForType = (type: string): number => {
  return configurations.value.filter(c => c.type === type).length;
};

// Store last run status for each test type
const lastRunStatusForTypes = ref<Record<string, string>>({});

const loadLastRunStatusForTypes = async () => {
  // Load last run status for each test type
  const typePromises = testTypes.map(async (testType) => {
    const typeConfigs = configurations.value.filter(c => c.type === testType.type);
    if (typeConfigs.length === 0) {
      lastRunStatusForTypes.value[testType.type] = undefined as any;
      return;
    }
    
    try {
      // Get the most recent test result for any configuration of this type
      const resultsPromises = typeConfigs.map(async (config) => {
        try {
          const response = await axios.get(`/api/test-results/test-configuration/${config.id}?limit=1`);
          return response.data && response.data.length > 0 ? response.data[0] : null;
        } catch (err) {
          return null;
        }
      });

      const results = await Promise.all(resultsPromises);
      const validResults = results.filter(r => r !== null);
      
      if (validResults.length > 0) {
        // Sort by timestamp and get the most recent
        validResults.sort((a, b) => {
          const timeA = new Date(a.timestamp).getTime();
          const timeB = new Date(b.timestamp).getTime();
          return timeB - timeA;
        });
        
        const mostRecent = validResults[0];
        lastRunStatusForTypes.value[testType.type] = mostRecent.status === 'passed' ? 'passed' : 'failed';
      } else {
        lastRunStatusForTypes.value[testType.type] = undefined as any;
      }
    } catch (err) {
      console.error(`Error loading last run status for type ${testType.type}:`, err);
      lastRunStatusForTypes.value[testType.type] = undefined as any;
    }
  });
  
  await Promise.all(typePromises);
};

const getLastRunStatusForType = (type: string): string | undefined => {
  return lastRunStatusForTypes.value[type];
};

// Configurations computed properties
const configTypeOptions = computed(() => {
  return [
    { label: 'All Types', value: '' },
    ...testTypes.map(t => ({ label: t.name, value: t.type }))
  ];
});

const filteredConfigurations = computed(() => {
  return configurations.value.filter(config => {
    const matchesSearch = !configSearchQuery.value ||
      config.name.toLowerCase().includes(configSearchQuery.value.toLowerCase()) ||
      (config.description && config.description.toLowerCase().includes(configSearchQuery.value.toLowerCase()));
    const matchesType = !configFilterType.value || config.type === configFilterType.value;
    return matchesSearch && matchesType;
  });
});

const getTypeLabel = (type: string): string => {
  const typeMap: Record<string, string> = {
    'api-gateway': 'API Gateway',
    'dlp': 'DLP',
    'network-policy': 'Network Policy',
    'api-security': 'API Security',
    'rls-cls': 'RLS/CLS',
    'distributed-systems': 'Distributed Systems'
  };
  return typeMap[type] || type;
};

// Load test results for better relationship tracking
const loadTestResults = async () => {
  try {
    const response = await axios.get('/api/test-results?limit=100');
    if (response.data) {
      // Update testResults with real data
      testResults.value = response.data.map((r: any) => ({
        ...r,
        timestamp: r.timestamp ? new Date(r.timestamp) : new Date(),
        passed: r.status === 'passed'
      }));
    }
  } catch (err) {
    console.error('Error loading test results:', err);
  }
};

const getUsedByCount = (configId: string): number => {
  return testSuites.value.filter(s => 
    s.testConfigurationIds && s.testConfigurationIds.includes(configId)
  ).length;
};

const getUsedBySuites = (configId: string): string[] => {
  return testSuites.value
    .filter(s => s.testConfigurationIds && s.testConfigurationIds.includes(configId))
    .map(s => s.id);
};

const getSuiteName = (suiteId: string): string => {
  const suite = testSuites.value.find(s => s.id === suiteId);
  return suite?.name || suiteId;
};

const getLastRunForConfig = (configId: string): string => {
  // This will be populated when we load test results
  const lastRun = lastRunForConfigs.value[configId];
  if (!lastRun) return 'Never';
  
  const now = new Date();
  const diffMs = now.getTime() - new Date(lastRun).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return new Date(lastRun).toLocaleDateString();
};

const lastRunForConfigs = ref<Record<string, string>>({});

const loadLastRunsForConfigs = async () => {
  // Load last run timestamp for each configuration
  const configIds = configurations.value.map(c => c.id);
  
  const promises = configIds.map(async (configId) => {
    try {
      const response = await axios.get(`/api/test-results/test-configuration/${configId}?limit=1`);
      if (response.data && response.data.length > 0) {
        lastRunForConfigs.value[configId] = response.data[0].timestamp;
      }
    } catch (err) {
      // Ignore errors
    }
  });
  
  await Promise.all(promises);
};

// Configuration handlers
const loadConfigurations = async () => {
  loadingConfigs.value = true;
  configsError.value = null;
  try {
    const response = await axios.get('/api/test-configurations');
    configurations.value = response.data || [];
    // Load last run timestamps for configurations
    await loadLastRunsForConfigs();
    // Reload last run statuses for types after configurations load
    await loadLastRunStatusForTypes();
  } catch (err: any) {
    configsError.value = err.response?.data?.message || 'Failed to load configurations';
    console.error('Error loading configurations:', err);
  } finally {
    loadingConfigs.value = false;
  }
};

const handleEditConfig = (config: any) => {
  editingConfig.value = config;
  showCreateConfigModal.value = true;
};

const handleViewResult = (result: any) => {
  selectedResult.value = result;
  showResultDetail.value = true;
};

const editConfiguration = (config: any) => {
  editingConfig.value = config;
  showCreateConfigModal.value = true;
};

// Test execution removed - tests run automatically in CI/CD

const deleteConfiguration = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-configurations/${id}`);
    await loadConfigurations();
    await loadLastRunStatusForTypes(); // Refresh type statuses
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to delete configuration');
  }
};

const closeConfigModal = () => {
  showCreateConfigModal.value = false;
  editingConfig.value = null;
};

const handleSaveConfig = async (configData: any) => {
  try {
    if (editingConfig.value) {
      await axios.put(`/api/test-configurations/${editingConfig.value.id}`, configData);
    } else {
      await axios.post('/api/test-configurations', configData);
    }
    await loadConfigurations();
    await loadLastRunStatusForTypes(); // Refresh type statuses
    closeConfigModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to save configuration');
  }
};
</script>

<style scoped>
.tests-page {
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
  padding: 0.5rem;
  background: transparent;
  border: none;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
  color: #4facfe;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon.btn-danger {
  color: #fc8181;
}

.btn-icon.btn-danger:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
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

.filters {
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
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.test-suites-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.test-suite-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.test-suite-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.suite-header {
  margin-bottom: 20px;
}

.suite-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.suite-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.suite-status-badges {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.suite-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.enabled-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.enabled-badge.enabled {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.enabled-badge.disabled {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.source-type-badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.source-type-badge.typescript {
  background: rgba(49, 120, 198, 0.2);
  color: #3178c6;
  border: 1px solid rgba(49, 120, 198, 0.3);
}

.source-type-badge.json {
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
  border: 1px solid rgba(255, 193, 7, 0.3);
}

.status-passing {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failing {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-pending {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.suite-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.source-path {
  font-size: 0.75rem;
  color: #718096;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
}

.suite-stats {
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

.stat-value.score {
  font-size: 1rem;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.suite-types {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.test-type-badge {
  padding: 4px 10px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.suite-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
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

.action-btn.warning-btn {
  color: #ed8936;
  border-color: rgba(237, 137, 54, 0.3);
}

.action-btn.warning-btn:hover {
  background: rgba(237, 137, 54, 0.1);
  border-color: rgba(237, 137, 54, 0.5);
}

.delete-btn {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
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

.run-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.execution-view {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.execution-header {
  margin-bottom: 24px;
}

.execution-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.execution-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
  display: inline-block;
}

.status-running {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.execution-progress {
  margin-top: 16px;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 8px;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.progress-text {
  font-size: 0.875rem;
  color: #a0aec0;
}

.execution-summary {
  margin-bottom: 24px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.summary-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}

.summary-stat {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.summary-stat .stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.summary-stat .stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.summary-stat .stat-value.passed {
  color: #22c55e;
}

.summary-stat .stat-value.failed {
  color: #fc8181;
}

.execution-errors {
  margin-top: 20px;
}

.errors-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 1rem;
  font-weight: 600;
  color: #fc8181;
  margin: 0 0 12px 0;
}

.error-icon {
  width: 18px;
  height: 18px;
}

.error-item {
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 6px;
  margin-bottom: 8px;
}

.error-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.error-test {
  font-weight: 600;
  color: #ffffff;
  font-size: 0.9rem;
}

.error-type {
  padding: 2px 8px;
  background: rgba(252, 129, 129, 0.2);
  border-radius: 4px;
  color: #fc8181;
  font-size: 0.75rem;
  font-weight: 500;
}

.error-message {
  color: #fc8181;
  font-size: 0.875rem;
  margin-bottom: 8px;
}

.error-stack {
  margin: 8px 0 0 0;
  padding: 8px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 4px;
  color: #a0aec0;
  font-size: 0.75rem;
  font-family: 'Courier New', monospace;
  white-space: pre-wrap;
  overflow-x: auto;
}

.execution-log {
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  padding: 16px;
}

.log-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.log-header h3 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-small-text {
  padding: 4px 8px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 4px;
  color: #4facfe;
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small-text:hover {
  background: rgba(79, 172, 254, 0.1);
}

.log-content {
  max-height: 400px;
  overflow-y: auto;
}

.log-entry {
  display: grid;
  grid-template-columns: 80px 60px 1fr;
  gap: 12px;
  padding: 8px 0;
  font-size: 0.875rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  align-items: center;
}

.log-entry:last-child {
  border-bottom: none;
}

.log-time {
  color: #718096;
  font-family: monospace;
  font-size: 0.75rem;
}

.log-level {
  font-size: 0.75rem;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 4px;
  text-align: center;
}

.log-entry.log-info .log-level {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.log-entry.log-success .log-level {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.log-entry.log-error .log-level {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.log-message {
  color: #a0aec0;
}

.log-entry.log-info .log-message {
  color: #4facfe;
}

.log-entry.log-success .log-message {
  color: #22c55e;
}

.log-entry.log-error .log-message {
  color: #fc8181;
}

.results-filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.result-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.result-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateX(4px);
}

.result-header {
  margin-bottom: 12px;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.result-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.result-status {
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.result-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.result-type {
  text-transform: capitalize;
}

.result-validator {
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.result-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 6px;
  color: #fc8181;
  font-size: 0.875rem;
}

.error-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.result-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
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

.suite-form {
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
.form-group select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #a0aec0;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
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

/* Overview Tab Styles */
.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.stats-cards {
  grid-column: 1 / -1;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.stat-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-icon-wrapper {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: rgba(79, 172, 254, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stat-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.quick-actions,
.recent-runs,
.how-it-works {
  grid-column: 1 / -1;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.relationship-explanation {
  display: flex;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
  justify-content: center;
}

.relationship-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  flex: 1;
  min-width: 200px;
  max-width: 300px;
}

.relationship-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: rgba(79, 172, 254, 0.15);
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid rgba(79, 172, 254, 0.3);
}

.relationship-icon .icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.relationship-content {
  text-align: center;
}

.relationship-content h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.relationship-content p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.5;
}

.relationship-arrow {
  font-size: 1.5rem;
  color: #4facfe;
  font-weight: 600;
  flex-shrink: 0;
}

@media (max-width: 768px) {
  .relationship-explanation {
    flex-direction: column;
  }
  
  .relationship-arrow {
    transform: rotate(90deg);
  }
}

.health-dashboard {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
}

.action-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  transition: all 0.2s;
}

.action-card:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.action-icon {
  width: 24px;
  height: 24px;
}

.empty-state-small {
  padding: 24px;
  text-align: center;
  color: #718096;
}

.runs-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.run-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.run-item:hover {
  background: rgba(15, 20, 25, 0.6);
}

.run-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.run-name {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.run-type {
  font-size: 0.75rem;
  color: #718096;
}

.run-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.run-status.passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.run-status.failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.run-time {
  color: #718096;
  font-size: 0.75rem;
}

.health-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.health-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.health-label {
  font-size: 0.75rem;
  color: #718096;
}

.health-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.health-value.health-excellent {
  color: #22c55e;
}

.health-value.health-good {
  color: #4facfe;
}

.health-value.health-warning {
  color: #fbbf24;
}

.health-value.health-poor {
  color: #fc8181;
}

/* Test Types Tab Styles */
.test-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

/* Configurations Tab Styles */
.configurations-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  gap: 16px;
  flex-wrap: wrap;
}

.configurations-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.configuration-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.configuration-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.config-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.config-title-section {
  flex: 1;
}

.config-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.config-type-badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 500;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.config-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 16px 0;
}

.config-meta {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.meta-item {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.meta-label {
  color: #718096;
}

.meta-value {
  color: #ffffff;
  font-weight: 500;
}

.used-by-list {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 4px;
}

.suite-badge {
  padding: 2px 8px;
  border-radius: 4px;
  background: rgba(79, 172, 254, 0.15);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: help;
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Test Batteries and Harnesses Styles */
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.section-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
}

.section-description {
  color: #a0aec0;
  margin: 0;
  font-size: 0.875rem;
}

.info-banner {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  background: #fff3cd;
  border: 1px solid #ffc107;
  border-radius: 8px;
  margin-bottom: 1.5rem;
  color: #856404;
}

.info-banner .info-icon {
  flex-shrink: 0;
}

.info-banner p {
  margin: 0;
  font-size: 0.875rem;
}

.batteries-grid,
.harnesses-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1.5rem;
}

.battery-card,
.harness-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 1.5rem;
  background: white;
  transition: all 0.2s;
  display: flex;
  justify-content: space-between;
  gap: 1rem;
}

.battery-content,
.harness-content {
  flex: 1;
  cursor: pointer;
}

.battery-card:hover,
.harness-card:hover {
  border-color: #4facfe;
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.15);
  transform: translateY(-2px);
}

.battery-actions,
.harness-actions {
  display: flex;
  gap: 0.5rem;
  align-items: flex-start;
}

.btn-icon {
  padding: 0.5rem;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
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
  border-color: rgba(79, 172, 254, 0.4);
}

.icon-small {
  width: 16px;
  height: 16px;
}

.battery-header,
.harness-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.75rem;
}

.battery-name,
.harness-name {
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0;
  color: #1a202c;
}

.battery-badge,
.harness-badges {
  display: flex;
  gap: 0.5rem;
}

.badge {
  padding: 0.25rem 0.75rem;
  background: #e3f2fd;
  color: #1976d2;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.battery-description,
.harness-description {
  color: #718096;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
  line-height: 1.5;
}

.battery-meta,
.harness-meta {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  padding-top: 0.75rem;
  border-top: 1px solid #e2e8f0;
}

.team-badge {
  padding: 0.25rem 0.75rem;
  background: #f5f5f5;
  border-radius: 4px;
  font-size: 0.75rem;
  color: #666;
}

.execution-mode {
  padding: 0.25rem 0.75rem;
  background: #e8f5e9;
  color: #2e7d32;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.suite-harnesses {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
  padding-top: 0.5rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.harness-label {
  font-size: 0.75rem;
  color: #718096;
  font-weight: 500;
}

.harness-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.harness-badge:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-1px);
}

.result-risk-management {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.risk-badge {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.risk-badge.risk-pending {
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  color: #fbbf24;
}

.risk-badge.risk-accepted {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.risk-badge.risk-remediated {
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.badge-icon {
  width: 14px;
  height: 14px;
}

.ticket-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #4facfe;
  font-size: 0.875rem;
}

.ticket-link a {
  color: #4facfe;
  text-decoration: none;
}

.ticket-link a:hover {
  text-decoration: underline;
}

.ticket-icon {
  width: 14px;
  height: 14px;
}

.btn-warning {
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  color: #fbbf24;
}

.btn-warning:hover {
  background: rgba(251, 191, 36, 0.2);
}

/* Risk Acceptance Modal Styles */
.risk-modal,
.ticket-modal {
  max-width: 600px;
}

.risk-form,
.ticket-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.result-summary {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 6px;
}

.result-type-badge {
  padding: 0.25rem 0.5rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 4px;
  font-size: 0.75rem;
  color: #4facfe;
}

.form-textarea,
.form-input {
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: inherit;
}

.form-textarea:focus,
.form-input:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.4);
}

.form-textarea {
  resize: vertical;
  min-height: 80px;
}

.form-actions {
  display: flex;
  gap: 0.75rem;
  justify-content: flex-end;
  margin-top: 0.5rem;
}

.btn-primary {
  padding: 0.75rem 1.5rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #0f1419;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-secondary {
  padding: 0.75rem 1.5rem;
  background: rgba(160, 174, 192, 0.1);
  border: 1px solid rgba(160, 174, 192, 0.3);
  border-radius: 6px;
  color: #a0aec0;
  font-weight: 500;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(160, 174, 192, 0.2);
}

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
  background: #1a1f2e;
  border-radius: 16px;
  width: 100%;
  max-width: 500px;
  max-height: 80vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1.5rem 2rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
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
  padding: 2rem;
  overflow-y: auto;
  flex: 1;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.remediation-badge {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.375rem 0.75rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.remediation-badge.remediation-not-started {
  background: rgba(160, 174, 192, 0.1);
  border: 1px solid rgba(160, 174, 192, 0.3);
  color: #a0aec0;
}

.remediation-badge.remediation-in-progress {
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.remediation-badge.remediation-completed {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.remediation-badge.remediation-verified {
  background: rgba(34, 197, 94, 0.2);
  border: 1px solid rgba(34, 197, 94, 0.4);
  color: #22c55e;
}

.progress-text {
  font-size: 0.75rem;
  opacity: 0.8;
}

.remediation-modal {
  max-width: 600px;
}

.remediation-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.progress-bar-container {
  width: 100%;
  height: 8px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 4px;
  overflow: hidden;
  margin-top: 0.5rem;
}

.progress-bar {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s ease;
}

/* Findings View Tabs */
.findings-tabs {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.view-tab {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.view-tab:hover {
  color: #4facfe;
}

.view-tab.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 16px;
  height: 16px;
}

/* Timeline View Styles */
.timeline-view {
  padding: 1rem 0;
}

.timeline-container {
  max-width: 900px;
  margin: 0 auto;
}

.timeline-group {
  margin-bottom: 3rem;
}

.timeline-date-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  padding-bottom: 0.75rem;
  border-bottom: 2px solid rgba(79, 172, 254, 0.2);
}

.date-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.timeline-date-header h3 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  flex: 1;
}

.date-count {
  font-size: 0.875rem;
  color: #718096;
}

.timeline-items {
  position: relative;
  padding-left: 2rem;
}

.timeline-items::before {
  content: '';
  position: absolute;
  left: 0.5rem;
  top: 0;
  bottom: 0;
  width: 2px;
  background: rgba(79, 172, 254, 0.2);
}

.timeline-item {
  position: relative;
  margin-bottom: 2rem;
  padding-left: 2rem;
}

.timeline-item:last-child {
  margin-bottom: 0;
}

.timeline-marker {
  position: absolute;
  left: -1.5rem;
  top: 0.25rem;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(15, 20, 25, 0.8);
  border: 2px solid rgba(79, 172, 254, 0.3);
  z-index: 1;
}

.timeline-item.passed .timeline-marker {
  border-color: rgba(34, 197, 94, 0.5);
  background: rgba(34, 197, 94, 0.1);
}

.timeline-item.failed .timeline-marker {
  border-color: rgba(252, 129, 129, 0.5);
  background: rgba(252, 129, 129, 0.1);
}

.marker-icon {
  width: 18px;
  height: 18px;
}

.timeline-item.passed .marker-icon {
  color: #22c55e;
}

.timeline-item.failed .marker-icon {
  color: #fc8181;
}

.timeline-content {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  transition: all 0.2s;
}

.timeline-content:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.timeline-time {
  font-size: 0.75rem;
  color: #718096;
  margin-bottom: 0.5rem;
}

.timeline-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.timeline-meta {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  margin-bottom: 0.5rem;
}

.timeline-type,
.timeline-validator {
  font-size: 0.875rem;
  color: #a0aec0;
}

.timeline-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.2);
  border-radius: 6px;
  color: #fc8181;
  font-size: 0.875rem;
  margin-top: 0.75rem;
}

.error-icon-small {
  width: 16px;
  height: 16px;
}

.timeline-actions {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-link {
  background: transparent;
  border: none;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  text-decoration: underline;
  padding: 0;
}

.btn-link:hover {
  color: #00f2fe;
}
</style>
