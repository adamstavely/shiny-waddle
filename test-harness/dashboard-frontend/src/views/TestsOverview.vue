<template>
  <div class="tests-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section with SVG Diagram -->
    <div class="hero-section">
      <div class="hero-card">
        <div class="hero-header">
          <h1 class="hero-title">Test Management Overview</h1>
          <p class="hero-description">
            Understand how test configurations, suites, harnesses, and batteries work together
          </p>
        </div>
        
        <!-- SVG Hierarchy Diagram -->
        <div class="diagram-container">
          <svg viewBox="0 0 1000 600" class="hierarchy-diagram">
            <!-- Background -->
            <rect width="1000" height="600" fill="transparent" />
            
            <!-- Level 1: Test Configurations -->
            <g class="diagram-level" data-level="configs">
              <rect x="50" y="50" width="180" height="100" rx="8" class="diagram-box config-box" />
              <text x="140" y="95" text-anchor="middle" class="diagram-title">Test Configurations</text>
              <text x="140" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.configurations }}</text>
            </g>
            
            <!-- Level 2: Individual Tests -->
            <g class="diagram-level" data-level="tests">
              <rect x="300" y="50" width="180" height="100" rx="8" class="diagram-box test-box" />
              <text x="390" y="95" text-anchor="middle" class="diagram-title">Individual Tests</text>
              <text x="390" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.tests }}</text>
            </g>
            
            <!-- Level 3: Test Suites -->
            <g class="diagram-level" data-level="suites">
              <rect x="550" y="50" width="180" height="100" rx="8" class="diagram-box suite-box" />
              <text x="640" y="95" text-anchor="middle" class="diagram-title">Test Suites</text>
              <text x="640" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.suites }}</text>
            </g>
            
            <!-- Level 4: Test Harnesses -->
            <g class="diagram-level" data-level="harnesses">
              <rect x="300" y="250" width="180" height="100" rx="8" class="diagram-box harness-box" />
              <text x="390" y="295" text-anchor="middle" class="diagram-title">Test Harnesses</text>
              <text x="390" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.harnesses }}</text>
            </g>
            
            <!-- Level 5: Test Batteries -->
            <g class="diagram-level" data-level="batteries">
              <rect x="550" y="250" width="180" height="100" rx="8" class="diagram-box battery-box" />
              <text x="640" y="295" text-anchor="middle" class="diagram-title">Test Batteries</text>
              <text x="640" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.batteries }}</text>
            </g>
            
            <!-- Arrows -->
            <!-- Configs → Tests -->
            <path d="M 230 100 L 300 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
            
            <!-- Tests → Suites -->
            <path d="M 480 100 L 550 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
            
            <!-- Suites → Harnesses -->
            <path d="M 640 150 L 390 250" class="diagram-arrow" marker-end="url(#arrowhead)" />
            
            <!-- Harnesses → Batteries -->
            <path d="M 480 300 L 550 300" class="diagram-arrow" marker-end="url(#arrowhead)" />
            
            <!-- Arrow marker definition -->
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                <polygon points="0 0, 10 3, 0 6" class="arrow-fill" />
              </marker>
            </defs>
          </svg>
        </div>
        
        <!-- Relationship Explanation -->
        <div class="relationship-explanation">
          <h3>How It Works</h3>
          <div class="explanation-steps">
            <div class="step">
              <div class="step-number">1</div>
              <div class="step-content">
                <strong>Test Configurations</strong> define how tests should run (user roles, policies, settings)
              </div>
            </div>
            <div class="step">
              <div class="step-number">2</div>
              <div class="step-content">
                <strong>Individual Tests</strong> use configurations to validate specific security requirements
              </div>
            </div>
            <div class="step">
              <div class="step-number">3</div>
              <div class="step-content">
                <strong>Test Suites</strong> group related tests together for organized execution
              </div>
            </div>
            <div class="step">
              <div class="step-number">4</div>
              <div class="step-content">
                <strong>Test Harnesses</strong> collect suites and assign them to applications
              </div>
            </div>
            <div class="step">
              <div class="step-number">5</div>
              <div class="step-content">
                <strong>Test Batteries</strong> execute multiple harnesses together with execution configuration
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card" @click="navigateTo('/tests/configurations')">
          <Settings class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.configurations }}</div>
            <div class="stat-label">Test Configurations</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/suites')">
          <List class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.suites }}</div>
            <div class="stat-label">Test Suites</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/harnesses')">
          <Layers class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.harnesses }}</div>
            <div class="stat-label">Test Harnesses</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/batteries')">
          <Battery class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.batteries }}</div>
            <div class="stat-label">Test Batteries</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/findings')">
          <AlertCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.findings }}</div>
            <div class="stat-label">Active Findings</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/tests/batteries')" class="action-card">
          <Battery class="action-icon" />
          <span>View Test Batteries</span>
        </button>
        <button @click="navigateTo('/tests/harnesses')" class="action-card">
          <Layers class="action-icon" />
          <span>View Test Harnesses</span>
        </button>
        <button @click="navigateTo('/tests/suites')" class="action-card">
          <List class="action-icon" />
          <span>View Test Suites</span>
        </button>
        <button @click="navigateTo('/tests/library')" class="action-card">
          <BookOpen class="action-icon" />
          <span>Browse Test Library</span>
        </button>
        <button @click="navigateTo('/tests/findings')" class="action-card">
          <AlertCircle class="action-icon" />
          <span>View Findings</span>
        </button>
        <button @click="navigateTo('/tests/suites/builder')" class="action-card">
          <Plus class="action-icon" />
          <span>Create Test Suite</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Battery,
  Layers,
  List,
  BookOpen,
  AlertCircle,
  Settings,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' }
];

const stats = ref({
  configurations: 0,
  tests: 0,
  suites: 0,
  harnesses: 0,
  batteries: 0,
  findings: 0
});

const loadStats = async () => {
  try {
    const [configsRes, suitesRes, harnessesRes, batteriesRes, resultsRes] = await Promise.all([
      axios.get('/api/test-configurations').catch(() => ({ data: [] })),
      axios.get('/api/test-suites').catch(() => ({ data: [] })),
      axios.get('/api/test-harnesses').catch(() => ({ data: [] })),
      axios.get('/api/test-batteries').catch(() => ({ data: [] })),
      axios.get('/api/test-results?limit=1000').catch(() => ({ data: [] }))
    ]);
    
    stats.value = {
      configurations: configsRes.data?.length || 0,
      tests: configsRes.data?.length || 0, // Approximate
      suites: suitesRes.data?.length || 0,
      harnesses: harnessesRes.data?.length || 0,
      batteries: batteriesRes.data?.length || 0,
      findings: resultsRes.data?.filter((r: any) => !r.passed || r.status === 'failed').length || 0
    };
  } catch (err) {
    console.error('Error loading stats:', err);
  }
};

const navigateTo = (path: string) => {
  router.push(path);
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.tests-overview-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.hero-section {
  margin-bottom: 3rem;
}

.hero-card {
  background: linear-gradient(135deg, rgba(79, 172, 254, 0.1) 0%, rgba(0, 242, 254, 0.1) 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  padding: 2rem;
}

.hero-header {
  text-align: center;
  margin-bottom: 2rem;
}

.hero-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.hero-description {
  font-size: 1.125rem;
  color: #a0aec0;
  margin: 0;
}

.diagram-container {
  display: flex;
  justify-content: center;
  margin: 2rem 0;
  padding: 2rem;
  background: rgba(15, 20, 25, 0.5);
  border-radius: 12px;
}

.hierarchy-diagram {
  width: 100%;
  max-width: 1000px;
  height: auto;
}

.diagram-box {
  fill: rgba(79, 172, 254, 0.15);
  stroke: rgba(79, 172, 254, 0.5);
  stroke-width: 2;
  transition: all 0.3s;
}

.diagram-box:hover {
  fill: rgba(79, 172, 254, 0.25);
  stroke: rgba(79, 172, 254, 0.8);
}

.config-box {
  fill: rgba(79, 172, 254, 0.15);
}

.test-box {
  fill: rgba(0, 242, 254, 0.15);
}

.suite-box {
  fill: rgba(139, 92, 246, 0.15);
}

.harness-box {
  fill: rgba(236, 72, 153, 0.15);
}

.battery-box {
  fill: rgba(251, 191, 36, 0.15);
}

.diagram-title {
  fill: #ffffff;
  font-size: 14px;
  font-weight: 600;
}

.diagram-subtitle {
  fill: #4facfe;
  font-size: 12px;
  font-weight: 500;
}

.diagram-arrow {
  stroke: rgba(79, 172, 254, 0.6);
  stroke-width: 2;
  fill: none;
}

.arrow-fill {
  fill: rgba(79, 172, 254, 0.6);
}

.relationship-explanation {
  margin-top: 2rem;
  padding-top: 2rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.relationship-explanation h3 {
  color: #ffffff;
  font-size: 1.5rem;
  margin-bottom: 1.5rem;
}

.explanation-steps {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1.5rem;
}

.step {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
}

.step-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  flex-shrink: 0;
}

.step-content {
  flex: 1;
  color: #a0aec0;
  font-size: 0.875rem;
  line-height: 1.5;
}

.step-content strong {
  color: #ffffff;
  display: block;
  margin-bottom: 0.25rem;
}

.stats-section,
.actions-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 1.5rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
}

.stat-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.stat-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.stat-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.action-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
}

.action-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
}
</style>

