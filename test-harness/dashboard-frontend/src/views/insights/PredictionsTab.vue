<template>
  <div class="predictions-tab">
    <div class="page-header">
      <div class="header-content">
        <div>
          <h2 class="section-title">
            <TrendingUp class="section-icon" />
            Predictive Analytics
          </h2>
          <p class="page-description">Forecast future risks, vulnerabilities, and compliance trends</p>
        </div>
      </div>
    </div>

    <div class="coming-soon">
      <div class="coming-soon-content">
        <TrendingUp class="icon" />
        <h3>Predictive Analytics Coming Soon</h3>
        <p>We're building advanced predictive models to help you:</p>
        <ul class="features-list">
          <li>
            <Shield class="feature-icon" />
            <div>
              <strong>Risk Prediction</strong>
              <span>Forecast future security risks based on historical patterns</span>
            </div>
          </li>
          <li>
            <AlertTriangle class="feature-icon" />
            <div>
              <strong>Vulnerability Prediction</strong>
              <span>Identify likely vulnerabilities before they become issues</span>
            </div>
          </li>
          <li>
            <TrendingDown class="feature-icon" />
            <div>
              <strong>Compliance Drift Prediction</strong>
              <span>Predict when compliance scores may decline</span>
            </div>
          </li>
          <li>
            <Server class="feature-icon" />
            <div>
              <strong>Resource Needs Prediction</strong>
              <span>Forecast compute and storage requirements</span>
            </div>
          </li>
        </ul>
        <p class="note">This feature will use machine learning models to analyze historical data and provide actionable insights.</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { TrendingUp, Shield, AlertTriangle, TrendingDown, Server } from 'lucide-vue-next';

defineProps<{
  sharedFilters: {
    timeRange: string;
    applications: string[];
    teams: string[];
    categories: string[];
  };
}>();
</script>

<style scoped>
.predictions-tab {
  width: 100%;
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

.section-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.section-icon {
  width: 28px;
  height: 28px;
  color: #4facfe;
  flex-shrink: 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.coming-soon {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 500px;
  padding: 60px 40px;
}

.coming-soon-content {
  text-align: center;
  max-width: 600px;
}

.coming-soon-content .icon {
  width: 80px;
  height: 80px;
  color: #4facfe;
  margin: 0 auto 32px;
  opacity: 0.7;
}

.coming-soon-content h3 {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 16px;
}

.coming-soon-content > p {
  font-size: 1.1rem;
  color: #a0aec0;
  margin-bottom: 32px;
}

.features-list {
  list-style: none;
  padding: 0;
  margin: 0 0 32px 0;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.features-list li {
  display: flex;
  gap: 16px;
  align-items: flex-start;
  padding: 20px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  transition: all 0.3s;
}

.features-list li:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.feature-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 2px;
}

.features-list li div {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.features-list li strong {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}

.features-list li span {
  font-size: 0.875rem;
  color: #a0aec0;
}

.note {
  font-size: 0.875rem;
  color: #718096;
  font-style: italic;
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}
</style>

