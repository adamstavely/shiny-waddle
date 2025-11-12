<template>
  <div class="access-denied">
    <div class="access-denied-container">
      <!-- Background decoration -->
      <div class="background-decoration" aria-hidden="true">
        <div class="decoration-circle circle-1"></div>
        <div class="decoration-circle circle-2"></div>
        <div class="decoration-circle circle-3"></div>
      </div>

      <!-- Main content -->
      <div class="access-denied-content">
        <!-- Custom SVG Icon -->
        <div class="error-icon" aria-hidden="true">
          <svg viewBox="0 0 200 200" class="access-denied-svg" preserveAspectRatio="xMidYMid meet">
            <defs>
              <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#4facfe;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:1" />
              </linearGradient>
              <linearGradient id="lockGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:#fc8181;stop-opacity:1" />
                <stop offset="100%" style="stop-color:#ef4444;stop-opacity:1" />
              </linearGradient>
            </defs>
            
            <!-- Shield base -->
            <path 
              d="M 100 20 L 140 35 L 140 75 Q 140 110 100 145 Q 60 110 60 75 L 60 35 Z" 
              fill="url(#shieldGradient)" 
              opacity="0.2"
              stroke="url(#shieldGradient)"
              stroke-width="2"
            />
            
            <!-- Shield middle layer -->
            <path 
              d="M 100 30 L 130 42 L 130 75 Q 130 105 100 135 Q 70 105 70 75 L 70 42 Z" 
              fill="url(#shieldGradient)" 
              opacity="0.3"
              stroke="url(#shieldGradient)"
              stroke-width="1.5"
            />
            
            <!-- Shield inner layer -->
            <path 
              d="M 100 40 L 120 50 L 120 75 Q 120 95 100 125 Q 80 95 80 75 L 80 50 Z" 
              fill="url(#shieldGradient)" 
              opacity="0.4"
            />
            
            <!-- Lock body -->
            <rect 
              x="75" 
              y="90" 
              width="50" 
              height="50" 
              rx="4" 
              fill="url(#lockGradient)" 
              opacity="0.9"
            />
            
            <!-- Lock shackle -->
            <path 
              d="M 85 90 Q 85 70 100 70 Q 115 70 115 90" 
              stroke="url(#lockGradient)" 
              stroke-width="6" 
              fill="none" 
              stroke-linecap="round"
              opacity="0.9"
            />
            
            <!-- Lock keyhole -->
            <circle 
              cx="100" 
              cy="115" 
              r="8" 
              fill="#0f1419" 
              opacity="0.8"
            />
            <rect 
              x="96" 
              y="115" 
              width="8" 
              height="12" 
              fill="#0f1419" 
              opacity="0.8"
            />
            
            <!-- Warning rings -->
            <circle cx="100" cy="100" r="85" fill="none" stroke="url(#lockGradient)" stroke-width="1" opacity="0.2"/>
            <circle cx="100" cy="100" r="75" fill="none" stroke="url(#lockGradient)" stroke-width="1" opacity="0.3"/>
            
            <!-- X mark overlay -->
            <g opacity="0.6">
              <line x1="50" y1="50" x2="150" y2="150" stroke="url(#lockGradient)" stroke-width="4" stroke-linecap="round"/>
              <line x1="150" y1="50" x2="50" y2="150" stroke="url(#lockGradient)" stroke-width="4" stroke-linecap="round"/>
            </g>
          </svg>
        </div>

        <!-- Title and message -->
        <h1 class="error-title">Access Denied</h1>
        <p class="error-message">
          You don't have permission to access this resource.
          <br />
          Please contact your administrator if you believe this is an error.
        </p>

        <!-- Action buttons -->
        <nav class="error-actions" aria-label="Primary navigation actions">
          <router-link to="/" class="btn-primary" aria-label="Go to home page">
            <Home class="btn-icon" aria-hidden="true" />
            <span>Go Home</span>
          </router-link>
          <button @click="goBack" class="btn-secondary" aria-label="Go back to previous page">
            <ArrowLeft class="btn-icon" aria-hidden="true" />
            <span>Go Back</span>
          </button>
        </nav>

        <!-- Help section -->
        <div class="help-section">
          <h2 class="help-title">Need Help?</h2>
          <p class="help-text">
            If you need access to this resource, please contact your system administrator
            or check your role permissions.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router';
import { Home, ArrowLeft } from 'lucide-vue-next';

const router = useRouter();

const goBack = () => {
  if (window.history.length > 1) {
    router.go(-1);
  } else {
    router.push('/');
  }
};
</script>

<style scoped>
.access-denied {
  width: 100%;
  min-height: calc(100vh - 64px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  position: relative;
  overflow: hidden;
}

.access-denied-container {
  position: relative;
  max-width: 800px;
  width: 100%;
  z-index: 10;
}

.background-decoration {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  z-index: 1;
}

.decoration-circle {
  position: absolute;
  border-radius: 50%;
  background: linear-gradient(135deg, rgba(252, 129, 129, 0.1) 0%, rgba(239, 68, 68, 0.1) 100%);
  filter: blur(60px);
  animation: float 20s ease-in-out infinite;
}

.circle-1 {
  width: 400px;
  height: 400px;
  top: -200px;
  left: -200px;
  animation-delay: 0s;
}

.circle-2 {
  width: 300px;
  height: 300px;
  bottom: -150px;
  right: -150px;
  animation-delay: 7s;
}

.circle-3 {
  width: 250px;
  height: 250px;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  animation-delay: 14s;
}

@keyframes float {
  0%, 100% {
    transform: translate(0, 0) scale(1);
    opacity: 0.3;
  }
  50% {
    transform: translate(30px, -30px) scale(1.1);
    opacity: 0.5;
  }
}

.access-denied-content {
  position: relative;
  z-index: 10;
  text-align: center;
  background: linear-gradient(135deg, rgba(26, 31, 46, 0.9) 0%, rgba(45, 55, 72, 0.9) 100%);
  border: 1px solid rgba(252, 129, 129, 0.2);
  border-radius: 24px;
  padding: 64px 48px;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
  backdrop-filter: blur(10px);
}

.error-icon {
  display: flex;
  justify-content: center;
  margin-bottom: 32px;
}

.access-denied-svg {
  width: 200px;
  height: 200px;
  filter: drop-shadow(0 8px 24px rgba(252, 129, 129, 0.3));
  animation: float-icon 3s ease-in-out infinite;
}

@keyframes float-icon {
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-10px);
  }
}

.error-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 16px;
  line-height: 1.2;
  background: linear-gradient(135deg, #fc8181 0%, #ef4444 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.error-message {
  font-size: 1.125rem;
  color: #a0aec0;
  line-height: 1.6;
  margin-bottom: 40px;
  max-width: 500px;
  margin-left: auto;
  margin-right: auto;
}

.error-actions {
  display: flex;
  gap: 16px;
  justify-content: center;
  margin-bottom: 48px;
  flex-wrap: wrap;
}

.btn-primary,
.btn-secondary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 14px 28px;
  border-radius: 12px;
  font-weight: 600;
  font-size: 1rem;
  text-decoration: none;
  transition: all 0.2s;
  border: none;
  cursor: pointer;
  font-family: inherit;
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
  color: #4facfe;
  border: 2px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 20px;
  height: 20px;
}

.help-section {
  border-top: 1px solid rgba(252, 129, 129, 0.2);
  padding-top: 32px;
}

.help-title {
  font-size: 1.125rem;
  color: #ffffff;
  margin-bottom: 12px;
  font-weight: 600;
}

.help-text {
  font-size: 0.875rem;
  color: #a0aec0;
  line-height: 1.6;
  max-width: 500px;
  margin: 0 auto;
}

/* Responsive design */
@media (max-width: 768px) {
  .access-denied {
    padding: 24px 16px;
  }

  .access-denied-content {
    padding: 48px 32px;
  }

  .access-denied-svg {
    width: 150px;
    height: 150px;
  }

  .error-title {
    font-size: 2rem;
  }

  .error-message {
    font-size: 1rem;
  }

  .error-actions {
    flex-direction: column;
    width: 100%;
  }

  .btn-primary,
  .btn-secondary {
    width: 100%;
    justify-content: center;
  }
}

@media (max-width: 480px) {
  .access-denied-svg {
    width: 120px;
    height: 120px;
  }

  .error-title {
    font-size: 1.75rem;
  }
}
</style>

