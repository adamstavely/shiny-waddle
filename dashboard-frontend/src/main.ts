import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import './style.css';
import './styles/design-tokens.css';
import './styles/utilities.css';
import './styles/accessibility.css';
import './styles/responsive.css';

createApp(App).use(router).mount('#app');

