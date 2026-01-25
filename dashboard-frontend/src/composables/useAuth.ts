import { ref, computed } from 'vue';

export interface UserContext {
  id: string;
  email: string;
  roles: string[];
  applicationIds?: string[];
  teamNames?: string[];
}

// Mock user for development
// In production, this would come from auth context/JWT token
const mockUser: UserContext = {
  id: 'current-user',
  email: 'developer@example.com',
  roles: ['editor', 'cyber-risk-manager'],
  applicationIds: [],
  teamNames: [],
};

const currentUser = ref<UserContext>(mockUser);
const loading = ref(false);

export function useAuth() {
  const loadUser = async () => {
    loading.value = true;
    try {
      // In production, this would fetch from /api/auth/me or similar
      // For now, use mock user
      currentUser.value = mockUser;
    } catch (error: any) {
      console.error('Failed to load user:', error);
      // Fallback to mock user - don't break app if user context fails
      currentUser.value = mockUser;
    } finally {
      loading.value = false;
    }
  };

  const hasRole = (role: string): boolean => {
    return currentUser.value.roles.includes(role);
  };

  const isApprover = computed(() => {
    return hasRole('cyber-risk-manager') || hasRole('data-steward');
  });

  const approverRole = computed<'cyber-risk-manager' | 'data-steward' | null>(() => {
    if (hasRole('cyber-risk-manager')) {
      return 'cyber-risk-manager';
    }
    if (hasRole('data-steward')) {
      return 'data-steward';
    }
    return null;
  });

  const getUserApplications = computed(() => {
    return currentUser.value.applicationIds || [];
  });

  const getUserTeams = computed(() => {
    return currentUser.value.teamNames || [];
  });

  return {
    user: currentUser,
    loading,
    loadUser,
    hasRole,
    isApprover,
    approverRole,
    getUserApplications,
    getUserTeams,
  };
}

