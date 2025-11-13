export interface UserContext {
  id: string;
  email: string;
  roles: string[];
  applicationIds?: string[];
  teamNames?: string[];
}

