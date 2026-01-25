export interface User {
  id: string;
  email: string;
  name: string;
  passwordHash?: string; // Optional for backward compatibility
  roles: string[];
  applicationIds: string[];
  teamNames: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

