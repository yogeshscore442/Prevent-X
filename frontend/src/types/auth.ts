export interface UserMembership {
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  role_name: string;
  permissions: string[];
}

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  is_superuser: boolean;
  is_active: boolean;
  current_organization_id?: string;
  memberships: UserMembership[];
}

export interface LoginResponse {
  user: UserProfile;
  tokens: {
    access_token: string;
    token_type: string;
    expires_in_seconds: number;
    session_id: string;
  };
  message: string;
}

export interface BootstrapPayload {
  bootstrap_token: string;
  email: string;
  password: string;
  full_name: string;
  initial_organization_name: string;
  initial_organization_slug: string;
}

