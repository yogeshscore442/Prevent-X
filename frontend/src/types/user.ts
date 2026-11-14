export interface UserItem {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  last_login_at?: string;
  role_name?: string;
}

export interface UserCreatePayload {
  email: string;
  password: string;
  full_name: string;
  role_name: string;
}

export interface UserListResponse {
  items: UserItem[];
  total: number;
}

