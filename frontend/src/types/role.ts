export interface Permission {
  id: string;
  code: string;
  name: string;
  description: string;
  module: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  is_system_role: boolean;
  permissions: Permission[];
}
