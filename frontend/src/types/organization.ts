export interface Organization {
  id: string;
  name: string;
  slug: string;
  sector?: string;
  contact_email: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface OrganizationCreatePayload {
  name: string;
  slug: string;
  sector?: string;
  contact_email: string;
}

export interface OrganizationListResponse {
  items: Organization[];
  total: number;
}
