export interface AuditEvent {
  id: string;
  organization_id?: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  ip_address?: string;
  user_agent?: string;
  status: 'SUCCESS' | 'FAILURE' | 'DENIED';
  details?: string;
  created_at: string;
}

export interface AuditLogListResponse {
  items: AuditEvent[];
  total: number;
}
