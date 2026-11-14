export type AssetType =
  | 'WEB_APPLICATION'
  | 'API_GATEWAY'
  | 'PUBLIC_IP'
  | 'INTERNAL_SERVER'
  | 'DOMAIN';

export type EnvironmentType = 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT';
export type CriticalityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ManagedAsset {
  id: string;
  organization_id: string;
  name: string;
  asset_type: AssetType;
  target: string;
  environment: EnvironmentType;
  criticality: CriticalityType;
  is_in_scope: boolean;
  created_at: string;
  updated_at: string;
}

export interface AssetCreatePayload {
  name: string;
  asset_type: AssetType;
  target: string;
  environment: EnvironmentType;
  criticality: CriticalityType;
  is_in_scope: boolean;
}

export interface AssetListResponse {
  items: ManagedAsset[];
  total: number;
}
