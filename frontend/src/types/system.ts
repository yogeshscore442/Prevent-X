export interface HealthInfo {
  status: string;
  version: string;
  environment: string;
  timestamp: string;
}

export interface ServiceHealth {
  status: 'UP' | 'DOWN' | 'DEGRADED';
  latency_ms: number;
  details: string;
}

export interface ReadinessInfo {
  ready: boolean;
  database: ServiceHealth;
  redis: ServiceHealth;
  timestamp: string;
}

export interface ModuleStatus {
  module_id: string;
  name: string;
  status: 'OPERATIONAL' | 'ARCHITECTURAL_STUB' | 'PLANNED_PHASE';
  phase: number;
  description: string;
}

export interface SystemInfo {
  app_name: string;
  app_version: string;
  phase: string;
  environment: string;
  python_version: string;
  database_backend: string;
  modules: ModuleStatus[];
}
