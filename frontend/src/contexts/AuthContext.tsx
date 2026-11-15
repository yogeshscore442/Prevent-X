import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '@/services/api';
import { UserProfile, LoginResponse } from '@/types/auth';

interface AuthContextType {
  user: UserProfile | null;
  activeOrgId: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, orgSlug?: string) => Promise<void>;
  logout: () => Promise<void>;
  switchOrganization: (orgId: string) => void;
  hasPermission: (permissionCode: string) => boolean;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [activeOrgId, setActiveOrgId] = useState<string | null>(
    localStorage.getItem('preventx_active_org_id')
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const refreshUser = async () => {
    try {
      const resp = await api.get<UserProfile>('/auth/me');
      setUser(resp.data);
      if (resp.data.current_organization_id && !activeOrgId) {
        setActiveOrgId(resp.data.current_organization_id);
        localStorage.setItem('preventx_active_org_id', resp.data.current_organization_id);
      }
    } catch {
      setUser(null);
      localStorage.removeItem('preventx_token');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshUser();
  }, []);

  const login = async (email: string, password: string, orgSlug?: string) => {
    setIsLoading(true);
    try {
      const resp = await api.post<LoginResponse>('/auth/login', {
        email,
        password,
        organization_slug: orgSlug || undefined,
      });

      const data = resp.data;
      setUser(data.user);
      localStorage.setItem('preventx_token', data.tokens.access_token);

      const orgId = data.user.current_organization_id || data.user.memberships[0]?.organization_id;
      if (orgId) {
        setActiveOrgId(orgId);
        localStorage.setItem('preventx_active_org_id', orgId);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch (e) {
      console.error('Logout error', e);
    } finally {
      setUser(null);
      setActiveOrgId(null);
      localStorage.removeItem('preventx_token');
      localStorage.removeItem('preventx_active_org_id');
      window.location.href = '/login';
    }
  };

  const switchOrganization = (orgId: string) => {
    setActiveOrgId(orgId);
    localStorage.setItem('preventx_active_org_id', orgId);
    // Reload data or trigger re-render
    window.location.reload();
  };

  const hasPermission = (permissionCode: string): boolean => {
    if (!user) return false;
    if (user.is_superuser) return true;
    const currentMembership = (user.memberships || []).find(
      (m) => m.organization_id === activeOrgId
    );
    return currentMembership ? (currentMembership.permissions || []).includes(permissionCode) : false;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        activeOrgId,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        switchOrganization,
        hasPermission,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

