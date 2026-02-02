import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { apiManager } from '../services/apiManager';
import { useAuth } from './useAuth';
import type { Tenant, User } from '../types/api';

export interface TenantContextType {
  currentTenant: Tenant | null;
  userTenantId: string | null;
  isMultiTenant: boolean;
  availableTenants: Tenant[];
  loading: boolean;
  error: string | null;
  switchTenant: (tenantId: string) => Promise<void>;
  canAccessTenant: (tenantId: string) => boolean;
  filterByTenant: <T extends { tenant_id?: string }>(items: T[]) => T[];
  getTenantSetting: (key: string) => any;
  updateTenantSettings: (settings: any) => Promise<void>;
  isTenantAdmin: boolean;
  tenantPermissions: string[];
}

const TenantContext = createContext<TenantContextType | undefined>(undefined);

export interface TenantProviderProps {
  children: ReactNode;
}

export const TenantProvider: React.FC<TenantProviderProps> = ({ children }) => {
  const { user } = useAuth();
  const [currentTenant, setCurrentTenant] = useState<Tenant | null>(null);
  const [availableTenants, setAvailableTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Load tenant data when user changes
  useEffect(() => {
    const loadTenantData = async () => {
      if (!user) {
        setCurrentTenant(null);
        setAvailableTenants([]);
        setLoading(false);
        return;
      }

      setLoading(true);
      setError(null);

      try {
        // For admin users, load all tenants
        if (user.role === 'admin') {
          const tenantsResponse = await apiManager.tenants.list();
          const tenants = tenantsResponse.data;
          setAvailableTenants(tenants);
          
          // Set current tenant to user's tenant or first available
          const userTenant = tenants.find((t: Tenant) => t.id === user.tenant_id);
          setCurrentTenant(userTenant || tenants[0] || null);
        } else {
          // For non-admin users, only load their tenant
          if (user.tenant_id) {
            try {
              const tenantResponse = await apiManager.tenants.get(user.tenant_id);
              const tenant = tenantResponse.data;
              setCurrentTenant(tenant);
              setAvailableTenants([tenant]);
            } catch (err) {
              console.error('Failed to load user tenant:', err);
              setError('Failed to load tenant information');
            }
          }
        }
      } catch (err) {
        console.error('Failed to load tenant data:', err);
        setError('Failed to load tenant information');
      } finally {
        setLoading(false);
      }
    };

    loadTenantData();
  }, [user]);

  const switchTenant = useCallback(async (tenantId: string) => {
    if (!user || user.role !== 'admin') {
      throw new Error('Only admin users can switch tenants');
    }

    const tenant = availableTenants.find(t => t.id === tenantId);
    if (!tenant) {
      throw new Error('Tenant not found');
    }

    setCurrentTenant(tenant);
  }, [user, availableTenants]);

  const canAccessTenant = useCallback((tenantId: string): boolean => {
    if (!user) return false;
    
    // Admin users can access any tenant
    if (user.role === 'admin') return true;
    
    // Other users can only access their own tenant
    return user.tenant_id === tenantId;
  }, [user]);

  const filterByTenant = useCallback(<T extends { tenant_id?: string }>(items: T[]): T[] => {
    if (!user || !currentTenant) return [];
    
    // Admin users see data for current tenant
    if (user.role === 'admin') {
      return items.filter(item => item.tenant_id === currentTenant.id);
    }
    
    // Other users see only their tenant's data
    return items.filter(item => item.tenant_id === user.tenant_id);
  }, [user, currentTenant]);

  const getTenantSetting = useCallback((key: string): any => {
    if (!currentTenant?.settings) return undefined;
    
    return key.split('.').reduce((obj: any, k: string) => obj && obj[k], currentTenant.settings as any);
  }, [currentTenant]);

  const updateTenantSettings = useCallback(async (settings: any): Promise<void> => {
    if (!currentTenant || !user) {
      throw new Error('No current tenant or user');
    }

    if (user.role !== 'admin' && user.tenant_id !== currentTenant.id) {
      throw new Error('Insufficient permissions to update tenant settings');
    }

    try {
      const response = await apiManager.tenants.update(currentTenant.id, {
        settings: { ...currentTenant.settings, ...settings }
      });
      const updatedTenant = response.data;
      
      setCurrentTenant(updatedTenant);
      
      // Update in available tenants list
      setAvailableTenants(prev => 
        prev.map(t => t.id === updatedTenant.id ? updatedTenant : t)
      );
    } catch (err) {
      console.error('Failed to update tenant settings:', err);
      throw err;
    }
  }, [currentTenant, user]);

  const contextValue: TenantContextType = {
    currentTenant,
    userTenantId: user?.tenant_id || null,
    isMultiTenant: user?.role === 'admin' && availableTenants.length > 1,
    availableTenants,
    loading,
    error,
    switchTenant,
    canAccessTenant,
    filterByTenant,
    getTenantSetting,
    updateTenantSettings,
    isTenantAdmin: user?.role === 'admin' || false,
    tenantPermissions: currentTenant?.settings?.features ? 
      Object.keys(currentTenant.settings.features).filter(
        key => (currentTenant.settings.features as any)[key]
      ) : [],
  };

  return (
    <TenantContext.Provider value={contextValue}>
      {children}
    </TenantContext.Provider>
  );
};

// Hook to use tenant context
export const useTenant = (): TenantContextType => {
  const context = useContext(TenantContext);
  if (!context) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
};

// Higher-order component for tenant-aware components
export function withTenantIsolation<P extends object>(
  WrappedComponent: React.ComponentType<P>
) {
  const TenantIsolatedComponent: React.FC<P> = (props) => {
    const { currentTenant, loading, error } = useTenant();

    if (loading) {
      return (
        <div className="flex items-center justify-center p-8">
          <div className="text-gray-400">Loading tenant information...</div>
        </div>
      );
    }

    if (error) {
      return (
        <div className="flex items-center justify-center p-8">
          <div className="text-red-400">Error: {error}</div>
        </div>
      );
    }

    if (!currentTenant) {
      return (
        <div className="flex items-center justify-center p-8">
          <div className="text-gray-400">No tenant information available</div>
        </div>
      );
    }

    return <WrappedComponent {...props} />;
  };

  TenantIsolatedComponent.displayName = `withTenantIsolation(${WrappedComponent.displayName || WrappedComponent.name})`;

  return TenantIsolatedComponent;
}

// Hook for tenant-aware API calls
export const useTenantAwareApi = () => {
  const { currentTenant, canAccessTenant, filterByTenant } = useTenant();

  const withTenantFilter = useCallback(<T extends { tenant_id?: string }>(
    apiCall: () => Promise<{ data: T[] | T; pagination?: any }>
  ) => {
    return async () => {
      const response = await apiCall();
      
      if (Array.isArray(response.data)) {
        return {
          ...response,
          data: filterByTenant(response.data)
        };
      }
      
      // For single items, check if user can access this tenant
      if (response.data.tenant_id && !canAccessTenant(response.data.tenant_id)) {
        throw new Error('Access denied to this tenant\'s data');
      }
      
      return response;
    };
  }, [filterByTenant, canAccessTenant]);

  const withTenantParam = useCallback((params: any = {}) => {
    if (!currentTenant) return params;
    
    return {
      ...params,
      tenant_id: currentTenant.id
    };
  }, [currentTenant]);

  return {
    withTenantFilter,
    withTenantParam,
    currentTenantId: currentTenant?.id || null
  };
};

// Tenant selector component
export interface TenantSelectorProps {
  className?: string;
  showTenantInfo?: boolean;
}

export const TenantSelector: React.FC<TenantSelectorProps> = ({
  className = '',
  showTenantInfo = true
}) => {
  const { 
    currentTenant, 
    availableTenants, 
    isMultiTenant, 
    switchTenant, 
    loading 
  } = useTenant();

  if (!isMultiTenant || loading) {
    return showTenantInfo && currentTenant ? (
      <div className={`text-sm text-gray-400 ${className}`}>
        Tenant: {currentTenant.name}
      </div>
    ) : null;
  }

  return (
    <div className={`flex items-center space-x-2 ${className}`}>
      <span className="text-sm text-gray-400">Tenant:</span>
      <select
        value={currentTenant?.id || ''}
        onChange={(e) => switchTenant(e.target.value)}
        className="bg-gray-800 border border-gray-600 text-white text-sm rounded px-2 py-1 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
      >
        {availableTenants.map(tenant => (
          <option key={tenant.id} value={tenant.id}>
            {tenant.name}
          </option>
        ))}
      </select>
    </div>
  );
};

// Tenant info component
export interface TenantInfoProps {
  className?: string;
  detailed?: boolean;
}

export const TenantInfo: React.FC<TenantInfoProps> = ({
  className = '',
  detailed = false
}) => {
  const { currentTenant, getTenantSetting } = useTenant();

  if (!currentTenant) return null;

  if (!detailed) {
    return (
      <div className={`bg-gray-800 border border-gray-700 rounded-lg p-4 ${className}`}>
        <h3 className="text-lg font-medium text-white mb-2">{currentTenant.name}</h3>
        <div className="text-sm text-gray-400">
          <div>Domain: {currentTenant.domain}</div>
          <div>Status: {currentTenant.is_active ? 'Active' : 'Inactive'}</div>
        </div>
      </div>
    );
  }

  const features = getTenantSetting('features') || {};
  const maxUsers = getTenantSetting('max_users');
  const retentionDays = getTenantSetting('retention_days');

  return (
    <div className={`bg-gray-800 border border-gray-700 rounded-lg p-6 ${className}`}>
      <h3 className="text-xl font-medium text-white mb-4">{currentTenant.name}</h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">Basic Information</h4>
          <div className="space-y-1 text-sm text-gray-400">
            <div>Domain: {currentTenant.domain}</div>
            <div>Status: {currentTenant.is_active ? 'Active' : 'Inactive'}</div>
            <div>Max Users: {maxUsers || 'Unlimited'}</div>
            <div>Retention: {retentionDays || 'Default'} days</div>
          </div>
        </div>
        
        <div>
          <h4 className="text-sm font-medium text-gray-300 mb-2">Features</h4>
          <div className="grid grid-cols-2 gap-1 text-xs">
            {Object.entries(features).map(([feature, enabled]) => (
              <div 
                key={feature}
                className={`flex items-center space-x-1 ${
                  enabled ? 'text-green-400' : 'text-gray-500'
                }`}
              >
                <div className={`w-2 h-2 rounded-full ${
                  enabled ? 'bg-green-400' : 'bg-gray-500'
                }`} />
                <span className="capitalize">{feature.replace(/_/g, ' ')}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default TenantProvider;
