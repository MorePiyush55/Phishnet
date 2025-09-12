import React, { useMemo, useEffect } from 'react';
import { useTenant, useTenantAwareApi } from '../hooks/useTenant';
import { useEmails, useEmail, useApiMutation } from '../hooks/useTypedApi';
import { VirtualEmailList } from './VirtualEmailList';
import { Pagination, usePaginationState } from './Pagination';
import { usePermissions } from '../hooks/useAuth';
import { apiManager } from '../services/apiManager';
import { EmailListParams, Email } from '../types/api';
import { Shield, Users, Database, AlertTriangle } from 'lucide-react';

export interface TenantAwareEmailListProps {
  searchTerm?: string;
  refreshTrigger?: number;
  onEmailClick?: (email: Email) => void;
  onSelectionChange?: (selectedIds: string[]) => void;
  className?: string;
}

export const TenantAwareEmailList: React.FC<TenantAwareEmailListProps> = ({
  searchTerm = '',
  refreshTrigger,
  onEmailClick,
  onSelectionChange,
  className = ''
}) => {
  // Pagination state
  const {
    currentPage,
    itemsPerPage,
    setCurrentPage,
    setItemsPerPage
  } = usePaginationState();

  // Tenant context and utilities
  const {
    currentTenant,
    availableTenants,
    switchTenant,
    loading: tenantLoading,
    error: tenantError
  } = useTenant();

  const { withTenantParam } = useTenantAwareApi();

  // Build API parameters with tenant awareness
  const apiParams: EmailListParams = useMemo(() => ({
    page: currentPage,
    limit: itemsPerPage,
    tenant_id: currentTenant?.id,
    search: searchTerm
  }), [currentPage, itemsPerPage, currentTenant?.id, searchTerm]);

  // Use typed API hooks for tenant-aware data fetching
  const {
    data: emailsArray,
    loading: emailsLoading,
    error: emailsError,
    refresh: refreshEmails
  } = useEmails(apiParams, {
    immediate: !tenantLoading && !!currentTenant,
  });

  // Get user permissions
  const permissions = usePermissions();

  // Simple tenant filtering function
  const filterByTenant = (emails: Email[]) => {
    if (!currentTenant) return [];
    return emails.filter(email => 
      !email.tenant_id || email.tenant_id === currentTenant.id
    );
  };

  // Filter emails by tenant (extra safety check)
  const filteredEmails = useMemo(() => {
    if (!emailsArray || !Array.isArray(emailsArray)) return [];
    return filterByTenant(emailsArray);
  }, [emailsArray, currentTenant]);

  // Bulk action mutation
  const bulkAction = useApiMutation();

  const handleBulkAction = async (emailIds: string[], action: string, reason?: string) => {
    if (!permissions.canDeleteEmails()) {
      throw new Error('Insufficient permissions for bulk actions');
    }

    // Validate tenant access for all selected emails
    const unauthorizedEmails = filteredEmails.filter((email: Email) =>
      emailIds.includes(email.id) && email.tenant_id !== currentTenant?.id
    );

    if (unauthorizedEmails.length > 0) {
      throw new Error(
        `Access denied for ${unauthorizedEmails.length} emails from other tenants`
      );
    }

    try {
      const result = await bulkAction.mutate(
        () => apiManager.emails.bulkAction({
          email_ids: emailIds,
          action: action as any,
          reason,
          notify_users: true
        }),
        { emailIds, action, reason }
      );

      // Refresh the email list after successful action
      await refreshEmails();
      return result;
    } catch (error) {
      console.error('Bulk action failed:', error);
      throw error;
    }
  };

  // Refresh on trigger change
  useEffect(() => {
    if (refreshTrigger) {
      refreshEmails();
    }
  }, [refreshTrigger, refreshEmails]);

  // Loading state
  if (tenantLoading || emailsLoading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <div className="flex items-center space-x-3">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          <span className="text-gray-600">Loading tenant-aware emails...</span>
        </div>
      </div>
    );
  }

  // Error state
  if (tenantError || emailsError) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center space-x-2 text-red-700">
          <AlertTriangle className="h-5 w-5" />
          <span className="font-medium">Error loading emails</span>
        </div>
        <p className="text-red-600 mt-1 text-sm">
          {tenantError || emailsError}
        </p>
        <button
          onClick={() => refreshEmails()}
          className="mt-3 px-3 py-1 bg-red-100 text-red-700 rounded text-sm hover:bg-red-200"
        >
          Retry
        </button>
      </div>
    );
  }

  // No tenant selected
  if (!currentTenant) {
    return (
      <div className={`bg-yellow-50 border border-yellow-200 rounded-lg p-6 ${className}`}>
        <div className="flex items-center space-x-2 text-yellow-700">
          <Users className="h-5 w-5" />
          <span className="font-medium">No tenant selected</span>
        </div>
        <p className="text-yellow-600 mt-1">
          Please select a tenant to view emails.
        </p>
        {availableTenants.length > 0 && (
          <select
            onChange={(e) => switchTenant(e.target.value)}
            className="mt-3 px-3 py-1 border border-yellow-300 rounded text-sm"
          >
            <option value="">Select a tenant...</option>
            {availableTenants.map(tenant => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name}
              </option>
            ))}
          </select>
        )}
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Tenant Information Header */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-5 w-5 text-blue-600" />
            <div>
              <h3 className="font-medium text-blue-900">
                Current Tenant: {currentTenant.name}
              </h3>
              <p className="text-blue-700 text-sm">
                Showing emails for tenant {currentTenant.id}
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Database className="h-4 w-4 text-blue-600" />
            <span className="text-blue-700 text-sm">
              {filteredEmails.length} emails
            </span>
          </div>
        </div>
      </div>

      {/* Email List */}
      {filteredEmails.length > 0 ? (
        <>
          <VirtualEmailList
            emails={filteredEmails}
            onEmailSelect={onEmailClick ? (email) => onEmailClick(email as any) : undefined}
            loading={emailsLoading}
            className="min-h-96"
          />

          <div className="flex justify-center">
            <Pagination
              currentPage={currentPage}
              totalPages={Math.ceil(filteredEmails.length / itemsPerPage)}
              totalItems={filteredEmails.length}
              itemsPerPage={itemsPerPage}
              onPageChange={setCurrentPage}
              onItemsPerPageChange={setItemsPerPage}
            />
          </div>
        </>
      ) : (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <Database className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            No emails found
          </h3>
          <p className="text-gray-600">
            {searchTerm 
              ? `No emails found matching "${searchTerm}" in tenant ${currentTenant.name}`
              : `No emails available in tenant ${currentTenant.name}`
            }
          </p>
        </div>
      )}
    </div>
  );
};

// Tenant-aware email details component
export interface TenantAwareEmailDetailsProps {
  emailId: string;
  onClose?: () => void;
  className?: string;
}

export const TenantAwareEmailDetails: React.FC<TenantAwareEmailDetailsProps> = ({
  emailId,
  onClose,
  className = ''
}) => {
  const { currentTenant } = useTenant();
  
  const { data: email, loading, error } = useEmail(emailId);

  // Validate tenant access
  useEffect(() => {
    if (email && email.tenant_id && email.tenant_id !== currentTenant?.id) {
      console.error('Access denied: Email belongs to different tenant');
      onClose?.();
    }
  }, [email, currentTenant, onClose]);

  if (loading) {
    return (
      <div className={`flex items-center justify-center p-8 ${className}`}>
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error || !email) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center space-x-2 text-red-700">
          <AlertTriangle className="h-5 w-5" />
          <span>Error loading email details</span>
        </div>
      </div>
    );
  }

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Tenant verification header */}
      <div className="bg-green-50 border border-green-200 rounded-lg p-3">
        <div className="flex items-center space-x-2 text-green-700">
          <Shield className="h-4 w-4" />
          <span className="text-sm">
            ✓ Email verified for tenant: {currentTenant?.name}
          </span>
        </div>
      </div>

      {/* Email details */}
      <div className="bg-white border rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">{email.subject}</h2>
        <div className="space-y-2 text-sm text-gray-600">
          <p><strong>From:</strong> {email.sender}</p>
          <p><strong>To:</strong> {email.recipient}</p>
          <p><strong>Date:</strong> {new Date(email.received_at).toLocaleString()}</p>
          <p><strong>Status:</strong> {email.status}</p>
          <p><strong>Risk Level:</strong> {email.risk_level}</p>
          {email.tenant_id && (
            <p><strong>Tenant:</strong> {email.tenant_id}</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default TenantAwareEmailList;
