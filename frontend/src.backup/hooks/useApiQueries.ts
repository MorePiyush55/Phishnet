import { useQuery, useMutation, useQueryClient, UseQueryOptions, UseMutationOptions } from '@tanstack/react-query';
import { apiService, Email, EmailsResponse, Link, AuditLog, SystemStats } from '../services/apiService';
import { useUIStore } from '../stores/uiStore';

// Query Keys
export const QUERY_KEYS = {
  emails: ['emails'] as const,
  email: (id: number) => ['emails', id] as const,
  emailLinks: (emailId: number) => ['emails', emailId, 'links'] as const,
  auditLogs: ['auditLogs'] as const,
  systemStats: ['systemStats'] as const,
  threatIntel: (query: string) => ['threatIntel', query] as const,
  health: ['health'] as const,
} as const;

// Email Hooks
export function useEmails(params: Parameters<typeof apiService.getEmails>[0] = {}) {
  const filters = useUIStore(state => state.filters);
  
  // Merge UI filters with params
  const queryParams = {
    search: filters.searchTerm || undefined,
    risk_level: filters.selectedRiskLevel !== 'all' ? filters.selectedRiskLevel : undefined,
    status: filters.statusFilter !== 'all' ? filters.statusFilter : undefined,
    time_range: filters.timeRange,
    sort_by: filters.sortBy,
    sort_order: filters.sortOrder,
    ...params,
  };

  return useQuery({
    queryKey: [...QUERY_KEYS.emails, queryParams],
    queryFn: () => apiService.getEmails(queryParams),
    staleTime: 30 * 1000, // 30 seconds
    gcTime: 5 * 60 * 1000, // 5 minutes
    refetchOnWindowFocus: true,
    refetchInterval: 60 * 1000, // Refresh every minute
  });
}

export function useEmail(id: number, options?: Partial<UseQueryOptions<Email>>) {
  return useQuery({
    queryKey: QUERY_KEYS.email(id),
    queryFn: () => apiService.getEmail(id),
    enabled: !!id,
    staleTime: 2 * 60 * 1000, // 2 minutes
    ...options,
  });
}

export function useEmailLinks(emailId: number) {
  return useQuery({
    queryKey: QUERY_KEYS.emailLinks(emailId),
    queryFn: () => apiService.getEmailLinks(emailId),
    enabled: !!emailId,
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

// Email Mutations
export function useUpdateEmailStatus() {
  const queryClient = useQueryClient();
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: ({ id, status, reason }: { id: number; status: string; reason?: string }) =>
      apiService.updateEmailStatus(id, status, reason),
    onSuccess: (updatedEmail) => {
      // Update the emails list cache
      queryClient.setQueryData<EmailsResponse>(
        [...QUERY_KEYS.emails],
        (oldData) => {
          if (!oldData) return oldData;
          
          return {
            ...oldData,
            emails: oldData.emails.map(email =>
              email.id === updatedEmail.id ? updatedEmail : email
            ),
          };
        }
      );

      // Update the individual email cache
      queryClient.setQueryData(QUERY_KEYS.email(updatedEmail.id), updatedEmail);

      addNotification({
        type: 'success',
        message: `Email status updated to ${updatedEmail.status}`,
      });

      // Optionally invalidate to ensure fresh data
      queryClient.invalidateQueries({ queryKey: [...QUERY_KEYS.emails] });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Failed to update email status: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

export function useDeleteEmail() {
  const queryClient = useQueryClient();
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: (id: number) => apiService.deleteEmail(id),
    onSuccess: (_, deletedId) => {
      // Remove from emails list cache
      queryClient.setQueryData<EmailsResponse>(
        [...QUERY_KEYS.emails],
        (oldData) => {
          if (!oldData) return oldData;
          
          return {
            ...oldData,
            emails: oldData.emails.filter(email => email.id !== deletedId),
            total: oldData.total - 1,
          };
        }
      );

      // Remove individual email cache
      queryClient.removeQueries({ queryKey: QUERY_KEYS.email(deletedId) });

      addNotification({
        type: 'success',
        message: 'Email deleted successfully',
      });

      // Invalidate to get accurate counts
      queryClient.invalidateQueries({ queryKey: [...QUERY_KEYS.emails] });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Failed to delete email: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

export function useBulkUpdateEmails() {
  const queryClient = useQueryClient();
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: ({ emailIds, action, reason }: { emailIds: number[]; action: string; reason?: string }) =>
      apiService.bulkUpdateEmails(emailIds, action, reason),
    onSuccess: (_, { emailIds, action }) => {
      addNotification({
        type: 'success',
        message: `Bulk action "${action}" applied to ${emailIds.length} emails`,
      });

      // Invalidate emails to refetch updated data
      queryClient.invalidateQueries({ queryKey: [...QUERY_KEYS.emails] });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Bulk action failed: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

// Link Mutations
export function useAnalyzeLink() {
  const queryClient = useQueryClient();
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: (linkId: number) => apiService.analyzeLink(linkId),
    onSuccess: (updatedLink) => {
      // Update the email links cache
      queryClient.setQueryData<Link[]>(
        QUERY_KEYS.emailLinks(updatedLink.email_id),
        (oldLinks) => {
          if (!oldLinks) return oldLinks;
          return oldLinks.map(link => 
            link.id === updatedLink.id ? updatedLink : link
          );
        }
      );

      addNotification({
        type: 'success',
        message: 'Link analysis completed',
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Link analysis failed: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

export function useGetLinkScreenshot() {
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: (linkId: number) => apiService.getLinkScreenshot(linkId),
    onSuccess: () => {
      addNotification({
        type: 'success',
        message: 'Screenshot captured successfully',
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Screenshot failed: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

// Analysis Hooks
export function useReprocessEmail() {
  const queryClient = useQueryClient();
  const addNotification = useUIStore(state => state.addNotification);

  return useMutation({
    mutationFn: (emailId: number) => apiService.reprocessEmail(emailId),
    onSuccess: (updatedEmail) => {
      // Update caches
      queryClient.setQueryData(QUERY_KEYS.email(updatedEmail.id), updatedEmail);
      queryClient.invalidateQueries({ queryKey: [...QUERY_KEYS.emails] });

      addNotification({
        type: 'success',
        message: 'Email reprocessing completed',
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        message: `Reprocessing failed: ${error?.response?.data?.detail || error.message}`,
      });
    },
  });
}

export function useThreatIntel(query: string, source?: string) {
  return useQuery({
    queryKey: QUERY_KEYS.threatIntel(query),
    queryFn: () => apiService.getThreatIntel(query, source),
    enabled: !!query && query.length > 3,
    staleTime: 10 * 60 * 1000, // 10 minutes
    gcTime: 30 * 60 * 1000, // 30 minutes
  });
}

// Audit Hooks
export function useAuditLogs(params: Parameters<typeof apiService.getAuditLogs>[0] = {}) {
  return useQuery({
    queryKey: [...QUERY_KEYS.auditLogs, params],
    queryFn: () => apiService.getAuditLogs(params),
    staleTime: 60 * 1000, // 1 minute
    refetchInterval: 2 * 60 * 1000, // Refresh every 2 minutes
  });
}

// System Hooks
export function useSystemStats() {
  return useQuery({
    queryKey: QUERY_KEYS.systemStats,
    queryFn: () => apiService.getSystemStats(),
    staleTime: 30 * 1000, // 30 seconds
    refetchInterval: 60 * 1000, // Refresh every minute
    refetchOnWindowFocus: true,
  });
}

export function useHealthStatus() {
  return useQuery({
    queryKey: QUERY_KEYS.health,
    queryFn: () => apiService.getHealthStatus(),
    staleTime: 10 * 1000, // 10 seconds
    refetchInterval: 30 * 1000, // Refresh every 30 seconds
    retry: (failureCount, error: any) => {
      // Don't retry if it's an auth error
      if (error?.response?.status === 401) return false;
      return failureCount < 3;
    },
  });
}

// Custom hook for invalidating queries based on WebSocket events
export function useWebSocketQueryInvalidation() {
  const queryClient = useQueryClient();

  const invalidateEmails = () => {
    queryClient.invalidateQueries({ queryKey: [...QUERY_KEYS.emails] });
  };

  const invalidateEmail = (emailId: number) => {
    queryClient.invalidateQueries({ queryKey: QUERY_KEYS.email(emailId) });
  };

  const invalidateSystemStats = () => {
    queryClient.invalidateQueries({ queryKey: QUERY_KEYS.systemStats });
  };

  const updateEmailInCache = (emailUpdate: Partial<Email> & { id: number }) => {
    // Update emails list cache
    queryClient.setQueryData<EmailsResponse>(
      [...QUERY_KEYS.emails],
      (oldData) => {
        if (!oldData) return oldData;
        
        return {
          ...oldData,
          emails: oldData.emails.map(email =>
            email.id === emailUpdate.id ? { ...email, ...emailUpdate } : email
          ),
        };
      }
    );

    // Update individual email cache if it exists
    const existingEmail = queryClient.getQueryData<Email>(QUERY_KEYS.email(emailUpdate.id));
    if (existingEmail) {
      queryClient.setQueryData(QUERY_KEYS.email(emailUpdate.id), {
        ...existingEmail,
        ...emailUpdate,
      });
    }
  };

  return {
    invalidateEmails,
    invalidateEmail,
    invalidateSystemStats,
    updateEmailInCache,
  };
}
