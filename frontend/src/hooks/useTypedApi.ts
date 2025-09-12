import { useState, useCallback, useEffect, useRef } from 'react';
import { typedApiClient, ApiError } from '../services/typedApiClient';
import {
  ApiResponse,
  PaginatedResponse,
  Email,
  EmailListParams,
  User,
  SystemStats,
  AuditLog,
  AuditLogParams,
  Link,
  EmailBody,
  ThreatIntelligence,
  ThreatIntelParams,
} from '../types/api';

// Generic API hook state
export interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  lastFetch: Date | null;
}

// Generic API hook options
export interface ApiHookOptions {
  immediate?: boolean;
  refreshInterval?: number;
  retryOnError?: boolean;
  retryAttempts?: number;
  retryDelay?: number;
}

// Generic API hook
export function useApi<T>(
  apiCall: () => Promise<ApiResponse<T> | PaginatedResponse<T>>,
  options: ApiHookOptions = {}
) {
  const {
    immediate = false,
    refreshInterval,
    retryOnError = false,
    retryAttempts = 3,
    retryDelay = 1000,
  } = options;

  const [state, setState] = useState<ApiState<T>>({
    data: null,
    loading: false,
    error: null,
    lastFetch: null,
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const execute = useCallback(async (showLoading = true) => {
    // Cancel previous request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    abortControllerRef.current = new AbortController();

    if (showLoading) {
      setState(prev => ({ ...prev, loading: true, error: null }));
    }

    try {
      const response = await apiCall();
      const data = 'pagination' in response ? response.data : response.data;
      
      setState({
        data: data as T,
        loading: false,
        error: null,
        lastFetch: new Date(),
      });

      return data as T;
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'An unexpected error occurred';

      setState(prev => ({
        ...prev,
        loading: false,
        error: errorMessage,
      }));

      if (retryOnError && retryAttempts > 0) {
        retryTimeoutRef.current = setTimeout(() => {
          execute(false);
        }, retryDelay);
      }

      throw error;
    }
  }, [apiCall, retryOnError, retryAttempts, retryDelay]);

  const refresh = useCallback(() => {
    return execute(true);
  }, [execute]);

  const reset = useCallback(() => {
    setState({
      data: null,
      loading: false,
      error: null,
      lastFetch: null,
    });
  }, []);

  // Auto-execute on mount if immediate is true
  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [immediate, execute]);

  // Set up refresh interval
  useEffect(() => {
    if (refreshInterval && refreshInterval > 0) {
      intervalRef.current = setInterval(() => {
        execute(false);
      }, refreshInterval);

      return () => {
        if (intervalRef.current) {
          clearInterval(intervalRef.current);
        }
      };
    }
  }, [refreshInterval, execute]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
      }
    };
  }, []);

  return {
    ...state,
    execute,
    refresh,
    reset,
    isStale: state.lastFetch ? Date.now() - state.lastFetch.getTime() > 30000 : true,
  };
}

// Specialized hooks for common API calls

// Emails
export function useEmails(params?: EmailListParams, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getEmails(params),
    { immediate: true, ...options }
  );
}

export function useEmail(id: string, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getEmail(id),
    { immediate: !!id, ...options }
  );
}

export function useEmailBody(id: string, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getEmailBody(id),
    { immediate: false, ...options }
  );
}

export function useEmailLinks(emailId: string, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getEmailLinks(emailId),
    { immediate: !!emailId, ...options }
  );
}

// Users
export function useCurrentUser(options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getCurrentUser(),
    { immediate: true, ...options }
  );
}

export function useUsers(params?: any, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getUsers(params),
    { immediate: true, ...options }
  );
}

// System
export function useSystemStats(options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getSystemStats(),
    { immediate: true, refreshInterval: 30000, ...options }
  );
}

export function useSystemHealth(options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getSystemHealth(),
    { immediate: true, refreshInterval: 60000, ...options }
  );
}

// Audit logs
export function useAuditLogs(params?: AuditLogParams, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getAuditLogs(params),
    { immediate: true, ...options }
  );
}

// Threat intelligence
export function useThreatIntelligence(params?: ThreatIntelParams, options?: ApiHookOptions) {
  return useApi(
    () => typedApiClient.getThreatIntelligence(params),
    { immediate: true, refreshInterval: 300000, ...options } // Refresh every 5 minutes
  );
}

// Mutation hooks for API operations that modify data
export function useApiMutation<TData, TVariables = any>() {
  const [state, setState] = useState<{
    loading: boolean;
    error: string | null;
    data: TData | null;
  }>({
    loading: false,
    error: null,
    data: null,
  });

  const mutate = useCallback(async (
    mutationFn: (variables: TVariables) => Promise<ApiResponse<TData>>,
    variables: TVariables
  ): Promise<TData> => {
    setState({ loading: true, error: null, data: null });

    try {
      const response = await mutationFn(variables);
      setState({ loading: false, error: null, data: response.data });
      return response.data;
    } catch (error) {
      const errorMessage = error instanceof ApiError 
        ? error.message 
        : error instanceof Error 
        ? error.message 
        : 'An unexpected error occurred';

      setState({ loading: false, error: errorMessage, data: null });
      throw error;
    }
  }, []);

  const reset = useCallback(() => {
    setState({ loading: false, error: null, data: null });
  }, []);

  return {
    ...state,
    mutate,
    reset,
  };
}

// Specialized mutation hooks
export function useEmailBulkAction() {
  return useApiMutation<any, any>();
}

export function useLinkAnalysis() {
  return useApiMutation<any, { linkId: string; params?: any }>();
}

export function useCreateUser() {
  return useApiMutation<User, any>();
}

export function useUpdateUser() {
  return useApiMutation<User, { id: number; data: any }>();
}

// Pagination hook for paginated API responses
export function usePaginatedApi<T>(
  apiCall: (params: any) => Promise<PaginatedResponse<T>>,
  initialParams: any = {},
  options?: ApiHookOptions
) {
  const [params, setParams] = useState(initialParams);
  const [allData, setAllData] = useState<T[]>([]);
  const [pagination, setPagination] = useState<any>(null);

  const api = useApi(
    () => apiCall(params),
    { immediate: true, ...options }
  );

  useEffect(() => {
    if (api.data) {
      const response = api.data as any;
      if ('pagination' in response) {
        if (params.page === 1) {
          setAllData(response.data);
        } else {
          setAllData(prev => [...prev, ...response.data]);
        }
        setPagination(response.pagination);
      }
    }
  }, [api.data, params.page]);

  const loadMore = useCallback(() => {
    if (pagination && pagination.page < pagination.pages) {
      setParams((prev: any) => ({ ...prev, page: prev.page + 1 }));
    }
  }, [pagination]);

  const reset = useCallback(() => {
    setParams({ ...initialParams, page: 1 });
    setAllData([]);
    setPagination(null);
    api.reset();
  }, [initialParams, api]);

  const updateParams = useCallback((newParams: any) => {
    setParams({ ...newParams, page: 1 });
    setAllData([]);
  }, []);

  return {
    data: allData,
    pagination,
    loading: api.loading,
    error: api.error,
    loadMore,
    reset,
    updateParams,
    hasMore: pagination ? pagination.page < pagination.pages : false,
    refresh: api.refresh,
  };
}

// Real-time data hook with automatic refresh
export function useRealTimeData<T>(
  apiCall: () => Promise<ApiResponse<T>>,
  interval: number = 5000,
  options?: ApiHookOptions
) {
  const [isRealTime, setIsRealTime] = useState(false);
  
  const api = useApi(apiCall, {
    immediate: true,
    refreshInterval: isRealTime ? interval : undefined,
    ...options,
  });

  const startRealTime = useCallback(() => {
    setIsRealTime(true);
  }, []);

  const stopRealTime = useCallback(() => {
    setIsRealTime(false);
  }, []);

  const toggleRealTime = useCallback(() => {
    setIsRealTime(prev => !prev);
  }, []);

  return {
    ...api,
    isRealTime,
    startRealTime,
    stopRealTime,
    toggleRealTime,
  };
}

// Cache-aware API hook
export function useCachedApi<T>(
  cacheKey: string,
  apiCall: () => Promise<ApiResponse<T>>,
  cacheTime: number = 5 * 60 * 1000, // 5 minutes
  options?: ApiHookOptions
) {
  const [cacheData, setCacheData] = useState<{
    data: T | null;
    timestamp: number;
  } | null>(null);

  const isCacheValid = cacheData && (Date.now() - cacheData.timestamp < cacheTime);

  const api = useApi(apiCall, {
    immediate: !isCacheValid,
    ...options,
  });

  useEffect(() => {
    if (api.data) {
      setCacheData({
        data: api.data,
        timestamp: Date.now(),
      });
    }
  }, [api.data]);

  return {
    ...api,
    data: isCacheValid ? cacheData!.data : api.data,
    isCached: isCacheValid,
    invalidateCache: () => setCacheData(null),
  };
}

export default typedApiClient;
