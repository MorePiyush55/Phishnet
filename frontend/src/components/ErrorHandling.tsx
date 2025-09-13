import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react';
import { AlertTriangle, Clock, X, RefreshCw } from 'lucide-react';

interface ErrorInfo {
  id: string;
  message: string;
  type: 'rate_limit' | 'network' | 'auth' | 'validation' | 'server' | 'unknown';
  timestamp: Date;
  retryable: boolean;
  retryAfter?: number; // seconds
  details?: Record<string, any>;
}

interface ErrorContextType {
  errors: ErrorInfo[];
  addError: (error: Omit<ErrorInfo, 'id' | 'timestamp'>) => void;
  removeError: (id: string) => void;
  clearErrors: () => void;
  retryAction: (errorId: string, action: () => Promise<void>) => Promise<void>;
}

const ErrorContext = createContext<ErrorContextType | undefined>(undefined);

export const useErrorHandling = () => {
  const context = useContext(ErrorContext);
  if (!context) {
    throw new Error('useErrorHandling must be used within an ErrorProvider');
  }
  return context;
};

interface ErrorProviderProps {
  children: ReactNode;
  maxErrors?: number;
  autoRemoveAfter?: number; // seconds
}

export const ErrorProvider: React.FC<ErrorProviderProps> = ({
  children,
  maxErrors = 10,
  autoRemoveAfter = 30
}) => {
  const [errors, setErrors] = useState<ErrorInfo[]>([]);

  const addError = useCallback((error: Omit<ErrorInfo, 'id' | 'timestamp'>) => {
    const newError: ErrorInfo = {
      ...error,
      id: `error-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date()
    };

    setErrors(prev => {
      const updatedErrors = [newError, ...prev].slice(0, maxErrors);
      
      // Auto-remove after specified time
      if (autoRemoveAfter > 0) {
        setTimeout(() => {
          removeError(newError.id);
        }, autoRemoveAfter * 1000);
      }
      
      return updatedErrors;
    });
  }, [maxErrors, autoRemoveAfter]);

  const removeError = useCallback((id: string) => {
    setErrors(prev => prev.filter(error => error.id !== id));
  }, []);

  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  const retryAction = useCallback(async (errorId: string, action: () => Promise<void>) => {
    try {
      await action();
      removeError(errorId);
    } catch (error: any) {
      // If retry fails, add a new error
      addError({
        message: `Retry failed: ${error.message}`,
        type: 'network',
        retryable: true
      });
    }
  }, [addError, removeError]);

  return (
    <ErrorContext.Provider value={{ errors, addError, removeError, clearErrors, retryAction }}>
      {children}
    </ErrorContext.Provider>
  );
};

// Enhanced error parsing utility
export const parseApiError = (error: any): Omit<ErrorInfo, 'id' | 'timestamp'> => {
  if (!error.response) {
    return {
      message: 'Network error. Please check your connection.',
      type: 'network',
      retryable: true
    };
  }

  const { status, data } = error.response;

  switch (status) {
    case 429:
      const retryAfter = error.response.headers['retry-after'] 
        ? parseInt(error.response.headers['retry-after']) 
        : 60;
      
      return {
        message: `Rate limit exceeded. Please wait ${retryAfter} seconds before trying again.`,
        type: 'rate_limit',
        retryable: true,
        retryAfter,
        details: { status, retryAfter }
      };

    case 401:
      return {
        message: 'Authentication failed. Please reconnect your Gmail account.',
        type: 'auth',
        retryable: false,
        details: { status }
      };

    case 403:
      return {
        message: 'Access denied. You may need to grant additional permissions.',
        type: 'auth',
        retryable: false,
        details: { status }
      };

    case 422:
      return {
        message: data?.detail || 'Invalid request. Please check your input.',
        type: 'validation',
        retryable: false,
        details: { status, validationErrors: data?.detail }
      };

    case 500:
    case 502:
    case 503:
    case 504:
      return {
        message: 'Server error. Please try again in a few moments.',
        type: 'server',
        retryable: true,
        details: { status }
      };

    default:
      return {
        message: data?.detail || `Unexpected error (${status})`,
        type: 'unknown',
        retryable: status >= 500,
        details: { status }
      };
  }
};

// Rate limiting hook with visual feedback
export const useRateLimit = (endpoint: string, maxRequests: number = 5, windowMs: number = 60000) => {
  const [isLimited, setIsLimited] = useState(false);
  const [timeUntilReset, setTimeUntilReset] = useState(0);
  const { addError } = useErrorHandling();

  const checkRateLimit = useCallback(() => {
    const now = Date.now();
    const key = `rate_limit_${endpoint}`;
    const requests = JSON.parse(localStorage.getItem(key) || '[]');
    
    // Remove old requests
    const validRequests = requests.filter((time: number) => now - time < windowMs);
    
    if (validRequests.length >= maxRequests) {
      const oldestRequest = Math.min(...validRequests);
      const resetTime = oldestRequest + windowMs;
      const timeUntil = Math.max(0, resetTime - now);
      
      setIsLimited(true);
      setTimeUntilReset(Math.ceil(timeUntil / 1000));
      
      // Start countdown
      const interval = setInterval(() => {
        const remaining = Math.max(0, Math.ceil((resetTime - Date.now()) / 1000));
        setTimeUntilReset(remaining);
        
        if (remaining <= 0) {
          setIsLimited(false);
          clearInterval(interval);
        }
      }, 1000);
      
      addError({
        message: `Too many requests. Please wait ${Math.ceil(timeUntil / 1000)} seconds.`,
        type: 'rate_limit',
        retryable: true,
        retryAfter: Math.ceil(timeUntil / 1000)
      });
      
      return false;
    }
    
    // Add current request
    validRequests.push(now);
    localStorage.setItem(key, JSON.stringify(validRequests));
    
    return true;
  }, [endpoint, maxRequests, windowMs, addError]);

  return { checkRateLimit, isLimited, timeUntilReset };
};

// Error display component
interface ErrorDisplayProps {
  className?: string;
  showDetails?: boolean;
}

export const ErrorDisplay: React.FC<ErrorDisplayProps> = ({ 
  className = '', 
  showDetails = false 
}) => {
  const { errors, removeError, clearErrors, retryAction } = useErrorHandling();

  if (errors.length === 0) return null;

  const getErrorIcon = (type: ErrorInfo['type']) => {
    switch (type) {
      case 'rate_limit':
        return <Clock className="h-4 w-4" />;
      default:
        return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const getErrorStyles = (type: ErrorInfo['type']) => {
    switch (type) {
      case 'rate_limit':
        return 'bg-yellow-50 border-yellow-200 text-yellow-800';
      case 'auth':
        return 'bg-red-50 border-red-200 text-red-800';
      case 'network':
        return 'bg-blue-50 border-blue-200 text-blue-800';
      case 'server':
        return 'bg-red-50 border-red-200 text-red-800';
      default:
        return 'bg-gray-50 border-gray-200 text-gray-800';
    }
  };

  return (
    <div className={`space-y-2 ${className}`}>
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-medium text-gray-700">
          System Messages ({errors.length})
        </h4>
        {errors.length > 1 && (
          <button
            onClick={clearErrors}
            className="text-xs text-gray-500 hover:text-gray-700"
          >
            Clear all
          </button>
        )}
      </div>

      {errors.map((error) => (
        <div
          key={error.id}
          className={`p-3 rounded-md border ${getErrorStyles(error.type)}`}
        >
          <div className="flex items-start justify-between">
            <div className="flex items-start gap-2">
              {getErrorIcon(error.type)}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium">{error.message}</p>
                
                {showDetails && error.details && (
                  <details className="mt-2">
                    <summary className="text-xs cursor-pointer">Technical details</summary>
                    <pre className="text-xs mt-1 bg-white bg-opacity-50 p-2 rounded overflow-auto">
                      {JSON.stringify(error.details, null, 2)}
                    </pre>
                  </details>
                )}
                
                <p className="text-xs mt-1 opacity-75">
                  {error.timestamp.toLocaleTimeString()}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-1 ml-2">
              {error.retryable && (
                <button
                  onClick={() => retryAction(error.id, async () => {
                    // This would be provided by the component using the error
                    throw new Error('Retry action not implemented');
                  })}
                  className="text-xs opacity-75 hover:opacity-100 flex items-center gap-1"
                  title="Retry action"
                >
                  <RefreshCw className="h-3 w-3" />
                </button>
              )}
              
              <button
                onClick={() => removeError(error.id)}
                className="text-xs opacity-75 hover:opacity-100"
                title="Dismiss"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          </div>

          {error.type === 'rate_limit' && error.retryAfter && (
            <div className="mt-2 text-xs">
              <div className="bg-white bg-opacity-50 rounded px-2 py-1">
                ⏱️ Can retry in {error.retryAfter} seconds
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// Hook for API calls with automatic error handling
export const useApiCall = () => {
  const { addError } = useErrorHandling();

  const callApi = useCallback(async <T,>(
    apiCall: () => Promise<T>,
    options: {
      endpoint?: string;
      rateLimitChecks?: boolean;
      customErrorHandler?: (error: any) => Omit<ErrorInfo, 'id' | 'timestamp'> | null;
    } = {}
  ): Promise<T | null> => {
    try {
      return await apiCall();
    } catch (error: any) {
      const errorInfo = options.customErrorHandler?.(error) || parseApiError(error);
      addError(errorInfo);
      return null;
    }
  }, [addError]);

  return { callApi };
};

export default ErrorProvider;