// Frontend Error Boundary and Logging Component

import React from 'react';
import { ErrorBoundary } from 'react-error-boundary';

// Error Fallback Component
function ErrorFallback({ error, resetErrorBoundary }) {
  const handleReportError = () => {
    // Send error to logging service
    logError({
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      userId: getCurrentUserId(), // Implement based on your auth system
    });
  };

  return (
    <div className="error-boundary" role="alert">
      <div className="error-container">
        <h2>Something went wrong</h2>
        <details style={{ whiteSpace: 'pre-wrap' }}>
          <summary>Error details</summary>
          {error.message}
        </details>
        <div className="error-actions">
          <button onClick={resetErrorBoundary} className="btn btn-primary">
            Try again
          </button>
          <button onClick={handleReportError} className="btn btn-secondary">
            Report issue
          </button>
        </div>
      </div>
    </div>
  );
}

// Client-side Error Logging
class ErrorLogger {
  constructor() {
    this.logQueue = [];
    this.isOnline = navigator.onLine;
    this.setupEventListeners();
  }

  setupEventListeners() {
    // Listen for online/offline events
    window.addEventListener('online', () => {
      this.isOnline = true;
      this.flushLogs();
    });

    window.addEventListener('offline', () => {
      this.isOnline = false;
    });

    // Global error handler
    window.addEventListener('error', (event) => {
      this.logError({
        type: 'javascript_error',
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack,
        timestamp: new Date().toISOString(),
      });
    });

    // Unhandled promise rejection handler
    window.addEventListener('unhandledrejection', (event) => {
      this.logError({
        type: 'unhandled_rejection',
        message: event.reason?.message || 'Unhandled promise rejection',
        stack: event.reason?.stack,
        timestamp: new Date().toISOString(),
      });
    });
  }

  logError(errorData) {
    const logEntry = {
      ...errorData,
      sessionId: this.getSessionId(),
      userId: getCurrentUserId(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      timestamp: errorData.timestamp || new Date().toISOString(),
    };

    // Sanitize sensitive data
    const sanitizedEntry = this.sanitizeLogEntry(logEntry);

    if (this.isOnline) {
      this.sendLog(sanitizedEntry);
    } else {
      this.queueLog(sanitizedEntry);
    }
  }

  sanitizeLogEntry(entry) {
    // Remove sensitive information from logs
    const sanitized = { ...entry };
    
    // Remove potential sensitive data from error messages
    if (sanitized.message) {
      sanitized.message = sanitized.message.replace(
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        '[EMAIL_REDACTED]'
      );
      sanitized.message = sanitized.message.replace(
        /\b\d{16}\b|\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
        '[CARD_REDACTED]'
      );
    }

    return sanitized;
  }

  async sendLog(logEntry) {
    try {
      await fetch('/api/logs/client-errors', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getAuthToken()}`,
        },
        body: JSON.stringify(logEntry),
      });
    } catch (error) {
      // If sending fails, queue the log
      this.queueLog(logEntry);
    }
  }

  queueLog(logEntry) {
    this.logQueue.push(logEntry);
    
    // Limit queue size to prevent memory issues
    if (this.logQueue.length > 100) {
      this.logQueue.shift();
    }

    // Store in localStorage as backup
    try {
      const existingLogs = JSON.parse(localStorage.getItem('errorLogs') || '[]');
      existingLogs.push(logEntry);
      
      // Keep only last 50 logs in localStorage
      if (existingLogs.length > 50) {
        existingLogs.splice(0, existingLogs.length - 50);
      }
      
      localStorage.setItem('errorLogs', JSON.stringify(existingLogs));
    } catch (e) {
      // localStorage might be full or unavailable
      console.warn('Failed to store error log in localStorage:', e);
    }
  }

  async flushLogs() {
    const logsToSend = [...this.logQueue];
    this.logQueue = [];

    for (const log of logsToSend) {
      await this.sendLog(log);
    }

    // Also send any logs from localStorage
    try {
      const storedLogs = JSON.parse(localStorage.getItem('errorLogs') || '[]');
      for (const log of storedLogs) {
        await this.sendLog(log);
      }
      localStorage.removeItem('errorLogs');
    } catch (e) {
      console.warn('Failed to flush logs from localStorage:', e);
    }
  }

  getSessionId() {
    let sessionId = sessionStorage.getItem('sessionId');
    if (!sessionId) {
      sessionId = generateUUID();
      sessionStorage.setItem('sessionId', sessionId);
    }
    return sessionId;
  }
}

// Performance Monitoring
class PerformanceMonitor {
  constructor() {
    this.metrics = {};
    this.setupPerformanceObserver();
  }

  setupPerformanceObserver() {
    if ('PerformanceObserver' in window) {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          this.recordMetric(entry);
        }
      });

      observer.observe({ entryTypes: ['navigation', 'resource', 'measure'] });
    }
  }

  recordMetric(entry) {
    switch (entry.entryType) {
      case 'navigation':
        this.logPageLoad(entry);
        break;
      case 'resource':
        this.logResourceLoad(entry);
        break;
      case 'measure':
        this.logCustomMeasure(entry);
        break;
    }
  }

  logPageLoad(entry) {
    const pageLoadData = {
      type: 'page_load',
      url: window.location.href,
      loadTime: entry.loadEventEnd - entry.loadEventStart,
      domContentLoaded: entry.domContentLoadedEventEnd - entry.domContentLoadedEventStart,
      firstContentfulPaint: this.getFirstContentfulPaint(),
      timestamp: new Date().toISOString(),
    };

    this.sendMetric(pageLoadData);
  }

  logResourceLoad(entry) {
    // Only log slow resources or failures
    if (entry.duration > 1000 || entry.transferSize === 0) {
      const resourceData = {
        type: 'resource_load',
        name: entry.name,
        duration: entry.duration,
        size: entry.transferSize,
        timestamp: new Date().toISOString(),
      };

      this.sendMetric(resourceData);
    }
  }

  logCustomMeasure(entry) {
    const measureData = {
      type: 'custom_measure',
      name: entry.name,
      duration: entry.duration,
      timestamp: new Date().toISOString(),
    };

    this.sendMetric(measureData);
  }

  getFirstContentfulPaint() {
    const entries = performance.getEntriesByType('paint');
    const fcp = entries.find(entry => entry.name === 'first-contentful-paint');
    return fcp ? fcp.startTime : null;
  }

  async sendMetric(metricData) {
    try {
      await fetch('/api/metrics/client', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getAuthToken()}`,
        },
        body: JSON.stringify(metricData),
      });
    } catch (error) {
      // Silently fail for metrics - don't impact user experience
      console.debug('Failed to send metric:', error);
    }
  }

  measureOperation(name, operation) {
    const startMark = `${name}-start`;
    const endMark = `${name}-end`;
    const measureName = name;

    performance.mark(startMark);
    
    const result = operation();
    
    if (result instanceof Promise) {
      return result.finally(() => {
        performance.mark(endMark);
        performance.measure(measureName, startMark, endMark);
      });
    } else {
      performance.mark(endMark);
      performance.measure(measureName, startMark, endMark);
      return result;
    }
  }
}

// Main App Component with Error Boundary
export function AppWithErrorBoundary({ children }) {
  const handleError = (error, errorInfo) => {
    // Log error to our error logging service
    errorLogger.logError({
      type: 'react_error',
      message: error.message,
      stack: error.stack,
      componentStack: errorInfo.componentStack,
      timestamp: new Date().toISOString(),
    });
  };

  return (
    <ErrorBoundary
      FallbackComponent={ErrorFallback}
      onError={handleError}
      onReset={() => window.location.reload()}
    >
      {children}
    </ErrorBoundary>
  );
}

// Utility functions
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function getCurrentUserId() {
  // Implement based on your authentication system
  return localStorage.getItem('userId') || 'anonymous';
}

function getAuthToken() {
  // Implement based on your authentication system
  return localStorage.getItem('authToken') || '';
}

// Initialize global instances
const errorLogger = new ErrorLogger();
const performanceMonitor = new PerformanceMonitor();

// Export for use in other components
export { errorLogger, performanceMonitor };

// CSS for Error Boundary
const errorBoundaryStyles = `
.error-boundary {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  background-color: #f8f9fa;
  border: 1px solid #dee2e6;
  border-radius: 0.5rem;
  padding: 2rem;
}

.error-container {
  text-align: center;
  max-width: 600px;
}

.error-container h2 {
  color: #dc3545;
  margin-bottom: 1rem;
}

.error-container details {
  margin: 1rem 0;
  padding: 1rem;
  background-color: #f1f3f4;
  border-radius: 0.25rem;
  text-align: left;
  font-family: monospace;
  font-size: 0.875rem;
}

.error-actions {
  display: flex;
  gap: 1rem;
  justify-content: center;
  margin-top: 1.5rem;
}

.btn {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 0.25rem;
  cursor: pointer;
  font-size: 0.875rem;
  text-decoration: none;
  display: inline-block;
}

.btn-primary {
  background-color: #007bff;
  color: white;
}

.btn-secondary {
  background-color: #6c757d;
  color: white;
}

.btn:hover {
  opacity: 0.9;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleSheet = document.createElement('style');
  styleSheet.textContent = errorBoundaryStyles;
  document.head.appendChild(styleSheet);
}
