/**
 * Secure Content Renderer - Safe DOM creation and content sanitization for React
 * 
 * This utility provides secure rendering of potentially unsafe content from the API,
 * ensuring no XSS vulnerabilities while maintaining user experience.
 */

import React, { ReactNode } from 'react';
import DOMPurify from 'dompurify';

// Security configuration for DOMPurify
const PURIFY_CONFIG = {
  // Allowed tags - very restrictive for security
  ALLOWED_TAGS: [
    'p', 'br', 'strong', 'em', 'u', 'span', 'div',
    'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'code', 'pre'
  ],
  
  // Allowed attributes - no event handlers or dangerous attributes
  ALLOWED_ATTR: [
    'class', 'id', 'title', 'aria-label', 'aria-describedby',
    'role', 'data-testid'
  ],
  
  // Forbidden tags - explicitly block dangerous elements
  FORBID_TAGS: [
    'script', 'object', 'embed', 'iframe', 'form', 'input',
    'textarea', 'select', 'button', 'link', 'style', 'meta'
  ],
  
  // Forbidden attributes - block all event handlers and dangerous attributes
  FORBID_ATTR: [
    'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus', 'onblur',
    'onkeydown', 'onkeyup', 'onsubmit', 'href', 'src', 'action',
    'formaction', 'background', 'dynsrc', 'lowsrc'
  ]
};

// Initialize DOMPurify with strict configuration
const configureDOMPurify = () => {
  // Remove any existing hooks
  DOMPurify.removeAllHooks();
  
  // Add security hook to block dangerous URLs
  DOMPurify.addHook('beforeSanitizeAttributes', (node: Element) => {
    // Block javascript: and data: URLs
    const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'blob:'];
    
    ['href', 'src', 'action', 'formaction', 'background'].forEach(attr => {
      if (node.hasAttribute && node.hasAttribute(attr)) {
        const value = node.getAttribute(attr);
        if (value && dangerousSchemes.some(scheme => value.toLowerCase().startsWith(scheme))) {
          node.removeAttribute(attr);
        }
      }
    });
  });
  
  return DOMPurify;
};

// Global DOMPurify instance
const purifier = configureDOMPurify();

export interface SecureContentProps {
  /** Content to render safely */
  content: string;
  /** Additional CSS classes */
  className?: string;
  /** Whether to allow limited HTML tags */
  allowHTML?: boolean;
  /** Maximum content length before truncation */
  maxLength?: number;
  /** Fallback content if sanitization fails */
  fallback?: ReactNode;
  /** Test ID for automated testing */
  testId?: string;
}

/**
 * Secure text renderer - always safe, never renders HTML
 */
export const SecureText: React.FC<SecureContentProps> = ({
  content,
  className = '',
  maxLength,
  fallback = 'Content not available',
  testId
}) => {
  try {
    // Ensure content is a string
    const textContent = String(content || '');
    
    // Apply length limit if specified
    const truncatedContent = maxLength && textContent.length > maxLength
      ? `${textContent.substring(0, maxLength)}...`
      : textContent;
    
    return (
      <span 
        className={`secure-text ${className}`}
        data-testid={testId}
        title={maxLength && textContent.length > maxLength ? textContent : undefined}
      >
        {truncatedContent}
      </span>
    );
  } catch (error) {
    console.error('SecureText rendering error:', error);
    return <span className={className}>{fallback}</span>;
  }
};

/**
 * Secure HTML renderer - sanitizes HTML content before rendering
 * Use only when HTML rendering is absolutely necessary
 */
export const SecureHTML: React.FC<SecureContentProps> = ({
  content,
  className = '',
  maxLength,
  fallback = 'Content not available',
  testId
}) => {
  try {
    // Ensure content is a string
    const htmlContent = String(content || '');
    
    // Apply length limit before sanitization for performance
    const truncatedContent = maxLength && htmlContent.length > maxLength
      ? `${htmlContent.substring(0, maxLength)}...`
      : htmlContent;
    
    // Sanitize HTML with strict configuration
    const sanitizedHTML = purifier.sanitize(truncatedContent, {
      ALLOWED_TAGS: PURIFY_CONFIG.ALLOWED_TAGS,
      ALLOWED_ATTR: PURIFY_CONFIG.ALLOWED_ATTR,
      FORBID_TAGS: PURIFY_CONFIG.FORBID_TAGS,
      FORBID_ATTR: PURIFY_CONFIG.FORBID_ATTR,
      KEEP_CONTENT: true,
      RETURN_DOM: false,
      RETURN_DOM_FRAGMENT: false,
      WHOLE_DOCUMENT: false
    });
    
    // Additional validation - reject if sanitization removed too much content
    if (htmlContent.length > 0 && sanitizedHTML.length === 0) {
      console.warn('HTML content was completely removed by sanitization');
      return <SecureText content={htmlContent} className={className} testId={testId} />;
    }
    
    return (
      <div 
        className={`secure-html ${className}`}
        data-testid={testId}
        dangerouslySetInnerHTML={{ __html: sanitizedHTML }}
      />
    );
  } catch (error) {
    console.error('SecureHTML rendering error:', error);
    return <div className={className}>{fallback}</div>;
  }
};

/**
 * Smart content renderer - chooses appropriate rendering method
 * Prefers text rendering for security, falls back to sanitized HTML only if needed
 */
export const SecureContent: React.FC<SecureContentProps> = ({
  content,
  className = '',
  allowHTML = false,
  maxLength,
  fallback = 'Content not available',
  testId
}) => {
  try {
    const textContent = String(content || '');
    
    // If HTML is not allowed or content doesn't contain HTML tags, use text rendering
    if (!allowHTML || !textContent.includes('<')) {
      return (
        <SecureText 
          content={textContent}
          className={className}
          maxLength={maxLength}
          fallback={fallback}
          testId={testId}
        />
      );
    }
    
    // Only use HTML rendering if explicitly allowed and content contains HTML
    return (
      <SecureHTML 
        content={textContent}
        className={className}
        maxLength={maxLength}
        fallback={fallback}
        testId={testId}
      />
    );
  } catch (error) {
    console.error('SecureContent rendering error:', error);
    return <span className={className}>{fallback}</span>;
  }
};

/**
 * Secure list renderer for arrays of content
 */
export const SecureList: React.FC<{
  items: string[];
  className?: string;
  itemClassName?: string;
  allowHTML?: boolean;
  maxLength?: number;
  testId?: string;
}> = ({
  items = [],
  className = '',
  itemClassName = '',
  allowHTML = false,
  maxLength,
  testId
}) => {
  if (!Array.isArray(items) || items.length === 0) {
    return <div className={className}>No items to display</div>;
  }
  
  return (
    <ul className={`secure-list ${className}`} data-testid={testId}>
      {items.map((item, index) => (
        <li key={index} className={`secure-list-item ${itemClassName}`}>
          <SecureContent 
            content={item}
            allowHTML={allowHTML}
            maxLength={maxLength}
            testId={`${testId}-item-${index}`}
          />
        </li>
      ))}
    </ul>
  );
};

/**
 * Hook for safe content processing
 */
export const useSecureContent = () => {
  const sanitizeText = (text: string): string => {
    try {
      // Remove any HTML tags and decode HTML entities
      const textContent = String(text || '');
      const withoutTags = textContent.replace(/<[^>]*>/g, '');
      const decoded = new DOMParser().parseFromString(withoutTags, 'text/html').body.textContent || '';
      return decoded.trim();
    } catch (error) {
      console.error('Text sanitization error:', error);
      return String(text || '').replace(/<[^>]*>/g, '');
    }
  };
  
  const sanitizeHTML = (html: string): string => {
    try {
      return purifier.sanitize(html, {
        ALLOWED_TAGS: PURIFY_CONFIG.ALLOWED_TAGS,
        ALLOWED_ATTR: PURIFY_CONFIG.ALLOWED_ATTR,
        FORBID_TAGS: PURIFY_CONFIG.FORBID_TAGS,
        FORBID_ATTR: PURIFY_CONFIG.FORBID_ATTR
      });
    } catch (error) {
      console.error('HTML sanitization error:', error);
      return sanitizeText(html);
    }
  };
  
  const isHTMLContent = (content: string): boolean => {
    return content.includes('<') && content.includes('>');
  };
  
  return {
    sanitizeText,
    sanitizeHTML,
    isHTMLContent
  };
};

/**
 * Utility function to safely extract text from API responses
 */
export const extractSafeContent = (apiResponse: any, path: string): string => {
  try {
    const keys = path.split('.');
    let value = apiResponse;
    
    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return '';
      }
    }
    
    return String(value || '');
  } catch (error) {
    console.error('Content extraction error:', error);
    return '';
  }
};

// Security audit function for development
export const auditContentSecurity = (content: string): {
  isSafe: boolean;
  violations: string[];
  recommendations: string[];
} => {
  const violations: string[] = [];
  const recommendations: string[] = [];
  
  // Check for dangerous patterns
  const dangerousPatterns = [
    { pattern: /<script/i, violation: 'Script tags detected' },
    { pattern: /javascript:/i, violation: 'JavaScript URL detected' },
    { pattern: /data:.*script/i, violation: 'Data URL with script detected' },
    { pattern: /on\w+\s*=/i, violation: 'Event handler attributes detected' },
    { pattern: /<iframe/i, violation: 'Iframe tags detected' },
    { pattern: /<object/i, violation: 'Object tags detected' },
    { pattern: /<embed/i, violation: 'Embed tags detected' }
  ];
  
  dangerousPatterns.forEach(({ pattern, violation }) => {
    if (pattern.test(content)) {
      violations.push(violation);
    }
  });
  
  // Generate recommendations
  if (violations.length > 0) {
    recommendations.push('Use SecureText component for text-only content');
    recommendations.push('Use SecureHTML component if HTML rendering is required');
    recommendations.push('Verify content is sanitized by backend before display');
  }
  
  if (content.includes('<')) {
    recommendations.push('Consider using markdown instead of HTML for rich text');
  }
  
  return {
    isSafe: violations.length === 0,
    violations,
    recommendations
  };
};

export default {
  SecureText,
  SecureHTML,
  SecureContent,
  SecureList,
  useSecureContent,
  extractSafeContent,
  auditContentSecurity
};
