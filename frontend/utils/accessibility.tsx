/**
 * Accessibility Enhancements for Inbox Components
 * 
 * Implements WCAG AA compliance with:
 * - ARIA labels and roles
 * - Keyboard navigation
 * - Focus management
 * - Screen reader support
 */

import { useEffect, useRef, useCallback } from 'react';

// ==================== Keyboard Navigation Hook ====================

export interface KeyboardShortcuts {
    [key: string]: () => void;
}

export const useKeyboardNavigation = (shortcuts: KeyboardShortcuts) => {
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            // Don't trigger shortcuts when typing in input fields
            if (
                e.target instanceof HTMLInputElement ||
                e.target instanceof HTMLTextAreaElement
            ) {
                return;
            }

            const key = e.key.toLowerCase();
            const withCtrl = e.ctrlKey || e.metaKey;
            const withShift = e.shiftKey;

            // Build shortcut key
            let shortcutKey = '';
            if (withCtrl) shortcutKey += 'ctrl+';
            if (withShift) shortcutKey += 'shift+';
            shortcutKey += key;

            // Execute shortcut if exists
            if (shortcuts[shortcutKey]) {
                e.preventDefault();
                shortcuts[shortcutKey]();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [shortcuts]);
};

// ==================== Focus Management ====================

export const useFocusTrap = (isActive: boolean) => {
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!isActive || !containerRef.current) return;

        const container = containerRef.current;
        const focusableElements = container.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );

        const firstElement = focusableElements[0] as HTMLElement;
        const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;

        const handleTabKey = (e: KeyboardEvent) => {
            if (e.key !== 'Tab') return;

            if (e.shiftKey) {
                // Shift + Tab
                if (document.activeElement === firstElement) {
                    e.preventDefault();
                    lastElement?.focus();
                }
            } else {
                // Tab
                if (document.activeElement === lastElement) {
                    e.preventDefault();
                    firstElement?.focus();
                }
            }
        };

        container.addEventListener('keydown', handleTabKey as EventListener);
        firstElement?.focus();

        return () => {
            container.removeEventListener('keydown', handleTabKey as EventListener);
        };
    }, [isActive]);

    return containerRef;
};

// ==================== Screen Reader Announcements ====================

export const announce = (message: string, priority: 'polite' | 'assertive' = 'polite') => {
    const announcement = document.createElement('div');
    announcement.setAttribute('role', 'status');
    announcement.setAttribute('aria-live', priority);
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;

    document.body.appendChild(announcement);

    setTimeout(() => {
        document.body.removeChild(announcement);
    }, 1000);
};

// ==================== Inbox-Specific Keyboard Shortcuts ====================

export const INBOX_SHORTCUTS = {
    // Navigation
    'j': 'Next email',
    'k': 'Previous email',
    'o': 'Open email',
    'u': 'Return to email list',

    // Actions
    'e': 'Archive email',
    's': 'Star/unstar email',
    'r': 'Reply',
    'a': 'Reply all',
    'f': 'Forward',
    'shift+i': 'Mark as read',
    'shift+u': 'Mark as unread',
    '#': 'Delete',

    // Compose
    'c': 'Compose new email',

    // Search
    '/': 'Focus search',

    // Selection
    'x': 'Select email',
    'shift+a': 'Select all',

    // Navigation
    'g+i': 'Go to Inbox',
    'g+s': 'Go to Starred',
    'g+t': 'Go to Sent',
    'g+d': 'Go to Drafts',
};

// ==================== ARIA Labels Helper ====================

export const getEmailAriaLabel = (email: any): string => {
    const parts = [
        email.is_read ? 'Read' : 'Unread',
        email.is_starred ? 'starred' : '',
        'email from',
        email.sender.name || email.sender.email,
        'subject:',
        email.subject,
        email.has_attachment ? 'with attachment' : '',
        email.risk_level !== 'SAFE' ? `Warning: ${email.risk_level}` : '',
    ];

    return parts.filter(Boolean).join(' ');
};

// ==================== Skip Links Component ====================

export const SkipLinks = () => (
    <div className="skip-links">
        <a href="#main-content" className="skip-link">
            Skip to main content
        </a>
        <a href="#email-list" className="skip-link">
            Skip to email list
        </a>
        <a href="#search" className="skip-link">
            Skip to search
        </a>
    </div>
);

// ==================== Accessible Button Component ====================

interface AccessibleButtonProps {
    onClick: () => void;
    ariaLabel: string;
    icon?: React.ReactNode;
    children?: React.ReactNode;
    disabled?: boolean;
}

export const AccessibleButton: React.FC<AccessibleButtonProps> = ({
    onClick,
    ariaLabel,
    icon,
    children,
    disabled = false,
}) => (
    <button
        onClick={onClick}
        aria-label={ariaLabel}
        disabled={disabled}
        className="accessible-button"
        type="button"
    >
        {icon && <span aria-hidden="true">{icon}</span>}
        {children}
    </button>
);

// ==================== CSS for Accessibility ====================

export const accessibilityStyles = `
/* Screen reader only content */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}

/* Skip links */
.skip-links {
  position: absolute;
  top: 0;
  left: 0;
  z-index: 9999;
}

.skip-link {
  position: absolute;
  left: -9999px;
  padding: 0.5rem 1rem;
  background: #000;
  color: #fff;
  text-decoration: none;
  font-weight: bold;
}

.skip-link:focus {
  left: 0;
  top: 0;
}

/* Focus visible (keyboard navigation) */
*:focus-visible {
  outline: 2px solid #4A90E2;
  outline-offset: 2px;
}

/* High contrast mode support */
@media (prefers-contrast: high) {
  * {
    border-color: currentColor !important;
  }
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
`;

// ==================== Usage Examples ====================

/*
// In EmailList component:
import { useKeyboardNavigation, getEmailAriaLabel, announce } from './accessibility';

const EmailList = ({ emails, onEmailClick }) => {
  const [selectedIndex, setSelectedIndex] = useState(0);

  useKeyboardNavigation({
    'j': () => {
      const newIndex = Math.min(selectedIndex + 1, emails.length - 1);
      setSelectedIndex(newIndex);
      announce(`Email ${newIndex + 1} of ${emails.length}`);
    },
    'k': () => {
      const newIndex = Math.max(selectedIndex - 1, 0);
      setSelectedIndex(newIndex);
      announce(`Email ${newIndex + 1} of ${emails.length}`);
    },
    'o': () => {
      onEmailClick(emails[selectedIndex]);
      announce(`Opening email: ${emails[selectedIndex].subject}`);
    },
  });

  return (
    <div role="listbox" aria-label="Email list">
      {emails.map((email, index) => (
        <div
          key={email.message_id}
          role="option"
          aria-selected={index === selectedIndex}
          aria-label={getEmailAriaLabel(email)}
          tabIndex={index === selectedIndex ? 0 : -1}
        >
          {email.subject}
        </div>
      ))}
    </div>
  );
};

// In modal/dialog:
import { useFocusTrap } from './accessibility';

const Modal = ({ isOpen, onClose, children }) => {
  const modalRef = useFocusTrap(isOpen);

  return isOpen ? (
    <div
      ref={modalRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      {children}
    </div>
  ) : null;
};
*/
