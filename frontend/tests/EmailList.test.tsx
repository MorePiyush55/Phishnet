/**
 * EmailList Component Tests
 * 
 * Tests for the EmailList component including:
 * - Rendering emails
 * - Virtual scrolling
 * - Email selection
 * - Keyboard navigation
 * - Accessibility
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { EmailList } from '../components/EmailList';

// Mock data
const mockEmails = [
    {
        message_id: 'msg_1',
        thread_id: 'thread_1',
        sender: { name: 'John Doe', email: 'john@example.com' },
        subject: 'Test Email 1',
        snippet: 'This is a test email',
        is_read: false,
        is_starred: false,
        has_attachment: false,
        threat_score: 0.1,
        risk_level: 'SAFE',
        received_at: '2024-01-01T10:00:00Z',
        labels: [],
        folder: 'inbox',
    },
    {
        message_id: 'msg_2',
        thread_id: 'thread_2',
        sender: { name: 'Jane Smith', email: 'jane@example.com' },
        subject: 'Test Email 2',
        snippet: 'Another test email',
        is_read: true,
        is_starred: true,
        has_attachment: true,
        threat_score: 0.8,
        risk_level: 'SUSPICIOUS',
        received_at: '2024-01-02T10:00:00Z',
        labels: ['work'],
        folder: 'inbox',
    },
];

describe('EmailList', () => {
    const mockOnEmailClick = jest.fn();
    const mockOnEmailSelect = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
    });

    // ==================== Rendering Tests ====================

    test('renders email list correctly', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(screen.getByText('Test Email 1')).toBeInTheDocument();
        expect(screen.getByText('Test Email 2')).toBeInTheDocument();
    });

    test('displays sender information', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(screen.getByText('John Doe')).toBeInTheDocument();
        expect(screen.getByText('Jane Smith')).toBeInTheDocument();
    });

    test('shows read/unread status', () => {
        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const emailItems = container.querySelectorAll('[data-email-id]');
        expect(emailItems[0]).toHaveClass('unread');
        expect(emailItems[1]).toHaveClass('read');
    });

    test('displays star icon for starred emails', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const starIcons = screen.getAllByLabelText(/star/i);
        expect(starIcons).toHaveLength(2);
    });

    test('shows attachment icon when email has attachments', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(screen.getByLabelText(/attachment/i)).toBeInTheDocument();
    });

    test('displays threat level indicator', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(screen.getByText(/SUSPICIOUS/i)).toBeInTheDocument();
    });

    // ==================== Interaction Tests ====================

    test('calls onEmailClick when email is clicked', async () => {
        const user = userEvent.setup();

        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        await user.click(screen.getByText('Test Email 1'));

        expect(mockOnEmailClick).toHaveBeenCalledWith(mockEmails[0]);
    });

    test('calls onEmailSelect when checkbox is clicked', async () => {
        const user = userEvent.setup();

        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const checkbox = container.querySelector('input[type="checkbox"]');
        await user.click(checkbox!);

        expect(mockOnEmailSelect).toHaveBeenCalledWith('msg_1', true);
    });

    // ==================== Keyboard Navigation Tests ====================

    test('supports keyboard navigation with j/k keys', () => {
        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const emailItems = container.querySelectorAll('[data-email-id]');

        // Press 'j' to move down
        fireEvent.keyDown(document, { key: 'j' });
        expect(emailItems[1]).toHaveFocus();

        // Press 'k' to move up
        fireEvent.keyDown(document, { key: 'k' });
        expect(emailItems[0]).toHaveFocus();
    });

    test('opens email with Enter key', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        fireEvent.keyDown(document, { key: 'Enter' });

        expect(mockOnEmailClick).toHaveBeenCalled();
    });

    test('selects email with x key', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        fireEvent.keyDown(document, { key: 'x' });

        expect(mockOnEmailSelect).toHaveBeenCalled();
    });

    // ==================== Accessibility Tests ====================

    test('has proper ARIA attributes', () => {
        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const list = container.querySelector('[role="listbox"]');
        expect(list).toBeInTheDocument();
        expect(list).toHaveAttribute('aria-label', 'Email list');

        const emailItems = container.querySelectorAll('[role="option"]');
        expect(emailItems).toHaveLength(2);
    });

    test('provides descriptive aria-labels for emails', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(
            screen.getByLabelText(/Unread email from John Doe/i)
        ).toBeInTheDocument();

        expect(
            screen.getByLabelText(/Read starred email from Jane Smith.*SUSPICIOUS/i)
        ).toBeInTheDocument();
    });

    test('supports focus management', () => {
        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const firstEmail = container.querySelector('[data-email-id="msg_1"]');
        expect(firstEmail).toHaveAttribute('tabindex', '0');

        const secondEmail = container.querySelector('[data-email-id="msg_2"]');
        expect(secondEmail).toHaveAttribute('tabindex', '-1');
    });

    // ==================== Empty State Tests ====================

    test('renders empty state when no emails', () => {
        render(
            <EmailList
                emails={[]}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        expect(screen.getByText(/No emails/i)).toBeInTheDocument();
    });

    // ==================== Loading State Tests ====================

    test('shows loading skeleton', () => {
        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
                isLoading={true}
            />
        );

        expect(screen.getByTestId('loading-skeleton')).toBeInTheDocument();
    });

    // ==================== Virtual Scrolling Tests ====================

    test('renders only visible emails with virtual scrolling', () => {
        const manyEmails = Array.from({ length: 1000 }, (_, i) => ({
            ...mockEmails[0],
            message_id: `msg_${i}`,
            subject: `Email ${i}`,
        }));

        const { container } = render(
            <EmailList
                emails={manyEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        // Should not render all 1000 emails
        const renderedEmails = container.querySelectorAll('[data-email-id]');
        expect(renderedEmails.length).toBeLessThan(100);
    });

    // ==================== Selection Tests ====================

    test('supports multi-selection', async () => {
        const user = userEvent.setup();

        const { container } = render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const checkboxes = container.querySelectorAll('input[type="checkbox"]');

        await user.click(checkboxes[0]);
        await user.click(checkboxes[1]);

        expect(mockOnEmailSelect).toHaveBeenCalledTimes(2);
    });

    test('select all checkbox selects all emails', async () => {
        const user = userEvent.setup();

        render(
            <EmailList
                emails={mockEmails}
                onEmailClick={mockOnEmailClick}
                onEmailSelect={mockOnEmailSelect}
            />
        );

        const selectAllCheckbox = screen.getByLabelText(/select all/i);
        await user.click(selectAllCheckbox);

        expect(mockOnEmailSelect).toHaveBeenCalledTimes(mockEmails.length);
    });
});
