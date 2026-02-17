import React, { useState, useEffect } from 'react';
import { Mail, Star, Paperclip, AlertTriangle, ChevronRight } from 'lucide-react';
import { FixedSizeList as List } from 'react-window';
import AutoSizer from 'react-virtualized-auto-sizer';

/**
 * EmailList Component
 * 
 * High-performance email list with virtual scrolling for 10k+ emails.
 * Uses react-window for efficient rendering of large lists.
 */

// ==================== Types ====================

interface EmailParticipant {
    name?: string;
    email: string;
}

interface Email {
    message_id: string;
    thread_id: string;
    sender: EmailParticipant;
    subject: string;
    snippet: string;
    is_read: boolean;
    is_starred: boolean;
    has_attachment: boolean;
    threat_score: number;
    risk_level: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
    received_at: string;
    labels: string[];
}

interface EmailListProps {
    emails: Email[];
    selectedEmails: Set<string>;
    currentEmailId?: string;
    onEmailClick: (email: Email) => void;
    onEmailSelect: (messageId: string, selected: boolean) => void;
    onSelectAll: (selected: boolean) => void;
    onStarToggle: (messageId: string, starred: boolean) => void;
    onArchive: (messageId: string) => void;
    onDelete: (messageId: string) => void;
    onMarkRead: (messageId: string, read: boolean) => void;
    isLoading?: boolean;
    hasMore?: boolean;
    onLoadMore?: () => void;
}

// ==================== Helper Functions ====================

const formatTimestamp = (timestamp: string): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays}d ago`;

    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const getThreatBadgeColor = (riskLevel: string): string => {
    switch (riskLevel) {
        case 'PHISHING':
            return 'bg-red-100 text-red-800 border-red-300';
        case 'SUSPICIOUS':
            return 'bg-yellow-100 text-yellow-800 border-yellow-300';
        case 'SAFE':
        default:
            return 'bg-green-100 text-green-800 border-green-300';
    }
};

const getThreatIcon = (riskLevel: string) => {
    if (riskLevel === 'PHISHING' || riskLevel === 'SUSPICIOUS') {
        return <AlertTriangle className="w-3 h-3" />;
    }
    return null;
};

// ==================== Email Row Component ====================

interface EmailRowProps {
    email: Email;
    isSelected: boolean;
    isCurrent: boolean;
    onEmailClick: (email: Email) => void;
    onEmailSelect: (messageId: string, selected: boolean) => void;
    onStarToggle: (messageId: string, starred: boolean) => void;
    onArchive: (messageId: string) => void;
    onDelete: (messageId: string) => void;
    onMarkRead: (messageId: string, read: boolean) => void;
    style: React.CSSProperties;
}

const EmailRow: React.FC<EmailRowProps> = React.memo(({
    email,
    isSelected,
    isCurrent,
    onEmailClick,
    onEmailSelect,
    onStarToggle,
    onArchive,
    onDelete,
    onMarkRead,
    style,
}) => {
    const [isHovered, setIsHovered] = useState(false);

    const handleCheckboxClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        onEmailSelect(email.message_id, !isSelected);
    };

    const handleStarClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        onStarToggle(email.message_id, !email.is_starred);
    };

    const handleArchiveClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        onArchive(email.message_id);
    };

    const handleDeleteClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        onDelete(email.message_id);
    };

    const handleMarkReadClick = (e: React.MouseEvent) => {
        e.stopPropagation();
        onMarkRead(email.message_id, !email.is_read);
    };

    return (
        <div
            style={style}
            className={`
        flex items-center px-4 py-3 border-b border-gray-200 cursor-pointer
        transition-colors duration-150
        ${isCurrent ? 'bg-blue-50 border-l-4 border-l-blue-500' : 'border-l-4 border-l-transparent'}
        ${isSelected ? 'bg-blue-50' : 'hover:bg-gray-50'}
        ${!email.is_read ? 'bg-white' : 'bg-gray-50'}
      `}
            onClick={() => onEmailClick(email)}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
        >
            {/* Checkbox */}
            <div className="flex-shrink-0 mr-3">
                <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={handleCheckboxClick}
                    onClick={handleCheckboxClick}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
            </div>

            {/* Star */}
            <div className="flex-shrink-0 mr-3">
                <button
                    onClick={handleStarClick}
                    className={`p-1 rounded hover:bg-gray-200 transition-colors ${email.is_starred ? 'text-yellow-500' : 'text-gray-400'
                        }`}
                    aria-label={email.is_starred ? 'Unstar' : 'Star'}
                >
                    <Star
                        className="w-4 h-4"
                        fill={email.is_starred ? 'currentColor' : 'none'}
                    />
                </button>
            </div>

            {/* Unread Indicator */}
            {!email.is_read && (
                <div className="flex-shrink-0 mr-3">
                    <div className="w-2 h-2 bg-blue-600 rounded-full"></div>
                </div>
            )}

            {/* Email Content */}
            <div className="flex-1 min-w-0">
                {/* Sender */}
                <div className="flex items-center mb-1">
                    <span className={`text-sm truncate ${!email.is_read ? 'font-semibold text-gray-900' : 'font-normal text-gray-700'}`}>
                        {email.sender.name || email.sender.email}
                    </span>

                    {/* Threat Badge */}
                    {email.risk_level !== 'SAFE' && (
                        <span className={`ml-2 inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full border ${getThreatBadgeColor(email.risk_level)}`}>
                            {getThreatIcon(email.risk_level)}
                            {email.risk_level}
                        </span>
                    )}
                </div>

                {/* Subject */}
                <div className={`text-sm mb-1 truncate ${!email.is_read ? 'font-semibold text-gray-900' : 'font-normal text-gray-700'}`}>
                    {email.subject || '(No subject)'}
                </div>

                {/* Snippet */}
                <div className="text-xs text-gray-600 truncate">
                    {email.snippet}
                </div>
            </div>

            {/* Right Side Icons */}
            <div className="flex-shrink-0 ml-4 flex items-center gap-2">
                {/* Attachment Icon */}
                {email.has_attachment && (
                    <Paperclip className="w-4 h-4 text-gray-400" />
                )}

                {/* Timestamp */}
                <span className="text-xs text-gray-500 min-w-[60px] text-right">
                    {formatTimestamp(email.received_at)}
                </span>

                {/* Hover Actions */}
                {isHovered && (
                    <div className="flex items-center gap-1 ml-2">
                        <button
                            onClick={handleArchiveClick}
                            className="p-1 rounded hover:bg-gray-200 text-gray-600"
                            title="Archive"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
                            </svg>
                        </button>
                        <button
                            onClick={handleDeleteClick}
                            className="p-1 rounded hover:bg-gray-200 text-gray-600"
                            title="Delete"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                        </button>
                        <button
                            onClick={handleMarkReadClick}
                            className="p-1 rounded hover:bg-gray-200 text-gray-600"
                            title={email.is_read ? 'Mark as unread' : 'Mark as read'}
                        >
                            <Mail className="w-4 h-4" />
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
});

EmailRow.displayName = 'EmailRow';

// ==================== Main EmailList Component ====================

export const EmailList: React.FC<EmailListProps> = ({
    emails,
    selectedEmails,
    currentEmailId,
    onEmailClick,
    onEmailSelect,
    onSelectAll,
    onStarToggle,
    onArchive,
    onDelete,
    onMarkRead,
    isLoading = false,
    hasMore = false,
    onLoadMore,
}) => {
    const allSelected = emails.length > 0 && emails.every(e => selectedEmails.has(e.message_id));
    const someSelected = emails.some(e => selectedEmails.has(e.message_id)) && !allSelected;

    const handleSelectAllChange = () => {
        onSelectAll(!allSelected);
    };

    // Render individual row
    const Row = ({ index, style }: { index: number; style: React.CSSProperties }) => {
        const email = emails[index];

        // Trigger load more when near the end
        if (index === emails.length - 10 && hasMore && onLoadMore && !isLoading) {
            onLoadMore();
        }

        return (
            <EmailRow
                email={email}
                isSelected={selectedEmails.has(email.message_id)}
                isCurrent={currentEmailId === email.message_id}
                onEmailClick={onEmailClick}
                onEmailSelect={onEmailSelect}
                onStarToggle={onStarToggle}
                onArchive={onArchive}
                onDelete={onDelete}
                onMarkRead={onMarkRead}
                style={style}
            />
        );
    };

    if (emails.length === 0 && !isLoading) {
        return (
            <div className="flex flex-col items-center justify-center h-full text-gray-500">
                <Mail className="w-16 h-16 mb-4 text-gray-300" />
                <p className="text-lg font-medium">No emails found</p>
                <p className="text-sm">Your inbox is empty or no emails match your filters</p>
            </div>
        );
    }

    return (
        <div className="flex flex-col h-full bg-white">
            {/* Header with Select All */}
            <div className="flex items-center px-4 py-2 border-b border-gray-200 bg-gray-50">
                <input
                    type="checkbox"
                    checked={allSelected}
                    ref={input => {
                        if (input) input.indeterminate = someSelected;
                    }}
                    onChange={handleSelectAllChange}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <span className="ml-3 text-sm text-gray-600">
                    {selectedEmails.size > 0 ? `${selectedEmails.size} selected` : 'Select all'}
                </span>
            </div>

            {/* Virtual Scrolling List */}
            <div className="flex-1">
                <AutoSizer>
                    {({ height, width }) => (
                        <List
                            height={height}
                            itemCount={emails.length}
                            itemSize={72} // Row height in pixels
                            width={width}
                            overscanCount={5} // Render 5 extra items above/below viewport
                        >
                            {Row}
                        </List>
                    )}
                </AutoSizer>
            </div>

            {/* Loading Indicator */}
            {isLoading && (
                <div className="flex items-center justify-center py-4 border-t border-gray-200">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                    <span className="ml-2 text-sm text-gray-600">Loading more emails...</span>
                </div>
            )}
        </div>
    );
};

export default EmailList;
