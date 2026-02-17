import React, { useState, useEffect } from 'react';
import { Menu, X } from 'lucide-react';
import Sidebar from './Sidebar';
import SearchBar from './SearchBar';
import ActionBar from './ActionBar';
import EmailList from './EmailList';
import EmailPreview from './EmailPreview';

/**
 * InboxLayout Component
 * 
 * Main 3-column responsive layout for the inbox dashboard.
 * Combines all inbox components into a cohesive interface.
 */

// ==================== Types ====================

interface Email {
    message_id: string;
    thread_id: string;
    sender: {
        name?: string;
        email: string;
    };
    recipients: {
        to: any[];
        cc: any[];
        bcc: any[];
    };
    subject: string;
    snippet: string;
    body_text?: string;
    body_html?: string;
    is_read: boolean;
    is_starred: boolean;
    has_attachment: boolean;
    attachments: any[];
    threat_score: number;
    risk_level: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
    threat_indicators: string[];
    received_at: string;
    timestamp: string;
    labels: string[];
}

interface FolderCount {
    folder: string;
    total: number;
    unread: number;
}

interface Label {
    label_id: string;
    name: string;
    color: string;
    parent_label_id?: string;
    email_count: number;
}

interface InboxLayoutProps {
    // Data
    emails: Email[];
    folderCounts: FolderCount[];
    labels: Label[];
    currentEmail: Email | null;

    // State
    currentFolder: string;
    currentLabels: string[];
    selectedEmails: Set<string>;
    isLoading?: boolean;
    hasMore?: boolean;

    // Callbacks
    onFolderChange: (folder: string) => void;
    onLabelClick: (labelId: string) => void;
    onEmailClick: (email: Email) => void;
    onEmailSelect: (messageId: string, selected: boolean) => void;
    onSelectAll: (selected: boolean) => void;
    onSearch: (query: string) => void;
    onRefresh: () => void;
    onLoadMore?: () => void;

    // Email Actions
    onMarkRead: (messageIds: string[], read: boolean) => void;
    onStarToggle: (messageIds: string[], starred: boolean) => void;
    onArchive: (messageIds: string[]) => void;
    onDelete: (messageIds: string[]) => void;
    onApplyLabel: (messageIds: string[], labelIds: string[]) => void;

    // Composer
    onCompose: () => void;
    onReply?: (email: Email) => void;
    onReplyAll?: (email: Email) => void;
    onForward?: (email: Email) => void;

    // Label Management
    onCreateLabel?: () => void;
    onEditLabel?: (labelId: string) => void;
    onDeleteLabel?: (labelId: string) => void;
}

// ==================== Main Component ====================

export const InboxLayout: React.FC<InboxLayoutProps> = ({
    emails,
    folderCounts,
    labels,
    currentEmail,
    currentFolder,
    currentLabels,
    selectedEmails,
    isLoading = false,
    hasMore = false,
    onFolderChange,
    onLabelClick,
    onEmailClick,
    onEmailSelect,
    onSelectAll,
    onSearch,
    onRefresh,
    onLoadMore,
    onMarkRead,
    onStarToggle,
    onArchive,
    onDelete,
    onApplyLabel,
    onCompose,
    onReply,
    onReplyAll,
    onForward,
    onCreateLabel,
    onEditLabel,
    onDeleteLabel,
}) => {
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const [emailPreviewOpen, setEmailPreviewOpen] = useState(false);
    const [isMobile, setIsMobile] = useState(false);

    // Detect mobile screen size
    useEffect(() => {
        const checkMobile = () => {
            setIsMobile(window.innerWidth < 1024);
        };

        checkMobile();
        window.addEventListener('resize', checkMobile);
        return () => window.removeEventListener('resize', checkMobile);
    }, []);

    // Close sidebar on mobile when folder changes
    useEffect(() => {
        if (isMobile) {
            setSidebarOpen(false);
        }
    }, [currentFolder, isMobile]);

    // Open email preview on mobile when email is clicked
    useEffect(() => {
        if (isMobile && currentEmail) {
            setEmailPreviewOpen(true);
        }
    }, [currentEmail, isMobile]);

    // Bulk Actions
    const handleBulkMarkRead = () => {
        onMarkRead(Array.from(selectedEmails), true);
    };

    const handleBulkMarkUnread = () => {
        onMarkRead(Array.from(selectedEmails), false);
    };

    const handleBulkStar = () => {
        onStarToggle(Array.from(selectedEmails), true);
    };

    const handleBulkArchive = () => {
        onArchive(Array.from(selectedEmails));
    };

    const handleBulkDelete = () => {
        onDelete(Array.from(selectedEmails));
    };

    // Single Email Actions
    const handleEmailStarToggle = (messageId: string, starred: boolean) => {
        onStarToggle([messageId], starred);
    };

    const handleEmailArchive = (messageId: string) => {
        onArchive([messageId]);
    };

    const handleEmailDelete = (messageId: string) => {
        onDelete([messageId]);
    };

    const handleEmailMarkRead = (messageId: string, read: boolean) => {
        onMarkRead([messageId], read);
    };

    return (
        <div className="flex h-screen bg-gray-100">
            {/* Mobile Menu Button */}
            {isMobile && (
                <button
                    onClick={() => setSidebarOpen(!sidebarOpen)}
                    className="fixed top-4 left-4 z-50 p-2 bg-white rounded-lg shadow-lg lg:hidden"
                >
                    {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
                </button>
            )}

            {/* Sidebar */}
            <div
                className={`
          ${isMobile ? 'fixed inset-y-0 left-0 z-40' : 'relative'}
          w-64 flex-shrink-0 transition-transform duration-300
          ${isMobile && !sidebarOpen ? '-translate-x-full' : 'translate-x-0'}
        `}
            >
                <Sidebar
                    currentFolder={currentFolder}
                    currentLabels={currentLabels}
                    folderCounts={folderCounts}
                    labels={labels}
                    onFolderClick={onFolderChange}
                    onLabelClick={onLabelClick}
                    onComposeClick={onCompose}
                    onCreateLabel={onCreateLabel}
                    onEditLabel={onEditLabel}
                    onDeleteLabel={onDeleteLabel}
                />
            </div>

            {/* Mobile Sidebar Overlay */}
            {isMobile && sidebarOpen && (
                <div
                    className="fixed inset-0 bg-black bg-opacity-50 z-30"
                    onClick={() => setSidebarOpen(false)}
                />
            )}

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col min-w-0">
                {/* Search Bar */}
                <div className="bg-white border-b border-gray-200 px-4 py-3">
                    <SearchBar
                        onSearch={onSearch}
                        onClear={() => onSearch('')}
                    />
                </div>

                {/* Action Bar */}
                <ActionBar
                    selectedCount={selectedEmails.size}
                    totalCount={emails.length}
                    hasMore={hasMore}
                    onSelectAll={() => onSelectAll(true)}
                    onDeselectAll={() => onSelectAll(false)}
                    onMarkRead={handleBulkMarkRead}
                    onMarkUnread={handleBulkMarkUnread}
                    onStar={handleBulkStar}
                    onArchive={handleBulkArchive}
                    onDelete={handleBulkDelete}
                    onRefresh={onRefresh}
                    isLoading={isLoading}
                />

                {/* Email List & Preview */}
                <div className="flex-1 flex min-h-0">
                    {/* Email List */}
                    <div
                        className={`
              ${isMobile && emailPreviewOpen ? 'hidden' : 'flex-1'}
              ${!isMobile ? 'w-1/3 min-w-[400px] max-w-[600px]' : ''}
              border-r border-gray-200
            `}
                    >
                        <EmailList
                            emails={emails}
                            selectedEmails={selectedEmails}
                            currentEmailId={currentEmail?.message_id}
                            onEmailClick={onEmailClick}
                            onEmailSelect={onEmailSelect}
                            onSelectAll={onSelectAll}
                            onStarToggle={handleEmailStarToggle}
                            onArchive={handleEmailArchive}
                            onDelete={handleEmailDelete}
                            onMarkRead={handleEmailMarkRead}
                            isLoading={isLoading}
                            hasMore={hasMore}
                            onLoadMore={onLoadMore}
                        />
                    </div>

                    {/* Email Preview */}
                    <div
                        className={`
              ${isMobile && !emailPreviewOpen ? 'hidden' : 'flex-1'}
              ${!isMobile ? 'flex-1' : 'fixed inset-0 z-40 bg-white'}
            `}
                    >
                        <EmailPreview
                            email={currentEmail}
                            onClose={isMobile ? () => setEmailPreviewOpen(false) : undefined}
                            onReply={onReply}
                            onReplyAll={onReplyAll}
                            onForward={onForward}
                            onStarToggle={handleEmailStarToggle}
                            onArchive={handleEmailArchive}
                            onDelete={handleEmailDelete}
                            onMarkRead={handleEmailMarkRead}
                        />
                    </div>
                </div>
            </div>
        </div>
    );
};

export default InboxLayout;
