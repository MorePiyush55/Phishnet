import React from 'react';
import InboxLayout from '../components/inbox/InboxLayout';
import { useInbox } from '../hooks/useInbox';

/**
 * InboxPage Component
 * 
 * Main inbox page that connects the InboxLayout with the useInbox hook.
 * This is the entry point for the inbox feature.
 */

export const InboxPage: React.FC = () => {
    const {
        // State
        emails,
        folderCounts,
        labels,
        currentEmail,
        currentFolder,
        currentLabels,
        selectedEmails,
        hasMore,
        isLoading,

        // Actions
        loadMore,
        refresh,
        markAsRead,
        toggleStar,
        archiveEmails,
        deleteEmails,
        applyLabels,

        // Label Management
        createLabel,
        updateLabel,
        deleteLabel,

        // Navigation
        changeFolder,
        toggleLabelFilter,
        search,
        selectEmailForPreview,

        // Selection
        toggleEmailSelection,
        toggleSelectAll,
    } = useInbox();

    // ==================== Handlers ====================

    const handleCompose = () => {
        // TODO: Open compose modal
        console.log('Compose clicked');
    };

    const handleReply = (email: any) => {
        // TODO: Open reply composer
        console.log('Reply to:', email);
    };

    const handleReplyAll = (email: any) => {
        // TODO: Open reply all composer
        console.log('Reply all to:', email);
    };

    const handleForward = (email: any) => {
        // TODO: Open forward composer
        console.log('Forward:', email);
    };

    const handleCreateLabel = () => {
        // TODO: Open create label modal
        const name = prompt('Enter label name:');
        if (name) {
            createLabel(name, '#' + Math.floor(Math.random() * 16777215).toString(16));
        }
    };

    const handleEditLabel = (labelId: string) => {
        // TODO: Open edit label modal
        const label = labels.find(l => l.label_id === labelId);
        if (label) {
            const newName = prompt('Enter new label name:', label.name);
            if (newName && newName !== label.name) {
                updateLabel(labelId, newName);
            }
        }
    };

    const handleDeleteLabel = (labelId: string) => {
        // TODO: Show confirmation dialog
        if (confirm('Are you sure you want to delete this label? Emails will not be deleted.')) {
            deleteLabel(labelId);
        }
    };

    const handleApplyLabel = () => {
        // TODO: Open label selector modal
        console.log('Apply label to selected emails');
    };

    // ==================== Render ====================

    return (
        <div className="h-screen">
            <InboxLayout
                // Data
                emails={emails}
                folderCounts={folderCounts}
                labels={labels}
                currentEmail={currentEmail}

                // State
                currentFolder={currentFolder}
                currentLabels={currentLabels}
                selectedEmails={selectedEmails}
                isLoading={isLoading}
                hasMore={hasMore}

                // Callbacks
                onFolderChange={changeFolder}
                onLabelClick={toggleLabelFilter}
                onEmailClick={selectEmailForPreview}
                onEmailSelect={toggleEmailSelection}
                onSelectAll={toggleSelectAll}
                onSearch={search}
                onRefresh={refresh}
                onLoadMore={loadMore}

                // Email Actions
                onMarkRead={(messageIds, read) => markAsRead(messageIds, read)}
                onStarToggle={(messageIds, starred) => toggleStar(messageIds, starred)}
                onArchive={(messageIds) => archiveEmails(messageIds)}
                onDelete={(messageIds) => deleteEmails(messageIds, false)}
                onApplyLabel={handleApplyLabel}

                // Composer
                onCompose={handleCompose}
                onReply={handleReply}
                onReplyAll={handleReplyAll}
                onForward={handleForward}

                // Label Management
                onCreateLabel={handleCreateLabel}
                onEditLabel={handleEditLabel}
                onDeleteLabel={handleDeleteLabel}
            />
        </div>
    );
};

export default InboxPage;
