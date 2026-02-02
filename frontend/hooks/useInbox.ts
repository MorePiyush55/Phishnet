import { useCallback, useEffect } from 'react';
import { useInboxStore } from '../stores/inboxStore';
import { inboxAPI } from '../lib/inboxAPI';

/**
 * useInbox Hook
 * 
 * Custom hook that integrates the inbox store with the API client.
 * Provides high-level functions for inbox operations.
 */

export const useInbox = () => {
    const {
        emails,
        folderCounts,
        labels,
        currentEmail,
        currentFolder,
        currentLabels,
        searchQuery,
        selectedEmails,
        cursor,
        hasMore,
        isLoading,
        error,
        setEmails,
        addEmails,
        updateEmail,
        removeEmails,
        setFolderCounts,
        updateFolderCount,
        setLabels,
        addLabel,
        updateLabel,
        removeLabel,
        setCurrentEmail,
        setCurrentFolder,
        toggleLabel,
        setSearchQuery,
        selectEmail,
        deselectEmail,
        selectAll,
        deselectAll,
        setCursor,
        setHasMore,
        setLoading,
        setError,
    } = useInboxStore();

    // ==================== Load Initial Data ====================

    /**
     * Load emails based on current filters
     */
    const loadEmails = useCallback(async (resetCursor: boolean = true) => {
        try {
            setLoading(true);
            setError(null);

            let response;

            if (searchQuery) {
                // Search mode
                response = await inboxAPI.searchEmails({
                    q: searchQuery,
                    limit: 50,
                });
            } else {
                // Normal listing mode
                response = await inboxAPI.listEmails({
                    folder: currentFolder || undefined,
                    labels: currentLabels.length > 0 ? currentLabels : undefined,
                    limit: 50,
                    cursor: resetCursor ? undefined : cursor || undefined,
                });
            }

            if (resetCursor) {
                setEmails(response.emails);
            } else {
                addEmails(response.emails);
            }

            setCursor(response.next_cursor);
            setHasMore(response.has_more);
        } catch (err: any) {
            setError(err.message || 'Failed to load emails');
            console.error('Error loading emails:', err);
        } finally {
            setLoading(false);
        }
    }, [currentFolder, currentLabels, searchQuery, cursor]);

    /**
     * Load more emails (pagination)
     */
    const loadMore = useCallback(async () => {
        if (!hasMore || isLoading) return;
        await loadEmails(false);
    }, [hasMore, isLoading, loadEmails]);

    /**
     * Refresh emails
     */
    const refresh = useCallback(async () => {
        await loadEmails(true);
    }, [loadEmails]);

    /**
     * Load folder counts
     */
    const loadFolderCounts = useCallback(async () => {
        try {
            const counts = await inboxAPI.getFolders();
            setFolderCounts(counts);
        } catch (err: any) {
            console.error('Error loading folder counts:', err);
        }
    }, [setFolderCounts]);

    /**
     * Load labels
     */
    const loadLabels = useCallback(async () => {
        try {
            const labelsList = await inboxAPI.getLabels();
            setLabels(labelsList);
        } catch (err: any) {
            console.error('Error loading labels:', err);
        }
    }, [setLabels]);

    // ==================== Email Actions ====================

    /**
     * Mark emails as read/unread
     */
    const markAsRead = useCallback(async (messageIds: string[], isRead: boolean) => {
        try {
            if (messageIds.length === 1) {
                await inboxAPI.updateReadStatus(messageIds[0], isRead);
            } else {
                await inboxAPI.bulkMarkRead(messageIds, isRead);
            }

            // Update local state
            messageIds.forEach((id) => {
                updateEmail(id, { is_read: isRead });
            });

            // Update folder counts
            await loadFolderCounts();
        } catch (err: any) {
            setError(err.message || 'Failed to update read status');
            console.error('Error updating read status:', err);
        }
    }, [updateEmail, loadFolderCounts, setError]);

    /**
     * Star/unstar emails
     */
    const toggleStar = useCallback(async (messageIds: string[], isStarred: boolean) => {
        try {
            if (messageIds.length === 1) {
                await inboxAPI.updateStarStatus(messageIds[0], isStarred);
            } else {
                await inboxAPI.bulkStar(messageIds, isStarred);
            }

            // Update local state
            messageIds.forEach((id) => {
                updateEmail(id, { is_starred: isStarred });
            });
        } catch (err: any) {
            setError(err.message || 'Failed to update star status');
            console.error('Error updating star status:', err);
        }
    }, [updateEmail, setError]);

    /**
     * Archive emails
     */
    const archiveEmails = useCallback(async (messageIds: string[]) => {
        try {
            if (messageIds.length === 1) {
                await inboxAPI.moveToFolder(messageIds[0], 'all_mail');
            } else {
                await inboxAPI.bulkMove(messageIds, 'all_mail');
            }

            // Remove from current view if in inbox
            if (currentFolder === 'inbox') {
                removeEmails(messageIds);
            } else {
                messageIds.forEach((id) => {
                    updateEmail(id, { folder: 'all_mail' });
                });
            }

            // Update folder counts
            await loadFolderCounts();

            // Deselect archived emails
            deselectAll();
        } catch (err: any) {
            setError(err.message || 'Failed to archive emails');
            console.error('Error archiving emails:', err);
        }
    }, [currentFolder, removeEmails, updateEmail, loadFolderCounts, deselectAll, setError]);

    /**
     * Delete emails
     */
    const deleteEmails = useCallback(async (messageIds: string[], permanent: boolean = false) => {
        try {
            if (messageIds.length === 1) {
                await inboxAPI.deleteEmail(messageIds[0], permanent);
            } else {
                await inboxAPI.bulkDelete(messageIds, permanent);
            }

            // Remove from view
            removeEmails(messageIds);

            // Update folder counts
            await loadFolderCounts();

            // Deselect deleted emails
            deselectAll();
        } catch (err: any) {
            setError(err.message || 'Failed to delete emails');
            console.error('Error deleting emails:', err);
        }
    }, [removeEmails, loadFolderCounts, deselectAll, setError]);

    /**
     * Apply labels to emails
     */
    const applyLabels = useCallback(async (messageIds: string[], labelIds: string[]) => {
        try {
            if (messageIds.length === 1) {
                await inboxAPI.applyLabels(messageIds[0], labelIds);
            } else {
                await inboxAPI.bulkApplyLabels(messageIds, labelIds);
            }

            // Update local state
            messageIds.forEach((id) => {
                const email = emails.find((e) => e.message_id === id);
                if (email) {
                    const newLabels = Array.from(new Set([...email.labels, ...labelIds]));
                    updateEmail(id, { labels: newLabels });
                }
            });

            // Reload labels to update counts
            await loadLabels();
        } catch (err: any) {
            setError(err.message || 'Failed to apply labels');
            console.error('Error applying labels:', err);
        }
    }, [emails, updateEmail, loadLabels, setError]);

    // ==================== Label Management ====================

    /**
     * Create new label
     */
    const createLabel = useCallback(async (name: string, color: string = '#808080', parentLabelId?: string) => {
        try {
            const newLabel = await inboxAPI.createLabel({
                name,
                color,
                parent_label_id: parentLabelId,
            });

            addLabel(newLabel);
            return newLabel;
        } catch (err: any) {
            setError(err.message || 'Failed to create label');
            console.error('Error creating label:', err);
            throw err;
        }
    }, [addLabel, setError]);

    /**
     * Update label
     */
    const updateLabelData = useCallback(async (labelId: string, name?: string, color?: string) => {
        try {
            const updatedLabel = await inboxAPI.updateLabel(labelId, { name, color });
            updateLabel(labelId, updatedLabel);
            return updatedLabel;
        } catch (err: any) {
            setError(err.message || 'Failed to update label');
            console.error('Error updating label:', err);
            throw err;
        }
    }, [updateLabel, setError]);

    /**
     * Delete label
     */
    const deleteLabel = useCallback(async (labelId: string) => {
        try {
            await inboxAPI.deleteLabel(labelId);
            removeLabel(labelId);
        } catch (err: any) {
            setError(err.message || 'Failed to delete label');
            console.error('Error deleting label:', err);
            throw err;
        }
    }, [removeLabel, setError]);

    // ==================== Navigation ====================

    /**
     * Change folder
     */
    const changeFolder = useCallback((folder: string) => {
        setCurrentFolder(folder);
    }, [setCurrentFolder]);

    /**
     * Toggle label filter
     */
    const toggleLabelFilter = useCallback((labelId: string) => {
        toggleLabel(labelId);
    }, [toggleLabel]);

    /**
     * Search emails
     */
    const search = useCallback((query: string) => {
        setSearchQuery(query);
    }, [setSearchQuery]);

    /**
     * Select email for preview
     */
    const selectEmailForPreview = useCallback(async (email: any) => {
        setCurrentEmail(email);

        // Auto-mark as read after delay
        if (!email.is_read) {
            setTimeout(async () => {
                await markAsRead([email.message_id], true);
            }, 2000);
        }
    }, [setCurrentEmail, markAsRead]);

    // ==================== Selection ====================

    /**
     * Toggle email selection
     */
    const toggleEmailSelection = useCallback((messageId: string, selected: boolean) => {
        if (selected) {
            selectEmail(messageId);
        } else {
            deselectEmail(messageId);
        }
    }, [selectEmail, deselectEmail]);

    /**
     * Toggle select all
     */
    const toggleSelectAll = useCallback((selected: boolean) => {
        if (selected) {
            selectAll();
        } else {
            deselectAll();
        }
    }, [selectAll, deselectAll]);

    // ==================== Effects ====================

    // Load emails when filters change
    useEffect(() => {
        loadEmails(true);
    }, [currentFolder, currentLabels, searchQuery]);

    // Load initial data
    useEffect(() => {
        loadFolderCounts();
        loadLabels();
    }, []);

    // ==================== Return ====================

    return {
        // State
        emails,
        folderCounts,
        labels,
        currentEmail,
        currentFolder,
        currentLabels,
        searchQuery,
        selectedEmails,
        hasMore,
        isLoading,
        error,

        // Email Actions
        loadEmails,
        loadMore,
        refresh,
        markAsRead,
        toggleStar,
        archiveEmails,
        deleteEmails,
        applyLabels,

        // Label Management
        createLabel,
        updateLabel: updateLabelData,
        deleteLabel,

        // Navigation
        changeFolder,
        toggleLabelFilter,
        search,
        selectEmailForPreview,

        // Selection
        toggleEmailSelection,
        toggleSelectAll,
    };
};

export default useInbox;
