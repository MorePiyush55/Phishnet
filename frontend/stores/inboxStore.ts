import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

/**
 * Inbox Store
 * 
 * Zustand store for managing inbox state including emails, folders, labels,
 * selection, and UI state.
 */

// ==================== Types ====================

interface EmailParticipant {
    name?: string;
    email: string;
}

interface EmailRecipients {
    to: EmailParticipant[];
    cc: EmailParticipant[];
    bcc: EmailParticipant[];
}

interface EmailAttachment {
    attachment_id: string;
    filename: string;
    size_bytes: number;
    mime_type: string;
    download_url?: string;
}

export interface Email {
    message_id: string;
    thread_id: string;
    sender: EmailParticipant;
    recipients: EmailRecipients;
    subject: string;
    snippet: string;
    body_text?: string;
    body_html?: string;
    is_read: boolean;
    is_starred: boolean;
    has_attachment: boolean;
    attachments: EmailAttachment[];
    threat_score: number;
    risk_level: 'SAFE' | 'SUSPICIOUS' | 'PHISHING';
    threat_indicators: string[];
    received_at: string;
    timestamp: string;
    labels: string[];
    folder: string;
}

export interface FolderCount {
    folder: string;
    total: number;
    unread: number;
}

export interface Label {
    label_id: string;
    name: string;
    color: string;
    parent_label_id?: string;
    email_count: number;
}

interface InboxState {
    // Data
    emails: Email[];
    folderCounts: FolderCount[];
    labels: Label[];
    currentEmail: Email | null;

    // Filters & Navigation
    currentFolder: string;
    currentLabels: string[];
    searchQuery: string;

    // Selection
    selectedEmails: Set<string>;

    // Pagination
    cursor: string | null;
    hasMore: boolean;

    // UI State
    isLoading: boolean;
    error: string | null;

    // Actions
    setEmails: (emails: Email[]) => void;
    addEmails: (emails: Email[]) => void;
    updateEmail: (messageId: string, updates: Partial<Email>) => void;
    removeEmails: (messageIds: string[]) => void;

    setFolderCounts: (counts: FolderCount[]) => void;
    updateFolderCount: (folder: string, updates: Partial<FolderCount>) => void;

    setLabels: (labels: Label[]) => void;
    addLabel: (label: Label) => void;
    updateLabel: (labelId: string, updates: Partial<Label>) => void;
    removeLabel: (labelId: string) => void;

    setCurrentEmail: (email: Email | null) => void;
    setCurrentFolder: (folder: string) => void;
    toggleLabel: (labelId: string) => void;
    setSearchQuery: (query: string) => void;

    selectEmail: (messageId: string) => void;
    deselectEmail: (messageId: string) => void;
    selectAll: () => void;
    deselectAll: () => void;

    setCursor: (cursor: string | null) => void;
    setHasMore: (hasMore: boolean) => void;

    setLoading: (isLoading: boolean) => void;
    setError: (error: string | null) => void;

    reset: () => void;
}

// ==================== Initial State ====================

const initialState = {
    emails: [],
    folderCounts: [],
    labels: [],
    currentEmail: null,
    currentFolder: 'inbox',
    currentLabels: [],
    searchQuery: '',
    selectedEmails: new Set<string>(),
    cursor: null,
    hasMore: false,
    isLoading: false,
    error: null,
};

// ==================== Store ====================

export const useInboxStore = create<InboxState>()(
    devtools(
        (set, get) => ({
            ...initialState,

            // Email Actions
            setEmails: (emails) =>
                set({ emails, selectedEmails: new Set() }, false, 'setEmails'),

            addEmails: (newEmails) =>
                set((state) => ({
                    emails: [...state.emails, ...newEmails],
                }), false, 'addEmails'),

            updateEmail: (messageId, updates) =>
                set((state) => ({
                    emails: state.emails.map((email) =>
                        email.message_id === messageId ? { ...email, ...updates } : email
                    ),
                    currentEmail:
                        state.currentEmail?.message_id === messageId
                            ? { ...state.currentEmail, ...updates }
                            : state.currentEmail,
                }), false, 'updateEmail'),

            removeEmails: (messageIds) =>
                set((state) => {
                    const messageIdSet = new Set(messageIds);
                    return {
                        emails: state.emails.filter((email) => !messageIdSet.has(email.message_id)),
                        selectedEmails: new Set(
                            Array.from(state.selectedEmails).filter((id) => !messageIdSet.has(id))
                        ),
                        currentEmail:
                            state.currentEmail && messageIdSet.has(state.currentEmail.message_id)
                                ? null
                                : state.currentEmail,
                    };
                }, false, 'removeEmails'),

            // Folder Count Actions
            setFolderCounts: (counts) =>
                set({ folderCounts: counts }, false, 'setFolderCounts'),

            updateFolderCount: (folder, updates) =>
                set((state) => ({
                    folderCounts: state.folderCounts.map((count) =>
                        count.folder === folder ? { ...count, ...updates } : count
                    ),
                }), false, 'updateFolderCount'),

            // Label Actions
            setLabels: (labels) =>
                set({ labels }, false, 'setLabels'),

            addLabel: (label) =>
                set((state) => ({
                    labels: [...state.labels, label],
                }), false, 'addLabel'),

            updateLabel: (labelId, updates) =>
                set((state) => ({
                    labels: state.labels.map((label) =>
                        label.label_id === labelId ? { ...label, ...updates } : label
                    ),
                }), false, 'updateLabel'),

            removeLabel: (labelId) =>
                set((state) => ({
                    labels: state.labels.filter((label) => label.label_id !== labelId),
                    currentLabels: state.currentLabels.filter((id) => id !== labelId),
                }), false, 'removeLabel'),

            // Navigation Actions
            setCurrentEmail: (email) =>
                set({ currentEmail: email }, false, 'setCurrentEmail'),

            setCurrentFolder: (folder) =>
                set({
                    currentFolder: folder,
                    currentLabels: [],
                    searchQuery: '',
                    cursor: null,
                    selectedEmails: new Set(),
                }, false, 'setCurrentFolder'),

            toggleLabel: (labelId) =>
                set((state) => {
                    const currentLabels = state.currentLabels.includes(labelId)
                        ? state.currentLabels.filter((id) => id !== labelId)
                        : [...state.currentLabels, labelId];

                    return {
                        currentLabels,
                        currentFolder: '',
                        searchQuery: '',
                        cursor: null,
                        selectedEmails: new Set(),
                    };
                }, false, 'toggleLabel'),

            setSearchQuery: (query) =>
                set({
                    searchQuery: query,
                    currentFolder: '',
                    currentLabels: [],
                    cursor: null,
                    selectedEmails: new Set(),
                }, false, 'setSearchQuery'),

            // Selection Actions
            selectEmail: (messageId) =>
                set((state) => ({
                    selectedEmails: new Set([...state.selectedEmails, messageId]),
                }), false, 'selectEmail'),

            deselectEmail: (messageId) =>
                set((state) => {
                    const newSelected = new Set(state.selectedEmails);
                    newSelected.delete(messageId);
                    return { selectedEmails: newSelected };
                }, false, 'deselectEmail'),

            selectAll: () =>
                set((state) => ({
                    selectedEmails: new Set(state.emails.map((e) => e.message_id)),
                }), false, 'selectAll'),

            deselectAll: () =>
                set({ selectedEmails: new Set() }, false, 'deselectAll'),

            // Pagination Actions
            setCursor: (cursor) =>
                set({ cursor }, false, 'setCursor'),

            setHasMore: (hasMore) =>
                set({ hasMore }, false, 'setHasMore'),

            // UI State Actions
            setLoading: (isLoading) =>
                set({ isLoading }, false, 'setLoading'),

            setError: (error) =>
                set({ error }, false, 'setError'),

            // Reset
            reset: () =>
                set(initialState, false, 'reset'),
        }),
        { name: 'InboxStore' }
    )
);

// ==================== Selectors ====================

// Get selected emails as array
export const useSelectedEmailsArray = () => {
    const selectedEmails = useInboxStore((state) => state.selectedEmails);
    const emails = useInboxStore((state) => state.emails);

    return emails.filter((email) => selectedEmails.has(email.message_id));
};

// Get current folder count
export const useCurrentFolderCount = () => {
    const currentFolder = useInboxStore((state) => state.currentFolder);
    const folderCounts = useInboxStore((state) => state.folderCounts);

    return folderCounts.find((count) => count.folder === currentFolder);
};

// Get unread count for a folder
export const useUnreadCount = (folder: string) => {
    const folderCounts = useInboxStore((state) => state.folderCounts);
    return folderCounts.find((count) => count.folder === folder)?.unread || 0;
};

// Get label by ID
export const useLabel = (labelId: string) => {
    const labels = useInboxStore((state) => state.labels);
    return labels.find((label) => label.label_id === labelId);
};

export default useInboxStore;
