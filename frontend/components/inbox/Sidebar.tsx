import React, { useState } from 'react';
import {
    Inbox,
    Star,
    Send,
    FileText,
    Archive,
    Trash2,
    AlertTriangle,
    Mail,
    Plus,
    ChevronDown,
    ChevronRight,
    Tag,
    Edit3
} from 'lucide-react';

/**
 * Sidebar Component
 * 
 * Gmail-style navigation sidebar with folders, labels, and counts.
 * Supports collapsible sections and label management.
 */

// ==================== Types ====================

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

interface SidebarProps {
    currentFolder: string;
    currentLabels: string[];
    folderCounts: FolderCount[];
    labels: Label[];
    onFolderClick: (folder: string) => void;
    onLabelClick: (labelId: string) => void;
    onComposeClick: () => void;
    onCreateLabel?: () => void;
    onEditLabel?: (labelId: string) => void;
    onDeleteLabel?: (labelId: string) => void;
}

// ==================== Folder Configuration ====================

const SYSTEM_FOLDERS = [
    { id: 'inbox', name: 'Inbox', icon: Inbox, color: 'text-blue-600' },
    { id: 'starred', name: 'Starred', icon: Star, color: 'text-yellow-500' },
    { id: 'sent', name: 'Sent', icon: Send, color: 'text-green-600' },
    { id: 'drafts', name: 'Drafts', icon: FileText, color: 'text-gray-600' },
    { id: 'all_mail', name: 'All Mail', icon: Mail, color: 'text-gray-600' },
    { id: 'spam', name: 'Spam', icon: AlertTriangle, color: 'text-orange-600' },
    { id: 'trash', name: 'Trash', icon: Trash2, color: 'text-red-600' },
];

// ==================== Helper Functions ====================

const getFolderCount = (folderId: string, folderCounts: FolderCount[]): FolderCount => {
    return folderCounts.find(f => f.folder === folderId) || { folder: folderId, total: 0, unread: 0 };
};

const formatCount = (count: number): string => {
    if (count >= 1000) return `${(count / 1000).toFixed(1)}k`;
    return count.toString();
};

// ==================== Folder Item Component ====================

interface FolderItemProps {
    folder: {
        id: string;
        name: string;
        icon: React.ComponentType<any>;
        color: string;
    };
    count: FolderCount;
    isActive: boolean;
    onClick: () => void;
}

const FolderItem: React.FC<FolderItemProps> = ({ folder, count, isActive, onClick }) => {
    const Icon = folder.icon;

    return (
        <button
            onClick={onClick}
            className={`
        w-full flex items-center justify-between px-3 py-2 rounded-lg
        transition-colors duration-150
        ${isActive
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-100'
                }
      `}
        >
            <div className="flex items-center gap-3 min-w-0">
                <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-blue-600' : folder.color}`} />
                <span className="truncate">{folder.name}</span>
            </div>

            {count.unread > 0 && (
                <span className={`
          ml-2 px-2 py-0.5 text-xs font-semibold rounded-full flex-shrink-0
          ${isActive
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-200 text-gray-700'
                    }
        `}>
                    {formatCount(count.unread)}
                </span>
            )}
        </button>
    );
};

// ==================== Label Item Component ====================

interface LabelItemProps {
    label: Label;
    isActive: boolean;
    onClick: () => void;
    onEdit?: () => void;
    onDelete?: () => void;
}

const LabelItem: React.FC<LabelItemProps> = ({ label, isActive, onClick, onEdit, onDelete }) => {
    const [isHovered, setIsHovered] = useState(false);

    return (
        <button
            onClick={onClick}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
            className={`
        w-full flex items-center justify-between px-3 py-2 rounded-lg
        transition-colors duration-150
        ${isActive
                    ? 'bg-blue-50 text-blue-700 font-medium'
                    : 'text-gray-700 hover:bg-gray-100'
                }
      `}
        >
            <div className="flex items-center gap-3 min-w-0">
                <Tag
                    className="w-4 h-4 flex-shrink-0"
                    style={{ color: label.color }}
                    fill={label.color}
                />
                <span className="truncate text-sm">{label.name}</span>
            </div>

            <div className="flex items-center gap-1">
                {label.email_count > 0 && (
                    <span className="text-xs text-gray-500 mr-1">
                        {formatCount(label.email_count)}
                    </span>
                )}

                {isHovered && onEdit && (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            onEdit();
                        }}
                        className="p-1 rounded hover:bg-gray-200"
                        title="Edit label"
                    >
                        <Edit3 className="w-3 h-3" />
                    </button>
                )}
            </div>
        </button>
    );
};

// ==================== Main Sidebar Component ====================

export const Sidebar: React.FC<SidebarProps> = ({
    currentFolder,
    currentLabels,
    folderCounts,
    labels,
    onFolderClick,
    onLabelClick,
    onComposeClick,
    onCreateLabel,
    onEditLabel,
    onDeleteLabel,
}) => {
    const [labelsExpanded, setLabelsExpanded] = useState(true);
    const [moreExpanded, setMoreExpanded] = useState(false);

    // Separate primary and secondary folders
    const primaryFolders = SYSTEM_FOLDERS.slice(0, 4); // Inbox, Starred, Sent, Drafts
    const secondaryFolders = SYSTEM_FOLDERS.slice(4); // All Mail, Spam, Trash

    // Organize labels by parent
    const topLevelLabels = labels.filter(l => !l.parent_label_id);
    const childLabels = labels.filter(l => l.parent_label_id);

    return (
        <div className="flex flex-col h-full bg-white border-r border-gray-200">
            {/* Compose Button */}
            <div className="p-4">
                <button
                    onClick={onComposeClick}
                    className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm"
                >
                    <Edit3 className="w-5 h-5" />
                    <span className="font-medium">Compose</span>
                </button>
            </div>

            {/* Navigation */}
            <nav className="flex-1 overflow-y-auto px-2">
                {/* Primary Folders */}
                <div className="space-y-1 mb-4">
                    {primaryFolders.map((folder) => (
                        <FolderItem
                            key={folder.id}
                            folder={folder}
                            count={getFolderCount(folder.id, folderCounts)}
                            isActive={currentFolder === folder.id}
                            onClick={() => onFolderClick(folder.id)}
                        />
                    ))}
                </div>

                {/* Labels Section */}
                <div className="mb-4">
                    <button
                        onClick={() => setLabelsExpanded(!labelsExpanded)}
                        className="w-full flex items-center justify-between px-3 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100 rounded-lg"
                    >
                        <span>Labels</span>
                        {labelsExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                        ) : (
                            <ChevronRight className="w-4 h-4" />
                        )}
                    </button>

                    {labelsExpanded && (
                        <div className="mt-1 space-y-1">
                            {topLevelLabels.map((label) => (
                                <div key={label.label_id}>
                                    <LabelItem
                                        label={label}
                                        isActive={currentLabels.includes(label.label_id)}
                                        onClick={() => onLabelClick(label.label_id)}
                                        onEdit={onEditLabel ? () => onEditLabel(label.label_id) : undefined}
                                        onDelete={onDeleteLabel ? () => onDeleteLabel(label.label_id) : undefined}
                                    />

                                    {/* Child Labels */}
                                    {childLabels
                                        .filter(cl => cl.parent_label_id === label.label_id)
                                        .map(childLabel => (
                                            <div key={childLabel.label_id} className="ml-6">
                                                <LabelItem
                                                    label={childLabel}
                                                    isActive={currentLabels.includes(childLabel.label_id)}
                                                    onClick={() => onLabelClick(childLabel.label_id)}
                                                    onEdit={onEditLabel ? () => onEditLabel(childLabel.label_id) : undefined}
                                                    onDelete={onDeleteLabel ? () => onDeleteLabel(childLabel.label_id) : undefined}
                                                />
                                            </div>
                                        ))}
                                </div>
                            ))}

                            {/* Create New Label */}
                            {onCreateLabel && (
                                <button
                                    onClick={onCreateLabel}
                                    className="w-full flex items-center gap-3 px-3 py-2 text-sm text-gray-600 hover:bg-gray-100 rounded-lg"
                                >
                                    <Plus className="w-4 h-4" />
                                    <span>Create new label</span>
                                </button>
                            )}
                        </div>
                    )}
                </div>

                {/* More Section */}
                <div>
                    <button
                        onClick={() => setMoreExpanded(!moreExpanded)}
                        className="w-full flex items-center justify-between px-3 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100 rounded-lg"
                    >
                        <span>More</span>
                        {moreExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                        ) : (
                            <ChevronRight className="w-4 h-4" />
                        )}
                    </button>

                    {moreExpanded && (
                        <div className="mt-1 space-y-1">
                            {secondaryFolders.map((folder) => (
                                <FolderItem
                                    key={folder.id}
                                    folder={folder}
                                    count={getFolderCount(folder.id, folderCounts)}
                                    isActive={currentFolder === folder.id}
                                    onClick={() => onFolderClick(folder.id)}
                                />
                            ))}
                        </div>
                    )}
                </div>
            </nav>

            {/* Storage Info (Optional) */}
            <div className="p-4 border-t border-gray-200">
                <div className="text-xs text-gray-600">
                    <div className="flex items-center justify-between mb-1">
                        <span>Storage</span>
                        <span>2.5 GB of 15 GB used</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-1.5">
                        <div className="bg-blue-600 h-1.5 rounded-full" style={{ width: '17%' }}></div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Sidebar;
