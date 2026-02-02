import React from 'react';
import {
    Mail,
    MailOpen,
    Star,
    Archive,
    Trash2,
    Tag,
    MoreVertical,
    RefreshCw,
    ChevronLeft,
    ChevronRight
} from 'lucide-react';

/**
 * ActionBar Component
 * 
 * Toolbar for bulk email actions with selection controls and pagination.
 */

// ==================== Types ====================

interface ActionBarProps {
    selectedCount: number;
    totalCount: number;
    currentPage?: number;
    hasMore?: boolean;
    onSelectAll?: () => void;
    onDeselectAll?: () => void;
    onMarkRead?: () => void;
    onMarkUnread?: () => void;
    onStar?: () => void;
    onArchive?: () => void;
    onDelete?: () => void;
    onApplyLabel?: () => void;
    onRefresh?: () => void;
    onPreviousPage?: () => void;
    onNextPage?: () => void;
    isLoading?: boolean;
}

// ==================== Main Component ====================

export const ActionBar: React.FC<ActionBarProps> = ({
    selectedCount,
    totalCount,
    currentPage,
    hasMore,
    onSelectAll,
    onDeselectAll,
    onMarkRead,
    onMarkUnread,
    onStar,
    onArchive,
    onDelete,
    onApplyLabel,
    onRefresh,
    onPreviousPage,
    onNextPage,
    isLoading = false,
}) => {
    const hasSelection = selectedCount > 0;

    return (
        <div className="flex items-center justify-between px-4 py-2 bg-white border-b border-gray-200">
            {/* Left Side - Selection Controls */}
            <div className="flex items-center gap-2">
                {/* Select/Deselect All */}
                {hasSelection ? (
                    <button
                        onClick={onDeselectAll}
                        className="px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                        Deselect all
                    </button>
                ) : (
                    <button
                        onClick={onSelectAll}
                        className="px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                    >
                        Select all
                    </button>
                )}

                {/* Selection Count */}
                {hasSelection && (
                    <span className="text-sm text-gray-600 font-medium">
                        {selectedCount} selected
                    </span>
                )}

                {/* Divider */}
                {hasSelection && <div className="w-px h-6 bg-gray-300"></div>}

                {/* Bulk Actions */}
                {hasSelection && (
                    <div className="flex items-center gap-1">
                        {/* Mark Read */}
                        {onMarkRead && (
                            <button
                                onClick={onMarkRead}
                                className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                                title="Mark as read"
                            >
                                <MailOpen className="w-4 h-4" />
                            </button>
                        )}

                        {/* Mark Unread */}
                        {onMarkUnread && (
                            <button
                                onClick={onMarkUnread}
                                className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                                title="Mark as unread"
                            >
                                <Mail className="w-4 h-4" />
                            </button>
                        )}

                        {/* Star */}
                        {onStar && (
                            <button
                                onClick={onStar}
                                className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                                title="Star"
                            >
                                <Star className="w-4 h-4" />
                            </button>
                        )}

                        {/* Archive */}
                        {onArchive && (
                            <button
                                onClick={onArchive}
                                className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                                title="Archive"
                            >
                                <Archive className="w-4 h-4" />
                            </button>
                        )}

                        {/* Delete */}
                        {onDelete && (
                            <button
                                onClick={onDelete}
                                className="p-2 rounded-lg hover:bg-gray-100 text-red-600 transition-colors"
                                title="Delete"
                            >
                                <Trash2 className="w-4 h-4" />
                            </button>
                        )}

                        {/* Apply Label */}
                        {onApplyLabel && (
                            <button
                                onClick={onApplyLabel}
                                className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                                title="Apply label"
                            >
                                <Tag className="w-4 h-4" />
                            </button>
                        )}

                        {/* More Actions */}
                        <button
                            className="p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors"
                            title="More actions"
                        >
                            <MoreVertical className="w-4 h-4" />
                        </button>
                    </div>
                )}
            </div>

            {/* Right Side - Refresh & Pagination */}
            <div className="flex items-center gap-2">
                {/* Email Count */}
                {!hasSelection && totalCount > 0 && (
                    <span className="text-sm text-gray-600">
                        {totalCount.toLocaleString()} {totalCount === 1 ? 'email' : 'emails'}
                    </span>
                )}

                {/* Refresh Button */}
                {onRefresh && (
                    <button
                        onClick={onRefresh}
                        disabled={isLoading}
                        className={`p-2 rounded-lg hover:bg-gray-100 text-gray-700 transition-colors ${isLoading ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                        title="Refresh"
                    >
                        <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                    </button>
                )}

                {/* Pagination */}
                {(onPreviousPage || onNextPage) && (
                    <div className="flex items-center gap-1 ml-2">
                        <button
                            onClick={onPreviousPage}
                            disabled={!onPreviousPage || currentPage === 1}
                            className={`p-2 rounded-lg transition-colors ${onPreviousPage && currentPage !== 1
                                    ? 'hover:bg-gray-100 text-gray-700'
                                    : 'text-gray-300 cursor-not-allowed'
                                }`}
                            title="Previous page"
                        >
                            <ChevronLeft className="w-4 h-4" />
                        </button>

                        {currentPage && (
                            <span className="text-sm text-gray-600 px-2">
                                Page {currentPage}
                            </span>
                        )}

                        <button
                            onClick={onNextPage}
                            disabled={!onNextPage || !hasMore}
                            className={`p-2 rounded-lg transition-colors ${onNextPage && hasMore
                                    ? 'hover:bg-gray-100 text-gray-700'
                                    : 'text-gray-300 cursor-not-allowed'
                                }`}
                            title="Next page"
                        >
                            <ChevronRight className="w-4 h-4" />
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ActionBar;
