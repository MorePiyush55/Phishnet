import React, { useMemo, useCallback } from 'react';
import { 
  ChevronLeft, 
  ChevronRight, 
  ChevronsLeft, 
  ChevronsRight,
  MoreHorizontal 
} from 'lucide-react';

export interface PaginationProps {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  itemsPerPage: number;
  onPageChange: (page: number) => void;
  onItemsPerPageChange?: (itemsPerPage: number) => void;
  showSizeSelector?: boolean;
  showInfo?: boolean;
  className?: string;
  maxVisiblePages?: number;
  sizeSelectorOptions?: number[];
}

export interface PaginationInfo {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  itemsPerPage: number;
  startItem: number;
  endItem: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
}

export const usePagination = (
  totalItems: number,
  itemsPerPage: number,
  currentPage: number
): PaginationInfo => {
  return useMemo(() => {
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    const startItem = (currentPage - 1) * itemsPerPage + 1;
    const endItem = Math.min(currentPage * itemsPerPage, totalItems);
    
    return {
      currentPage,
      totalPages,
      totalItems,
      itemsPerPage,
      startItem,
      endItem,
      hasNextPage: currentPage < totalPages,
      hasPreviousPage: currentPage > 1,
    };
  }, [totalItems, itemsPerPage, currentPage]);
};

export const Pagination: React.FC<PaginationProps> = ({
  currentPage,
  totalPages,
  totalItems,
  itemsPerPage,
  onPageChange,
  onItemsPerPageChange,
  showSizeSelector = true,
  showInfo = true,
  className = '',
  maxVisiblePages = 7,
  sizeSelectorOptions = [10, 25, 50, 100],
}) => {
  const paginationInfo = usePagination(totalItems, itemsPerPage, currentPage);

  const visiblePages = useMemo(() => {
    const pages: (number | 'ellipsis')[] = [];
    
    if (totalPages <= maxVisiblePages) {
      // Show all pages
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      // Calculate which pages to show
      const halfVisible = Math.floor(maxVisiblePages / 2);
      let startPage = Math.max(1, currentPage - halfVisible);
      let endPage = Math.min(totalPages, currentPage + halfVisible);
      
      // Adjust if we're near the beginning or end
      if (currentPage <= halfVisible) {
        endPage = Math.min(totalPages, maxVisiblePages);
      }
      if (currentPage > totalPages - halfVisible) {
        startPage = Math.max(1, totalPages - maxVisiblePages + 1);
      }
      
      // Always show first page
      if (startPage > 1) {
        pages.push(1);
        if (startPage > 2) {
          pages.push('ellipsis');
        }
      }
      
      // Show visible pages
      for (let i = startPage; i <= endPage; i++) {
        pages.push(i);
      }
      
      // Always show last page
      if (endPage < totalPages) {
        if (endPage < totalPages - 1) {
          pages.push('ellipsis');
        }
        pages.push(totalPages);
      }
    }
    
    return pages;
  }, [currentPage, totalPages, maxVisiblePages]);

  const handlePageChange = useCallback((page: number) => {
    if (page >= 1 && page <= totalPages && page !== currentPage) {
      onPageChange(page);
    }
  }, [currentPage, totalPages, onPageChange]);

  const handleItemsPerPageChange = useCallback((newItemsPerPage: number) => {
    if (onItemsPerPageChange && newItemsPerPage !== itemsPerPage) {
      // Calculate what the current page should be with the new items per page
      const currentFirstItem = (currentPage - 1) * itemsPerPage + 1;
      const newPage = Math.ceil(currentFirstItem / newItemsPerPage);
      onItemsPerPageChange(newItemsPerPage);
      if (newPage !== currentPage) {
        onPageChange(newPage);
      }
    }
  }, [currentPage, itemsPerPage, onPageChange, onItemsPerPageChange]);

  if (totalPages <= 1 && !showSizeSelector && !showInfo) {
    return null;
  }

  return (
    <div className={`flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0 ${className}`}>
      {/* Info section */}
      {showInfo && (
        <div className="flex items-center text-sm text-gray-400">
          <span>
            Showing {paginationInfo.startItem.toLocaleString()} to {paginationInfo.endItem.toLocaleString()} of{' '}
            {paginationInfo.totalItems.toLocaleString()} results
          </span>
        </div>
      )}

      <div className="flex items-center space-x-4">
        {/* Size selector */}
        {showSizeSelector && onItemsPerPageChange && (
          <div className="flex items-center space-x-2">
            <span className="text-sm text-gray-400">Show:</span>
            <select
              value={itemsPerPage}
              onChange={(e) => handleItemsPerPageChange(Number(e.target.value))}
              className="bg-gray-800 border border-gray-600 text-white text-sm rounded px-2 py-1 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {sizeSelectorOptions.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
            <span className="text-sm text-gray-400">per page</span>
          </div>
        )}

        {/* Pagination controls */}
        {totalPages > 1 && (
          <div className="flex items-center space-x-1">
            {/* First page */}
            <button
              onClick={() => handlePageChange(1)}
              disabled={!paginationInfo.hasPreviousPage}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 disabled:text-gray-600 disabled:cursor-not-allowed rounded transition-colors"
              title="First page"
            >
              <ChevronsLeft className="h-4 w-4" />
            </button>

            {/* Previous page */}
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={!paginationInfo.hasPreviousPage}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 disabled:text-gray-600 disabled:cursor-not-allowed rounded transition-colors"
              title="Previous page"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>

            {/* Page numbers */}
            <div className="flex items-center space-x-1">
              {visiblePages.map((page, index) => (
                <React.Fragment key={index}>
                  {page === 'ellipsis' ? (
                    <span className="px-3 py-2 text-gray-400">
                      <MoreHorizontal className="h-4 w-4" />
                    </span>
                  ) : (
                    <button
                      onClick={() => handlePageChange(page)}
                      className={`
                        px-3 py-2 text-sm rounded transition-colors
                        ${page === currentPage
                          ? 'bg-blue-600 text-white'
                          : 'text-gray-400 hover:text-white hover:bg-gray-700'
                        }
                      `}
                    >
                      {page}
                    </button>
                  )}
                </React.Fragment>
              ))}
            </div>

            {/* Next page */}
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={!paginationInfo.hasNextPage}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 disabled:text-gray-600 disabled:cursor-not-allowed rounded transition-colors"
              title="Next page"
            >
              <ChevronRight className="h-4 w-4" />
            </button>

            {/* Last page */}
            <button
              onClick={() => handlePageChange(totalPages)}
              disabled={!paginationInfo.hasNextPage}
              className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 disabled:text-gray-600 disabled:cursor-not-allowed rounded transition-colors"
              title="Last page"
            >
              <ChevronsRight className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

// Hook for managing pagination state
export const usePaginationState = (
  initialPage: number = 1,
  initialItemsPerPage: number = 25
) => {
  const [currentPage, setCurrentPage] = React.useState(initialPage);
  const [itemsPerPage, setItemsPerPage] = React.useState(initialItemsPerPage);

  const resetToFirstPage = useCallback(() => {
    setCurrentPage(1);
  }, []);

  const goToPage = useCallback((page: number) => {
    setCurrentPage(page);
  }, []);

  const changeItemsPerPage = useCallback((newItemsPerPage: number) => {
    setItemsPerPage(newItemsPerPage);
    // Optionally reset to first page when changing items per page
    setCurrentPage(1);
  }, []);

  return {
    currentPage,
    itemsPerPage,
    setCurrentPage,
    setItemsPerPage,
    resetToFirstPage,
    goToPage,
    changeItemsPerPage,
  };
};

// Component for simple pagination info
export const PaginationInfo: React.FC<{
  info: PaginationInfo;
  className?: string;
}> = ({ info, className = '' }) => (
  <div className={`text-sm text-gray-400 ${className}`}>
    Showing {info.startItem.toLocaleString()}-{info.endItem.toLocaleString()} of{' '}
    {info.totalItems.toLocaleString()}
  </div>
);

// Utility function to calculate pagination offset
export const getPaginationOffset = (page: number, itemsPerPage: number): number => {
  return (page - 1) * itemsPerPage;
};

// Utility function to get pagination parameters for API calls
export const getPaginationParams = (page: number, itemsPerPage: number) => ({
  offset: getPaginationOffset(page, itemsPerPage),
  limit: itemsPerPage,
  page,
});

export default Pagination;
