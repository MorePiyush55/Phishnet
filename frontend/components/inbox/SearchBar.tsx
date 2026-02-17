import React, { useState, useRef, useEffect } from 'react';
import { Search, X, Filter, Clock } from 'lucide-react';

/**
 * SearchBar Component
 * 
 * Advanced search bar with Gmail-style syntax support and recent searches.
 * Supports filters: from:, to:, subject:, has:, before:, after:, is:
 */

// ==================== Types ====================

interface SearchBarProps {
    onSearch: (query: string) => void;
    onClear?: () => void;
    placeholder?: string;
    recentSearches?: string[];
    onRemoveRecentSearch?: (query: string) => void;
}

interface SearchSuggestion {
    type: 'recent' | 'filter';
    text: string;
    description?: string;
}

// ==================== Filter Suggestions ====================

const FILTER_SUGGESTIONS: SearchSuggestion[] = [
    { type: 'filter', text: 'from:', description: 'Search by sender email' },
    { type: 'filter', text: 'to:', description: 'Search by recipient email' },
    { type: 'filter', text: 'subject:', description: 'Search in subject line' },
    { type: 'filter', text: 'has:attachment', description: 'Emails with attachments' },
    { type: 'filter', text: 'is:read', description: 'Read emails only' },
    { type: 'filter', text: 'is:unread', description: 'Unread emails only' },
    { type: 'filter', text: 'is:starred', description: 'Starred emails only' },
    { type: 'filter', text: 'before:', description: 'Emails before date (YYYY-MM-DD)' },
    { type: 'filter', text: 'after:', description: 'Emails after date (YYYY-MM-DD)' },
];

// ==================== Main Component ====================

export const SearchBar: React.FC<SearchBarProps> = ({
    onSearch,
    onClear,
    placeholder = 'Search emails (try: from:john subject:meeting)',
    recentSearches = [],
    onRemoveRecentSearch,
}) => {
    const [query, setQuery] = useState('');
    const [isFocused, setIsFocused] = useState(false);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const inputRef = useRef<HTMLInputElement>(null);
    const dropdownRef = useRef<HTMLDivElement>(null);

    // Close suggestions when clicking outside
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (
                dropdownRef.current &&
                !dropdownRef.current.contains(event.target as Node) &&
                inputRef.current &&
                !inputRef.current.contains(event.target as Node)
            ) {
                setShowSuggestions(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (query.trim()) {
            onSearch(query.trim());
            setShowSuggestions(false);
        }
    };

    const handleClear = () => {
        setQuery('');
        if (onClear) {
            onClear();
        }
        inputRef.current?.focus();
    };

    const handleSuggestionClick = (suggestion: SearchSuggestion) => {
        if (suggestion.type === 'recent') {
            setQuery(suggestion.text);
            onSearch(suggestion.text);
            setShowSuggestions(false);
        } else {
            // For filter suggestions, append to current query
            const newQuery = query.trim() ? `${query.trim()} ${suggestion.text}` : suggestion.text;
            setQuery(newQuery);
            inputRef.current?.focus();
        }
    };

    const handleRemoveRecent = (e: React.MouseEvent, searchQuery: string) => {
        e.stopPropagation();
        if (onRemoveRecentSearch) {
            onRemoveRecentSearch(searchQuery);
        }
    };

    // Filter suggestions based on current query
    const getFilteredSuggestions = (): SearchSuggestion[] => {
        const suggestions: SearchSuggestion[] = [];

        // Add recent searches
        if (recentSearches.length > 0 && !query.trim()) {
            recentSearches.slice(0, 5).forEach(search => {
                suggestions.push({ type: 'recent', text: search });
            });
        }

        // Add filter suggestions
        const lowerQuery = query.toLowerCase();
        FILTER_SUGGESTIONS.forEach(filter => {
            if (!lowerQuery || filter.text.toLowerCase().includes(lowerQuery)) {
                suggestions.push(filter);
            }
        });

        return suggestions.slice(0, 8);
    };

    const suggestions = getFilteredSuggestions();

    return (
        <div className="relative w-full">
            <form onSubmit={handleSubmit} className="relative">
                {/* Search Input */}
                <div className={`
          flex items-center gap-2 px-4 py-2 bg-gray-100 rounded-lg
          transition-all duration-200
          ${isFocused ? 'bg-white ring-2 ring-blue-500 shadow-md' : 'hover:bg-gray-200'}
        `}>
                    <Search className="w-5 h-5 text-gray-500 flex-shrink-0" />

                    <input
                        ref={inputRef}
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        onFocus={() => {
                            setIsFocused(true);
                            setShowSuggestions(true);
                        }}
                        onBlur={() => setIsFocused(false)}
                        placeholder={placeholder}
                        className="flex-1 bg-transparent border-none outline-none text-gray-900 placeholder-gray-500"
                    />

                    {query && (
                        <button
                            type="button"
                            onClick={handleClear}
                            className="p-1 rounded-full hover:bg-gray-200 text-gray-500"
                            aria-label="Clear search"
                        >
                            <X className="w-4 h-4" />
                        </button>
                    )}

                    <button
                        type="button"
                        className="p-1 rounded-full hover:bg-gray-200 text-gray-500"
                        title="Advanced filters"
                    >
                        <Filter className="w-5 h-5" />
                    </button>
                </div>

                {/* Search Suggestions Dropdown */}
                {showSuggestions && suggestions.length > 0 && (
                    <div
                        ref={dropdownRef}
                        className="absolute top-full left-0 right-0 mt-2 bg-white rounded-lg shadow-lg border border-gray-200 z-50 max-h-96 overflow-y-auto"
                    >
                        {/* Recent Searches */}
                        {suggestions.some(s => s.type === 'recent') && (
                            <div className="border-b border-gray-200">
                                <div className="px-4 py-2 text-xs font-semibold text-gray-500 uppercase">
                                    Recent Searches
                                </div>
                                {suggestions
                                    .filter(s => s.type === 'recent')
                                    .map((suggestion, idx) => (
                                        <button
                                            key={`recent-${idx}`}
                                            onClick={() => handleSuggestionClick(suggestion)}
                                            className="w-full flex items-center justify-between px-4 py-2 hover:bg-gray-50 text-left"
                                        >
                                            <div className="flex items-center gap-3">
                                                <Clock className="w-4 h-4 text-gray-400" />
                                                <span className="text-sm text-gray-900">{suggestion.text}</span>
                                            </div>
                                            {onRemoveRecentSearch && (
                                                <button
                                                    onClick={(e) => handleRemoveRecent(e, suggestion.text)}
                                                    className="p-1 rounded hover:bg-gray-200 text-gray-400"
                                                    aria-label="Remove"
                                                >
                                                    <X className="w-3 h-3" />
                                                </button>
                                            )}
                                        </button>
                                    ))}
                            </div>
                        )}

                        {/* Filter Suggestions */}
                        {suggestions.some(s => s.type === 'filter') && (
                            <div>
                                <div className="px-4 py-2 text-xs font-semibold text-gray-500 uppercase">
                                    Search Filters
                                </div>
                                {suggestions
                                    .filter(s => s.type === 'filter')
                                    .map((suggestion, idx) => (
                                        <button
                                            key={`filter-${idx}`}
                                            onClick={() => handleSuggestionClick(suggestion)}
                                            className="w-full flex items-start gap-3 px-4 py-2 hover:bg-gray-50 text-left"
                                        >
                                            <code className="px-2 py-1 bg-gray-100 rounded text-xs font-mono text-blue-600">
                                                {suggestion.text}
                                            </code>
                                            {suggestion.description && (
                                                <span className="text-xs text-gray-600">{suggestion.description}</span>
                                            )}
                                        </button>
                                    ))}
                            </div>
                        )}
                    </div>
                )}
            </form>

            {/* Search Tips */}
            {isFocused && !query && (
                <div className="mt-2 px-4 py-2 bg-blue-50 border border-blue-200 rounded-lg text-xs text-blue-800">
                    <strong>Search tips:</strong> Use filters like <code className="px-1 bg-blue-100 rounded">from:john@example.com</code> or <code className="px-1 bg-blue-100 rounded">has:attachment</code>
                </div>
            )}
        </div>
    );
};

export default SearchBar;
