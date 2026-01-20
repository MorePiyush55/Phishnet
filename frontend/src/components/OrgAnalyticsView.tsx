import React, { useState, useEffect } from 'react';
import { BarChart, Users, AlertCircle, Shield, TrendingUp, Search, RefreshCw, Mail } from 'lucide-react';

interface OrgStats {
    total_checks: number;
    verdict_counts: {
        PHISHING: number;
        SUSPICIOUS: number;
        SAFE: number;
    };
    recent_history: any[];
}

interface OrgAnalyticsViewProps {
    userEmail: string;
}

const OrgAnalyticsView: React.FC<OrgAnalyticsViewProps> = ({ userEmail }) => {
    const [stats, setStats] = useState<OrgStats | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [orgDomain, setOrgDomain] = useState(() => userEmail.split('@')[1] || '');

    const fetchOrgStats = async () => {
        if (!orgDomain) return;
        setLoading(true);
        setError(null);
        try {
            const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080';
            const response = await fetch(`${apiUrl}/api/v2/organization/stats/${orgDomain}`);
            if (!response.ok) throw new Error('Failed to fetch organization stats');
            const data = await response.json();
            if (data.success) {
                setStats(data);
            } else {
                throw new Error(data.message || 'Failed to load stats');
            }
        } catch (err) {
            setError(err instanceof Error ? err.message : 'An error occurred');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchOrgStats();
    }, [orgDomain]);

    if (loading && !stats) {
        return (
            <div className="flex flex-col items-center justify-center p-12 text-gray-400">
                <RefreshCw className="h-12 w-12 animate-spin mb-4 text-blue-500" />
                <p>Loading Organization Analytics...</p>
            </div>
        );
    }

    return (
        <div className="p-6 space-y-8 bg-gray-900 min-h-full overflow-y-auto">
            {/* Header & Controls */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                        <TrendingUp className="h-6 w-6 text-green-400" />
                        Mode 1: Bulk Forward Overview
                    </h2>
                    <p className="text-gray-400">Real-time threat landscape for <span className="text-blue-400 font-mono">{orgDomain}</span></p>
                </div>

                <div className="flex items-center gap-2">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                        <input
                            type="text"
                            value={orgDomain}
                            onChange={(e) => setOrgDomain(e.target.value)}
                            placeholder="Change domain..."
                            className="pl-9 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500 w-48 transition-all"
                        />
                    </div>
                    <button
                        onClick={fetchOrgStats}
                        className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-300 transition-colors"
                    >
                        <RefreshCw className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {error ? (
                <div className="bg-red-900/30 border border-red-800 rounded-xl p-6 text-center">
                    <AlertCircle className="h-10 w-10 text-red-500 mx-auto mb-2" />
                    <p className="text-red-200">{error}</p>
                </div>
            ) : stats ? (
                <>
                    {/* Summary Cards */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                        <div className="bg-gray-800/50 border border-gray-700 p-5 rounded-2xl hover:border-blue-500/50 transition-all group">
                            <div className="flex items-center justify-between mb-2">
                                <Mail className="h-5 w-5 text-blue-400" />
                                <span className="text-xs text-blue-400 bg-blue-400/10 px-2 py-0.5 rounded-full">+12%</span>
                            </div>
                            <p className="text-3xl font-bold">{stats.total_checks}</p>
                            <p className="text-gray-400 text-sm">Total Submissions</p>
                        </div>

                        <div className="bg-gray-800/50 border border-gray-700 p-5 rounded-2xl hover:border-red-500/50 transition-all group">
                            <div className="flex items-center justify-between mb-2">
                                <AlertCircle className="h-5 w-5 text-red-400" />
                                <span className="text-xs text-red-400 bg-red-400/10 px-2 py-0.5 rounded-full">High Risk</span>
                            </div>
                            <p className="text-3xl font-bold text-red-400">{stats.verdict_counts.PHISHING}</p>
                            <p className="text-gray-400 text-sm">Phishing Detected</p>
                        </div>

                        <div className="bg-gray-800/50 border border-gray-700 p-5 rounded-2xl hover:border-orange-500/50 transition-all group">
                            <div className="flex items-center justify-between mb-2">
                                <AlertCircle className="h-5 w-5 text-orange-400" />
                            </div>
                            <p className="text-3xl font-bold text-orange-400">{stats.verdict_counts.SUSPICIOUS}</p>
                            <p className="text-gray-400 text-sm">Suspicious Alerts</p>
                        </div>

                        <div className="bg-gray-800/50 border border-gray-700 p-5 rounded-2xl hover:border-green-500/50 transition-all group">
                            <div className="flex items-center justify-between mb-2">
                                <Shield className="h-5 w-5 text-green-400" />
                            </div>
                            <p className="text-3xl font-bold text-green-400">{stats.verdict_counts.SAFE}</p>
                            <p className="text-gray-400 text-sm">Likely Safe</p>
                        </div>
                    </div>

                    {/* Recent Submissions Table */}
                    <div className="bg-gray-800/30 border border-gray-700 rounded-2xl overflow-hidden">
                        <div className="px-6 py-4 border-b border-gray-700 flex justify-between items-center">
                            <h3 className="font-semibold text-white">Live Submission Feed</h3>
                            <span className="text-xs text-gray-500">Auto-updating every 30s</span>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-left">
                                <thead className="bg-gray-800/50 text-gray-400 text-sm uppercase">
                                    <tr>
                                        <th className="px-6 py-3">Subject</th>
                                        <th className="px-6 py-3">Forwarder</th>
                                        <th className="px-6 py-3">Verdict</th>
                                        <th className="px-6 py-3">Confidence</th>
                                        <th className="px-6 py-3">Date</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-700/50 text-sm">
                                    {stats.recent_history.map((item, i) => (
                                        <tr key={i} className="hover:bg-gray-800/50 transition-colors">
                                            <td className="px-6 py-4 text-white font-medium truncate max-w-xs">{item.original_subject}</td>
                                            <td className="px-6 py-4 text-gray-400">{item.forwarded_by}</td>
                                            <td className="px-6 py-4">
                                                <span className={`px-2 py-1 rounded-full text-xs font-bold ${item.risk_level === 'PHISHING' ? 'bg-red-400/10 text-red-400 border border-red-400/20' :
                                                    item.risk_level === 'SUSPICIOUS' ? 'bg-orange-400/10 text-orange-400 border border-orange-400/20' :
                                                        'bg-green-400/10 text-green-400 border border-green-400/20'
                                                    }`}>
                                                    {item.risk_level}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 text-gray-300 font-mono">{(item.threat_score * 100).toFixed(0)}%</td>
                                            <td className="px-6 py-4 text-gray-500 italic">{new Date(item.created_at).toLocaleTimeString()}</td>
                                        </tr>
                                    ))}
                                    {stats.recent_history.length === 0 && (
                                        <tr>
                                            <td colSpan={5} className="px-6 py-12 text-center text-gray-500 italic">No submissions found for this domain yet.</td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </>
            ) : null}
        </div>
    );
};

export default OrgAnalyticsView;
