import React, { useEffect, useState } from 'react';import React, { useEffect, useState } from 'react';import React, { useEffect, useState } from 'react';

import { Shield, Mail, AlertTriangle, CheckCircle, Activity, TrendingUp, LogOut } from 'lucide-react';

import { Shield, Mail, AlertTriangle, CheckCircle, Activity, TrendingUp, LogOut } from 'lucide-react';import { Shield, Mail, AlertTriangle, CheckCircle, Users, Activity, TrendingUp, LogOut } from 'lucide-react';

interface DashboardStats {

  totalEmails: number;

  phishingDetected: number;

  safeEmails: number;interface DashboardStats {interface DashboardStats {

  protectionRate: number;

}  totalEmails: number;  totalEmails: number;



const OAuthDashboard: React.FC = () => {  phishingDetected: number;  phishingDetected: number;

  const [stats, setStats] = useState<DashboardStats>({

    totalEmails: 0,  safeEmails: number;  safeEmails: number;

    phishingDetected: 0,

    safeEmails: 0,  protectionRate: number;  protectionRate: number;

    protectionRate: 0

  });}}

  const [userEmail, setUserEmail] = useState<string>('');

  const [isLoading, setIsLoading] = useState(true);

  const [recentActivity, setRecentActivity] = useState<any[]>([]);

const OAuthDashboard: React.FC = () => {const OAuthDashboard: React.FC = () => {

  useEffect(() => {

    // Check for auth token  const [stats, setStats] = useState<DashboardStats>({  const [stats, setStats] = useState<DashboardStats>({

    const token = localStorage.getItem('auth_token') || new URLSearchParams(window.location.search).get('token');

    if (!token) {    totalEmails: 0,    totalEmails: 0,

      window.location.href = '/login';

      return;    phishingDetected: 0,    phishingDetected: 0,

    }

    safeEmails: 0,    safeEmails: 0,

    if (token && !localStorage.getItem('auth_token')) {

      localStorage.setItem('auth_token', token);    protectionRate: 0    protectionRate: 0

      // Clean URL

      window.history.replaceState({}, document.title, window.location.pathname);  });  });

    }

  const [userEmail, setUserEmail] = useState<string>('');  const [userEmail, setUserEmail] = useState<string>('');

    // Simulate loading user data

    setTimeout(() => {  const [isLoading, setIsLoading] = useState(true);  const [isLoading, setIsLoading] = useState(true);

      setStats({

        totalEmails: 1247,  const [recentActivity, setRecentActivity] = useState<any[]>([]);  const [recentActivity, setRecentActivity] = useState<any[]>([]);

        phishingDetected: 23,

        safeEmails: 1224,

        protectionRate: 98.2

      });  useEffect(() => {  useEffect(() => {

      setUserEmail('user@gmail.com');

      setRecentActivity([    // Check for auth token    // Check for auth token

        { type: 'phishing', subject: 'Urgent: Verify your account', time: '2 mins ago', status: 'blocked' },

        { type: 'safe', subject: 'Weekly Newsletter', time: '15 mins ago', status: 'delivered' },    const token = localStorage.getItem('auth_token') || new URLSearchParams(window.location.search).get('token');    const token = localStorage.getItem('auth_token') || new URLSearchParams(window.location.search).get('token');

        { type: 'phishing', subject: 'PayPal Security Alert', time: '1 hour ago', status: 'quarantined' },

        { type: 'safe', subject: 'Meeting Invitation', time: '2 hours ago', status: 'delivered' }    if (!token) {    if (!token) {

      ]);

      setIsLoading(false);      window.location.href = '/login';      window.location.href = '/login';

    }, 1500);

  }, []);      return;      return;



  const handleLogout = () => {    }    }

    localStorage.removeItem('auth_token');

    window.location.href = '/login';

  };

    if (token && !localStorage.getItem('auth_token')) {    if (token && !localStorage.getItem('auth_token')) {

  if (isLoading) {

    return (      localStorage.setItem('auth_token', token);      localStorage.setItem('auth_token', token);

      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center">

        <div className="text-center">      // Clean URL      // Clean URL

          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mx-auto mb-4"></div>

          <p className="text-blue-200">Loading your protection dashboard...</p>      window.history.replaceState({}, document.title, window.location.pathname);      window.history.replaceState({}, document.title, window.location.pathname);

        </div>

      </div>    }    }

    );

  }



  return (    // Simulate loading user data    // Simulate loading user data

    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">

      <header className="bg-white/10 backdrop-blur-md border-b border-white/20">    setTimeout(() => {    setTimeout(() => {

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">

          <div className="flex justify-between items-center py-4">      setStats({      setStats({

            <div className="flex items-center space-x-3">

              <div className="h-10 w-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">        totalEmails: 1247,        totalEmails: 1247,

                <Shield className="h-6 w-6 text-white" />

              </div>        phishingDetected: 23,        phishingDetected: 23,

              <div>

                <h1 className="text-xl font-bold text-white">PhishNet</h1>        safeEmails: 1224,        safeEmails: 1224,

                <p className="text-sm text-blue-300">Email Protection Dashboard</p>

              </div>        protectionRate: 98.2        protectionRate: 98.2

            </div>

            <div className="flex items-center space-x-4">      });      });

              <div className="text-right">

                <p className="text-sm font-medium text-white">{userEmail}</p>      setUserEmail('user@gmail.com');      setUserEmail('user@gmail.com');

                <p className="text-xs text-blue-300">Protected Account</p>

              </div>      setRecentActivity([      setRecentActivity([

              <button

                onClick={handleLogout}        { type: 'phishing', subject: 'Urgent: Verify your account', time: '2 mins ago', status: 'blocked' },        { type: 'phishing', subject: 'Urgent: Verify your account', time: '2 mins ago', status: 'blocked' },

                className="flex items-center space-x-2 px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 rounded-lg transition-colors"

              >        { type: 'safe', subject: 'Weekly Newsletter', time: '15 mins ago', status: 'delivered' },        { type: 'safe', subject: 'Weekly Newsletter', time: '15 mins ago', status: 'delivered' },

                <LogOut className="h-4 w-4" />

                <span>Logout</span>        { type: 'phishing', subject: 'PayPal Security Alert', time: '1 hour ago', status: 'quarantined' },        { type: 'phishing', subject: 'PayPal Security Alert', time: '1 hour ago', status: 'quarantined' },

              </button>

            </div>        { type: 'safe', subject: 'Meeting Invitation', time: '2 hours ago', status: 'delivered' }        { type: 'safe', subject: 'Meeting Invitation', time: '2 hours ago', status: 'delivered' }

          </div>

        </div>      ]);      ]);

      </header>

      setIsLoading(false);      setIsLoading(false);

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

        <div className="bg-gradient-to-r from-green-600/20 to-blue-600/20 backdrop-blur-md rounded-xl p-6 border border-green-500/30 mb-8">    }, 1500);    }, 1500);

          <div className="flex items-center space-x-3 mb-4">

            <CheckCircle className="h-8 w-8 text-green-400" />  }, []);  }, []);

            <div>

              <h2 className="text-xl font-bold text-white">Gmail Successfully Connected!</h2>

              <p className="text-green-300">Your email is now protected by AI-powered phishing detection</p>

            </div>  const handleLogout = () => {  const handleLogout = () => {

          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">    localStorage.removeItem('auth_token');    localStorage.removeItem('auth_token');

            <div className="flex items-center space-x-2 text-green-300">

              <CheckCircle className="h-4 w-4" />    window.location.href = '/login';    window.location.href = '/login';

              <span>Real-time email scanning</span>

            </div>  };  };

            <div className="flex items-center space-x-2 text-green-300">

              <CheckCircle className="h-4 w-4" />

              <span>Advanced threat detection</span>

            </div>  if (isLoading) {  if (isLoading) {

            <div className="flex items-center space-x-2 text-green-300">

              <CheckCircle className="h-4 w-4" />    return (    return (

              <span>Automatic quarantine</span>

            </div>      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center">      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex items-center justify-center">

          </div>

        </div>        <div className="text-center">        <div className="text-center">



        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mx-auto mb-4"></div>          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-400 mx-auto mb-4"></div>

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">          <p className="text-blue-200">Loading your protection dashboard...</p>          <p className="text-blue-200">Loading your protection dashboard...</p>

              <div>

                <p className="text-blue-300 text-sm font-medium">Total Emails</p>        </div>        </div>

                <p className="text-3xl font-bold text-white">{stats.totalEmails.toLocaleString()}</p>

                <p className="text-xs text-blue-400 mt-1">Last 30 days</p>      </div>      </div>

              </div>

              <Mail className="h-8 w-8 text-blue-400" />    );    );

            </div>

          </div>  }  }



          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">

              <div>  return (  return (

                <p className="text-red-300 text-sm font-medium">Threats Blocked</p>

                <p className="text-3xl font-bold text-white">{stats.phishingDetected}</p>    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">

                <p className="text-xs text-red-400 mt-1">Prevented attacks</p>

              </div>      {/* Header */}      {/* Header */}

              <AlertTriangle className="h-8 w-8 text-red-400" />

            </div>      <header className="bg-white/10 backdrop-blur-md border-b border-white/20">      <header className="bg-white/10 backdrop-blur-md border-b border-white/20">

          </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">          <div className="flex justify-between items-center py-4">          <div className="flex justify-between items-center py-4">

              <div>

                <p className="text-green-300 text-sm font-medium">Safe Emails</p>            <div className="flex items-center space-x-3">            <div className="flex items-center space-x-3">

                <p className="text-3xl font-bold text-white">{stats.safeEmails.toLocaleString()}</p>

                <p className="text-xs text-green-400 mt-1">Verified legitimate</p>              <div className="h-10 w-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">              <div className="h-10 w-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg flex items-center justify-center">

              </div>

              <CheckCircle className="h-8 w-8 text-green-400" />                <Shield className="h-6 w-6 text-white" />                <Shield className="h-6 w-6 text-white" />

            </div>

          </div>              </div>              </div>



          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">              <div>              <div>

            <div className="flex items-center justify-between">

              <div>                <h1 className="text-xl font-bold text-white">PhishNet</h1>                <h1 className="text-xl font-bold text-white">PhishNet</h1>

                <p className="text-cyan-300 text-sm font-medium">Protection Rate</p>

                <p className="text-3xl font-bold text-white">{stats.protectionRate}%</p>                <p className="text-sm text-blue-300">Email Protection Dashboard</p>                <p className="text-sm text-blue-300">Email Protection Dashboard</p>

                <p className="text-xs text-cyan-400 mt-1">Detection accuracy</p>

              </div>              </div>              </div>

              <TrendingUp className="h-8 w-8 text-cyan-400" />

            </div>            </div>            </div>

          </div>

        </div>            <div className="flex items-center space-x-4">            <div className="flex items-center space-x-4">



        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">              <div className="text-right">              <div className="text-right">

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between mb-6">                <p className="text-sm font-medium text-white">{userEmail}</p>                <p className="text-sm font-medium text-white">{userEmail}</p>

              <h2 className="text-xl font-bold text-white">Recent Activity</h2>

              <Activity className="h-5 w-5 text-blue-400" />                <p className="text-xs text-blue-300">Protected Account</p>                <p className="text-xs text-blue-300">Protected Account</p>

            </div>

            <div className="space-y-4">              </div>              </div>

              {recentActivity.map((activity, index) => (

                <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg hover:bg-white/10 transition-colors">              <button              <button

                  <div className="flex items-center space-x-3">

                    {activity.type === 'phishing' ? (                onClick={handleLogout}                onClick={handleLogout}

                      <div className="p-2 bg-red-500/20 rounded-lg">

                        <AlertTriangle className="h-4 w-4 text-red-400" />                className="flex items-center space-x-2 px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 rounded-lg transition-colors"                className="flex items-center space-x-2 px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-300 rounded-lg transition-colors"

                      </div>

                    ) : (              >              >

                      <div className="p-2 bg-green-500/20 rounded-lg">

                        <CheckCircle className="h-4 w-4 text-green-400" />                <LogOut className="h-4 w-4" />                <LogOut className="h-4 w-4" />

                      </div>

                    )}                <span>Logout</span>                <span>Logout</span>

                    <div>

                      <p className="text-white font-medium text-sm">{activity.subject}</p>              </button>              </button>

                      <p className="text-blue-300 text-xs">{activity.time}</p>

                    </div>            </div>            </div>

                  </div>

                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${          </div>          </div>

                    activity.status === 'blocked' || activity.status === 'quarantined'

                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'        </div>        </div>

                      : 'bg-green-500/20 text-green-300 border border-green-500/30'

                  }`}>      </header>      </header>

                    {activity.status}

                  </span>

                </div>

              ))}      {/* Main Content */}      {/* Main Content */}

            </div>

            <div className="mt-4 text-center">      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

              <button className="text-blue-400 hover:text-blue-300 text-sm font-medium">

                View all activity →        {/* Welcome Message */}        {/* Welcome Message */}

              </button>

            </div>        <div className="bg-gradient-to-r from-green-600/20 to-blue-600/20 backdrop-blur-md rounded-xl p-6 border border-green-500/30 mb-8">        <div className="bg-gradient-to-r from-green-600/20 to-blue-600/20 backdrop-blur-md rounded-xl p-6 border border-green-500/30 mb-8">

          </div>

          <div className="flex items-center space-x-3 mb-4">          <div className="flex items-center space-x-3 mb-4">

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between mb-6">            <CheckCircle className="h-8 w-8 text-green-400" />            <CheckCircle className="h-8 w-8 text-green-400" />

              <h2 className="text-xl font-bold text-white">Protection Status</h2>

              <Shield className="h-5 w-5 text-green-400" />            <div>            <div>

            </div>

            <div className="space-y-4">              <h2 className="text-xl font-bold text-white">Gmail Successfully Connected!</h2>              <h2 className="text-xl font-bold text-white">Gmail Successfully Connected!</h2>

              <div className="flex items-center justify-between p-4 bg-green-500/20 rounded-lg border border-green-500/30">

                <div className="flex items-center space-x-3">              <p className="text-green-300">Your email is now protected by AI-powered phishing detection</p>              <p className="text-green-300">Your email is now protected by AI-powered phishing detection</p>

                  <CheckCircle className="h-6 w-6 text-green-400" />

                  <div>            </div>            </div>

                    <p className="text-green-300 font-medium">Gmail Connected</p>

                    <p className="text-green-400 text-sm">Real-time monitoring active</p>          </div>          </div>

                  </div>

                </div>          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">

                <div className="h-3 w-3 bg-green-400 rounded-full animate-pulse"></div>

              </div>            <div className="flex items-center space-x-2 text-green-300">            <div className="flex items-center space-x-2 text-green-300">

              

              <div className="flex items-center justify-between p-4 bg-blue-500/20 rounded-lg border border-blue-500/30">              <CheckCircle className="h-4 w-4" />              <CheckCircle className="h-4 w-4" />

                <div className="flex items-center space-x-3">

                  <Activity className="h-6 w-6 text-blue-400" />              <span>Real-time email scanning</span>              <span>Real-time email scanning</span>

                  <div>

                    <p className="text-blue-300 font-medium">AI Detection</p>            </div>            </div>

                    <p className="text-blue-400 text-sm">Advanced threat analysis enabled</p>

                  </div>            <div className="flex items-center space-x-2 text-green-300">            <div className="flex items-center space-x-2 text-green-300">

                </div>

                <div className="h-3 w-3 bg-blue-400 rounded-full animate-pulse"></div>              <CheckCircle className="h-4 w-4" />              <CheckCircle className="h-4 w-4" />

              </div>

                            <span>Advanced threat detection</span>              <span>Advanced threat detection</span>

              <div className="flex items-center justify-between p-4 bg-cyan-500/20 rounded-lg border border-cyan-500/30">

                <div className="flex items-center space-x-3">            </div>            </div>

                  <TrendingUp className="h-6 w-6 text-cyan-400" />

                  <div>            <div className="flex items-center space-x-2 text-green-300">            <div className="flex items-center space-x-2 text-green-300">

                    <p className="text-cyan-300 font-medium">Auto-Learning</p>

                    <p className="text-cyan-400 text-sm">Continuously improving detection</p>              <CheckCircle className="h-4 w-4" />              <CheckCircle className="h-4 w-4" />

                  </div>

                </div>              <span>Automatic quarantine</span>              <span>Automatic quarantine</span>

                <div className="h-3 w-3 bg-cyan-400 rounded-full animate-pulse"></div>

              </div>            </div>            </div>

            </div>

                      </div>          </div>

            <div className="mt-6 p-4 bg-white/5 rounded-lg">

              <h4 className="text-white font-medium mb-2">Next Steps</h4>        </div>        </div>

              <ul className="text-sm text-blue-300 space-y-1">

                <li>• Configure custom threat rules</li>

                <li>• Set up email notifications</li>

                <li>• Enable team collaboration</li>        {/* Stats Grid */}        {/* Stats Grid */}

              </ul>

            </div>        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">

          </div>

        </div>          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

      </main>

    </div>            <div className="flex items-center justify-between">            <div className="flex items-center justify-between">

  );

};              <div>              <div>



export default OAuthDashboard;                <p className="text-blue-300 text-sm font-medium">Total Emails</p>                <p className="text-blue-300 text-sm font-medium">Total Emails</p>

                <p className="text-3xl font-bold text-white">{stats.totalEmails.toLocaleString()}</p>                <p className="text-3xl font-bold text-white">{stats.totalEmails.toLocaleString()}</p>

                <p className="text-xs text-blue-400 mt-1">Last 30 days</p>                <p className="text-xs text-blue-400 mt-1">Last 30 days</p>

              </div>              </div>

              <Mail className="h-8 w-8 text-blue-400" />              <Mail className="h-8 w-8 text-blue-400" />

            </div>            </div>

          </div>          </div>



          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">            <div className="flex items-center justify-between">

              <div>              <div>

                <p className="text-red-300 text-sm font-medium">Threats Blocked</p>                <p className="text-red-300 text-sm font-medium">Threats Blocked</p>

                <p className="text-3xl font-bold text-white">{stats.phishingDetected}</p>                <p className="text-3xl font-bold text-white">{stats.phishingDetected}</p>

                <p className="text-xs text-red-400 mt-1">Prevented attacks</p>                <p className="text-xs text-red-400 mt-1">Prevented attacks</p>

              </div>              </div>

              <AlertTriangle className="h-8 w-8 text-red-400" />              <AlertTriangle className="h-8 w-8 text-red-400" />

            </div>            </div>

          </div>          </div>



          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">            <div className="flex items-center justify-between">

              <div>              <div>

                <p className="text-green-300 text-sm font-medium">Safe Emails</p>                <p className="text-green-300 text-sm font-medium">Safe Emails</p>

                <p className="text-3xl font-bold text-white">{stats.safeEmails.toLocaleString()}</p>                <p className="text-3xl font-bold text-white">{stats.safeEmails.toLocaleString()}</p>

                <p className="text-xs text-green-400 mt-1">Verified legitimate</p>                <p className="text-xs text-green-400 mt-1">Verified legitimate</p>

              </div>              </div>

              <CheckCircle className="h-8 w-8 text-green-400" />              <CheckCircle className="h-8 w-8 text-green-400" />

            </div>            </div>

          </div>          </div>



          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between">            <div className="flex items-center justify-between">

              <div>              <div>

                <p className="text-cyan-300 text-sm font-medium">Protection Rate</p>                <p className="text-cyan-300 text-sm font-medium">Protection Rate</p>

                <p className="text-3xl font-bold text-white">{stats.protectionRate}%</p>                <p className="text-3xl font-bold text-white">{stats.protectionRate}%</p>

                <p className="text-xs text-cyan-400 mt-1">Detection accuracy</p>                <p className="text-xs text-cyan-400 mt-1">Detection accuracy</p>

              </div>              </div>

              <TrendingUp className="h-8 w-8 text-cyan-400" />              <TrendingUp className="h-8 w-8 text-cyan-400" />

            </div>            </div>

          </div>          </div>

        </div>        </div>



        {/* Recent Activity & Protection Status */}        {/* Recent Activity & Protection Status */}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between mb-6">            <div className="flex items-center justify-between mb-6">

              <h2 className="text-xl font-bold text-white">Recent Activity</h2>              <h2 className="text-xl font-bold text-white">Recent Activity</h2>

              <Activity className="h-5 w-5 text-blue-400" />              <Activity className="h-5 w-5 text-blue-400" />

            </div>            </div>

            <div className="space-y-4">            <div className="space-y-4">

              {recentActivity.map((activity, index) => (              {recentActivity.map((activity, index) => (

                <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg hover:bg-white/10 transition-colors">                <div key={index} className="flex items-center justify-between p-4 bg-white/5 rounded-lg hover:bg-white/10 transition-colors">

                  <div className="flex items-center space-x-3">                  <div className="flex items-center space-x-3">

                    {activity.type === 'phishing' ? (                    {activity.type === 'phishing' ? (

                      <div className="p-2 bg-red-500/20 rounded-lg">                      <div className="p-2 bg-red-500/20 rounded-lg">

                        <AlertTriangle className="h-4 w-4 text-red-400" />                        <AlertTriangle className="h-4 w-4 text-red-400" />

                      </div>                      </div>

                    ) : (                    ) : (

                      <div className="p-2 bg-green-500/20 rounded-lg">                      <div className="p-2 bg-green-500/20 rounded-lg">

                        <CheckCircle className="h-4 w-4 text-green-400" />                        <CheckCircle className="h-4 w-4 text-green-400" />

                      </div>                      </div>

                    )}                    )}

                    <div>                    <div>

                      <p className="text-white font-medium text-sm">{activity.subject}</p>                      <p className="text-white font-medium text-sm">{activity.subject}</p>

                      <p className="text-blue-300 text-xs">{activity.time}</p>                      <p className="text-blue-300 text-xs">{activity.time}</p>

                    </div>                    </div>

                  </div>                  </div>

                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${

                    activity.status === 'blocked' || activity.status === 'quarantined'                    activity.status === 'blocked' || activity.status === 'quarantined'

                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'

                      : 'bg-green-500/20 text-green-300 border border-green-500/30'                      : 'bg-green-500/20 text-green-300 border border-green-500/30'

                  }`}>                  }`}>

                    {activity.status}                    {activity.status}

                  </span>                  </span>

                </div>                </div>

              ))}              ))}

            </div>            </div>

            <div className="mt-4 text-center">            <div className="mt-4 text-center">

              <button className="text-blue-400 hover:text-blue-300 text-sm font-medium">              <button className="text-blue-400 hover:text-blue-300 text-sm font-medium">

                View all activity →                View all activity →

              </button>              </button>

            </div>            </div>

          </div>          </div>



          {/* Protection Status */}          {/* Protection Status */}

          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">          <div className="bg-white/10 backdrop-blur-md rounded-xl p-6 border border-white/20">

            <div className="flex items-center justify-between mb-6">            <div className="flex items-center justify-between mb-6">

              <h2 className="text-xl font-bold text-white">Protection Status</h2>              <h2 className="text-xl font-bold text-white">Protection Status</h2>

              <Shield className="h-5 w-5 text-green-400" />              <Shield className="h-5 w-5 text-green-400" />

            </div>            </div>

            <div className="space-y-4">            <div className="space-y-4">

              <div className="flex items-center justify-between p-4 bg-green-500/20 rounded-lg border border-green-500/30">              <div className="flex items-center justify-between p-4 bg-green-500/20 rounded-lg border border-green-500/30">

                <div className="flex items-center space-x-3">                <div className="flex items-center space-x-3">

                  <CheckCircle className="h-6 w-6 text-green-400" />                  <CheckCircle className="h-6 w-6 text-green-400" />

                  <div>                  <div>

                    <p className="text-green-300 font-medium">Gmail Connected</p>                    <p className="text-green-300 font-medium">Gmail Connected</p>

                    <p className="text-green-400 text-sm">Real-time monitoring active</p>                    <p className="text-green-400 text-sm">Real-time monitoring active</p>

                  </div>                  </div>

                </div>                </div>

                <div className="h-3 w-3 bg-green-400 rounded-full animate-pulse"></div>                <div className="h-3 w-3 bg-green-400 rounded-full animate-pulse"></div>

              </div>              </div>

                            

              <div className="flex items-center justify-between p-4 bg-blue-500/20 rounded-lg border border-blue-500/30">              <div className="flex items-center justify-between p-4 bg-blue-500/20 rounded-lg border border-blue-500/30">

                <div className="flex items-center space-x-3">                <div className="flex items-center space-x-3">

                  <Activity className="h-6 w-6 text-blue-400" />                  <Activity className="h-6 w-6 text-blue-400" />

                  <div>                  <div>

                    <p className="text-blue-300 font-medium">AI Detection</p>                    <p className="text-blue-300 font-medium">AI Detection</p>

                    <p className="text-blue-400 text-sm">Advanced threat analysis enabled</p>                    <p className="text-blue-400 text-sm">Advanced threat analysis enabled</p>

                  </div>                  </div>

                </div>                </div>

                <div className="h-3 w-3 bg-blue-400 rounded-full animate-pulse"></div>                <div className="h-3 w-3 bg-blue-400 rounded-full animate-pulse"></div>

              </div>              </div>

                            

              <div className="flex items-center justify-between p-4 bg-cyan-500/20 rounded-lg border border-cyan-500/30">              <div className="flex items-center justify-between p-4 bg-cyan-500/20 rounded-lg border border-cyan-500/30">

                <div className="flex items-center space-x-3">                <div className="flex items-center space-x-3">

                  <TrendingUp className="h-6 w-6 text-cyan-400" />                  <TrendingUp className="h-6 w-6 text-cyan-400" />

                  <div>                  <div>

                    <p className="text-cyan-300 font-medium">Auto-Learning</p>                    <p className="text-cyan-300 font-medium">Auto-Learning</p>

                    <p className="text-cyan-400 text-sm">Continuously improving detection</p>                    <p className="text-cyan-400 text-sm">Continuously improving detection</p>

                  </div>                  </div>

                </div>                </div>

                <div className="h-3 w-3 bg-cyan-400 rounded-full animate-pulse"></div>                <div className="h-3 w-3 bg-cyan-400 rounded-full animate-pulse"></div>

              </div>              </div>

            </div>            </div>

                        

            <div className="mt-6 p-4 bg-white/5 rounded-lg">            <div className="mt-6 p-4 bg-white/5 rounded-lg">

              <h4 className="text-white font-medium mb-2">Next Steps</h4>              <h4 className="text-white font-medium mb-2">Next Steps</h4>

              <ul className="text-sm text-blue-300 space-y-1">              <ul className="text-sm text-blue-300 space-y-1">

                <li>• Configure custom threat rules</li>                <li>• Configure custom threat rules</li>

                <li>• Set up email notifications</li>                <li>• Set up email notifications</li>

                <li>• Enable team collaboration</li>                <li>• Enable team collaboration</li>

              </ul>              </ul>

            </div>            </div>

          </div>          </div>

        </div>        </div>

      </main>      </main>

    </div>    </div>

  );  );

};};



export default OAuthDashboard;export default OAuthDashboard;
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-gray-600">Connected as {userStatus?.email}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Display */}
        <ErrorDisplay className="mb-6" showDetails={process.env.NODE_ENV === 'development'} />

        {/* Main Content */}
        {!isConnected && !isLoading ? (
          /* Not connected - show connect UI */
          <div className="max-w-2xl mx-auto">
            <GmailConnect 
              onConnectionChange={(connected) => {
                if (connected) {
                  window.location.reload(); // Refresh to update status
                }
              }}
            />
          </div>
        ) : (
          /* Connected - show full dashboard */
          <div className="space-y-6">
            {/* Tab Navigation */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200">
              <div className="border-b border-gray-200">
                <nav className="flex space-x-8 px-6" aria-label="Tabs">
                  {tabs.map((tab) => {
                    const Icon = tab.icon;
                    return (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id as any)}
                        className={`py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 ${
                          activeTab === tab.id
                            ? 'border-blue-500 text-blue-600'
                            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                        }`}
                      >
                        <Icon className="h-4 w-4" />
                        {tab.label}
                      </button>
                    );
                  })}
                </nav>
              </div>

              {/* Tab Content */}
              <div className="p-6">
                {activeTab === 'overview' && (
                  <div className="space-y-6">
                    {isLoading ? (
                      <div className="animate-pulse space-y-4">
                        <div className="h-4 bg-gray-200 rounded w-1/4"></div>
                        <div className="h-32 bg-gray-200 rounded"></div>
                      </div>
                    ) : (
                      <ConnectionStatus />
                    )}
                  </div>
                )}

                {activeTab === 'notifications' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Real-time Updates</h3>
                      <p className="text-sm text-gray-600">
                        Live notifications for scan results and connection status changes.
                      </p>
                    </div>
                    <RealtimeNotifications maxNotifications={10} />
                  </div>
                )}

                {activeTab === 'privacy' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Privacy & Security</h3>
                      <p className="text-sm text-gray-600">
                        Manage your data, export information, and control privacy settings.
                      </p>
                    </div>
                    <PrivacyControls />
                  </div>
                )}

                {activeTab === 'settings' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Settings</h3>
                      <p className="text-sm text-gray-600">
                        Configure your PhishNet experience and preferences.
                      </p>
                    </div>
                    
                    {/* Settings content */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-50 rounded-lg p-4">
                        <h4 className="font-medium text-gray-900 mb-2">Notification Preferences</h4>
                        <div className="space-y-2">
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Email scan alerts</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Connection status changes</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" />
                            <span className="ml-2 text-sm text-gray-700">Daily security reports</span>
                          </label>
                        </div>
                      </div>

                      <div className="bg-gray-50 rounded-lg p-4">
                        <h4 className="font-medium text-gray-900 mb-2">Scan Settings</h4>
                        <div className="space-y-2">
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Auto-quarantine malicious emails</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" defaultChecked />
                            <span className="ml-2 text-sm text-gray-700">Scan attachments</span>
                          </label>
                          <label className="flex items-center">
                            <input type="checkbox" className="rounded" />
                            <span className="ml-2 text-sm text-gray-700">Scan sent emails</span>
                          </label>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default OAuthDashboard;