import React from 'react';
import { Shield, Mail, Lock, CheckCircle, ArrowRight, Star, Users, Globe, Zap, AlertTriangle, Eye, BarChart3 } from 'lucide-react';

interface AuthLandingPageProps {
  onGoogleSignIn: () => void;
}

export const AuthLandingPage: React.FC<AuthLandingPageProps> = ({ onGoogleSignIn }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Navigation */}
      <nav className="px-6 py-4 bg-white/95 backdrop-blur-sm border-b border-gray-200 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="relative">
              <Shield className="h-10 w-10 text-blue-600" />
              <div className="absolute -top-1 -right-1 h-4 w-4 bg-green-500 rounded-full border-2 border-white"></div>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">PhishNet</h1>
              <p className="text-xs text-gray-500 font-medium">Enterprise Email Security</p>
            </div>
          </div>
          <div className="hidden md:flex items-center space-x-6">
            <div className="flex items-center space-x-2 text-sm text-gray-600">
              <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse"></div>
              <span>System Operational</span>
            </div>
            <div className="text-sm text-gray-500">SOC 2 Type II Certified</div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="relative">
        {/* Background Pattern */}
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        
        <div className="relative px-6 py-16 lg:py-24">
          <div className="max-w-7xl mx-auto">
            <div className="grid lg:grid-cols-2 gap-16 items-center">
              
              {/* Left Column - Content */}
              <div className="space-y-10">
                {/* Badge */}
                <div className="inline-flex items-center px-4 py-2 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white text-sm font-semibold shadow-lg">
                  <Star className="h-4 w-4 mr-2" />
                  #1 AI-Powered Email Security Platform
                </div>

                {/* Headlines */}
                <div className="space-y-6">
                  <h1 className="text-5xl lg:text-7xl font-bold text-gray-900 leading-tight">
                    Stop Email
                    <span className="block text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600">
                      Threats
                    </span>
                    <span className="block text-gray-900">Before They Hit</span>
                  </h1>
                  
                  <p className="text-xl lg:text-2xl text-gray-600 leading-relaxed max-w-2xl">
                    PhishNet's advanced AI analyzes your Gmail in real-time, blocking phishing attempts, 
                    malicious links, and suspicious attachments with 99.8% accuracy.
                  </p>
                </div>

                {/* Key Benefits */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {[
                    { icon: Zap, text: "Real-time AI Detection", color: "text-yellow-600" },
                    { icon: Shield, text: "Zero-Day Protection", color: "text-blue-600" },
                    { icon: Lock, text: "Bank-Grade Security", color: "text-green-600" },
                    { icon: BarChart3, text: "Advanced Analytics", color: "text-purple-600" }
                  ].map((benefit, index) => (
                    <div key={index} className="flex items-center space-x-3 p-3 rounded-lg bg-white/60 backdrop-blur-sm">
                      <benefit.icon className={`h-6 w-6 ${benefit.color}`} />
                      <span className="font-semibold text-gray-800">{benefit.text}</span>
                    </div>
                  ))}
                </div>

                {/* CTA Section */}
                <div className="space-y-6">
                  <button
                    onClick={onGoogleSignIn}
                    className="group relative inline-flex items-center px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white font-bold text-lg rounded-xl transition-all duration-300 shadow-xl hover:shadow-2xl transform hover:-translate-y-1 border border-blue-500"
                  >
                    <div className="flex items-center space-x-3">
                      <img 
                        src="https://developers.google.com/identity/images/g-logo.png" 
                        alt="Google" 
                        className="h-6 w-6"
                      />
                      <span>Connect Gmail Account</span>
                      <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
                    </div>
                    <div className="absolute inset-0 bg-white/20 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  </button>
                  
                  <div className="flex items-center space-x-4 text-sm text-gray-600">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                      <span>OAuth 2.0 Secure</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                      <span>No Passwords Required</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-600" />
                      <span>Read-Only Access</span>
                    </div>
                  </div>
                </div>

                {/* Trust Indicators */}
                <div className="flex items-center space-x-8 pt-8 border-t border-gray-200">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-gray-900">500K+</div>
                    <div className="text-sm text-gray-600">Emails Protected</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-gray-900">99.8%</div>
                    <div className="text-sm text-gray-600">Detection Rate</div>
                  </div>
                  <div className="text-center">
                    <div className="text-3xl font-bold text-gray-900">Enterprise</div>
                    <div className="text-sm text-gray-600">Grade Security</div>
                  </div>
                </div>
              </div>

              {/* Right Column - Dashboard Preview */}
              <div className="relative">
                {/* Main Dashboard Card */}
                <div className="bg-white rounded-2xl shadow-2xl border border-gray-200 overflow-hidden">
                  {/* Header */}
                  <div className="bg-gradient-to-r from-gray-50 to-blue-50 px-6 py-4 border-b">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className="h-3 w-3 bg-green-500 rounded-full animate-pulse"></div>
                        <span className="font-semibold text-gray-900">PhishNet Security Dashboard</span>
                      </div>
                      <div className="text-xs text-gray-500 font-mono">Real-time</div>
                    </div>
                  </div>
                  
                  {/* Threat Detection Panel */}
                  <div className="p-6 space-y-4">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Threats Detected</h3>
                    
                    {/* Threat Items */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-4 bg-red-50 border-l-4 border-red-500 rounded-r-lg">
                        <div className="flex items-center space-x-3">
                          <AlertTriangle className="h-5 w-5 text-red-600" />
                          <div>
                            <div className="font-semibold text-red-900">Credential Phishing</div>
                            <div className="text-sm text-red-700">banking-security@fake-bank.com</div>
                          </div>
                        </div>
                        <div className="px-3 py-1 bg-red-100 text-red-800 text-xs font-bold rounded-full">
                          BLOCKED
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between p-4 bg-yellow-50 border-l-4 border-yellow-500 rounded-r-lg">
                        <div className="flex items-center space-x-3">
                          <Eye className="h-5 w-5 text-yellow-600" />
                          <div>
                            <div className="font-semibold text-yellow-900">Suspicious Link</div>
                            <div className="text-sm text-yellow-700">malicious-download.exe</div>
                          </div>
                        </div>
                        <div className="px-3 py-1 bg-yellow-100 text-yellow-800 text-xs font-bold rounded-full">
                          QUARANTINED
                        </div>
                      </div>
                      
                      <div className="flex items-center justify-between p-4 bg-green-50 border-l-4 border-green-500 rounded-r-lg">
                        <div className="flex items-center space-x-3">
                          <CheckCircle className="h-5 w-5 text-green-600" />
                          <div>
                            <div className="font-semibold text-green-900">Legitimate Email</div>
                            <div className="text-sm text-green-700">team@company.com</div>
                          </div>
                        </div>
                        <div className="px-3 py-1 bg-green-100 text-green-800 text-xs font-bold rounded-full">
                          VERIFIED
                        </div>
                      </div>
                    </div>

                    {/* Stats Grid */}
                    <div className="grid grid-cols-3 gap-4 pt-6 border-t border-gray-200">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-blue-600">99.8%</div>
                        <div className="text-xs text-gray-600 font-medium">Accuracy</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-green-600">0.02%</div>
                        <div className="text-xs text-gray-600 font-medium">False Positive</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-purple-600">&lt;30ms</div>
                        <div className="text-xs text-gray-600 font-medium">Response Time</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Floating Security Badge */}
                <div className="absolute -top-4 -right-4 bg-white rounded-xl shadow-lg border border-gray-200 p-3">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5 text-green-600" />
                    <span className="text-sm font-semibold text-gray-900">SOC 2</span>
                  </div>
                </div>

                {/* Floating Elements for Visual Appeal */}
                <div className="absolute -bottom-6 -left-6 h-12 w-12 bg-blue-500 rounded-full opacity-20 animate-bounce"></div>
                <div className="absolute -top-8 left-1/2 h-6 w-6 bg-purple-500 rounded-full opacity-30"></div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="px-6 py-8 bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
            <div className="flex items-center space-x-6 text-sm text-gray-600">
              <span>© 2025 PhishNet. All rights reserved.</span>
              <a href="#" className="hover:text-blue-600 transition-colors font-medium">Privacy Policy</a>
              <a href="#" className="hover:text-blue-600 transition-colors font-medium">Terms of Service</a>
              <a href="#" className="hover:text-blue-600 transition-colors font-medium">Security</a>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <img src="https://developers.google.com/identity/images/g-logo.png" alt="Google Partner" className="h-5 w-5" />
                <span className="text-sm text-gray-600 font-medium">Google Cloud Partner</span>
              </div>
              <div className="h-4 w-px bg-gray-300"></div>
              <div className="text-sm text-gray-600 font-medium">SOC 2 Type II</div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};