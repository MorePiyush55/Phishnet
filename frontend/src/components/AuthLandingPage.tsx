import React from 'react';
import { Shield, Mail, Lock, CheckCircle, ArrowRight, Star, Users, Globe } from 'lucide-react';

interface AuthLandingPageProps {
  onGoogleSignIn: () => void;
}

export const AuthLandingPage: React.FC<AuthLandingPageProps> = ({ onGoogleSignIn }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-indigo-50">
      {/* Header */}
      <header className="px-6 py-4 bg-white/80 backdrop-blur-sm border-b">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <span className="text-2xl font-bold text-gray-900">PhishNet</span>
          </div>
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <Lock className="h-4 w-4" />
            <span>Enterprise Security</span>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="px-6 py-16">
        <div className="max-w-7xl mx-auto">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            {/* Left Column - Hero Content */}
            <div className="space-y-8">
              <div className="space-y-4">
                <div className="inline-flex items-center px-3 py-1 rounded-full bg-blue-100 text-blue-800 text-sm font-medium">
                  <Star className="h-4 w-4 mr-2" />
                  Advanced Email Threat Detection
                </div>
                <h1 className="text-4xl lg:text-6xl font-bold text-gray-900 leading-tight">
                  Protect Your
                  <span className="text-blue-600 block">Gmail Inbox</span>
                </h1>
                <p className="text-xl text-gray-600 leading-relaxed">
                  PhishNet analyzes your emails using advanced AI to detect phishing attempts, 
                  malicious links, and suspicious attachments before they reach you.
                </p>
              </div>

              {/* Features List */}
              <div className="space-y-4">
                {[
                  'Real-time phishing detection',
                  'AI-powered threat analysis',
                  'Secure Gmail integration',
                  'Enterprise-grade privacy'
                ].map((feature, index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                    <span className="text-gray-700">{feature}</span>
                  </div>
                ))}
              </div>

              {/* CTA Button */}
              <div className="space-y-4">
                <button
                  onClick={onGoogleSignIn}
                  className="group inline-flex items-center px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-lg transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-1"
                >
                  <img 
                    src="https://developers.google.com/identity/images/g-logo.png" 
                    alt="Google" 
                    className="h-5 w-5 mr-3"
                  />
                  Connect with Gmail
                  <ArrowRight className="h-5 w-5 ml-2 group-hover:translate-x-1 transition-transform" />
                </button>
                <p className="text-sm text-gray-500">
                  Secure OAuth 2.0 authentication • No passwords stored
                </p>
              </div>

              {/* Trust Indicators */}
              <div className="flex items-center space-x-6 pt-6 border-t">
                <div className="flex items-center space-x-2">
                  <Users className="h-5 w-5 text-gray-400" />
                  <span className="text-sm text-gray-600">10,000+ Users</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Globe className="h-5 w-5 text-gray-400" />
                  <span className="text-sm text-gray-600">Enterprise Ready</span>
                </div>
                <div className="flex items-center space-x-2">
                  <Shield className="h-5 w-5 text-gray-400" />
                  <span className="text-sm text-gray-600">SOC 2 Compliant</span>
                </div>
              </div>
            </div>

            {/* Right Column - Visual */}
            <div className="relative">
              <div className="bg-white rounded-2xl shadow-2xl p-8 border">
                <div className="space-y-6">
                  {/* Mock Email Interface */}
                  <div className="flex items-center space-x-3 pb-4 border-b">
                    <Mail className="h-6 w-6 text-blue-600" />
                    <span className="font-semibold text-gray-900">Email Security Dashboard</span>
                  </div>
                  
                  {/* Mock Threat Detection */}
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-red-50 border border-red-200 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="h-3 w-3 bg-red-500 rounded-full"></div>
                        <span className="text-sm font-medium text-red-900">Phishing Detected</span>
                      </div>
                      <span className="text-xs text-red-600 font-medium">BLOCKED</span>
                    </div>
                    
                    <div className="flex items-center justify-between p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="h-3 w-3 bg-yellow-500 rounded-full"></div>
                        <span className="text-sm font-medium text-yellow-900">Suspicious Link</span>
                      </div>
                      <span className="text-xs text-yellow-600 font-medium">QUARANTINED</span>
                    </div>
                    
                    <div className="flex items-center justify-between p-4 bg-green-50 border border-green-200 rounded-lg">
                      <div className="flex items-center space-x-3">
                        <div className="h-3 w-3 bg-green-500 rounded-full"></div>
                        <span className="text-sm font-medium text-green-900">Email Verified</span>
                      </div>
                      <span className="text-xs text-green-600 font-medium">SAFE</span>
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-4 pt-4 border-t">
                    <div className="text-center">
                      <div className="text-2xl font-bold text-blue-600">99.7%</div>
                      <div className="text-xs text-gray-500">Detection Rate</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-green-600">0.01%</div>
                      <div className="text-xs text-gray-500">False Positives</div>
                    </div>
                    <div className="text-center">
                      <div className="text-2xl font-bold text-purple-600">&lt;50ms</div>
                      <div className="text-xs text-gray-500">Analysis Time</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Floating Elements */}
              <div className="absolute -top-4 -right-4 h-8 w-8 bg-blue-500 rounded-full opacity-20"></div>
              <div className="absolute -bottom-4 -left-4 h-12 w-12 bg-purple-500 rounded-full opacity-20"></div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="px-6 py-8 bg-gray-50 border-t">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
            <div className="flex items-center space-x-6 text-sm text-gray-600">
              <span>© 2025 PhishNet. All rights reserved.</span>
              <a href="#" className="hover:text-blue-600 transition-colors">Privacy Policy</a>
              <a href="#" className="hover:text-blue-600 transition-colors">Terms of Service</a>
            </div>
            <div className="flex items-center space-x-4">
              <img src="https://developers.google.com/identity/images/g-logo.png" alt="Google Partner" className="h-6 w-6" />
              <span className="text-sm text-gray-500">Google Verified Partner</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};