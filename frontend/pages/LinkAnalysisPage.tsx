/**
 * Link Analysis Page Component
 * 
 * Main page for link redirect analysis and security assessment
 */

import React from 'react';
import { Helmet } from 'react-helmet-async';
import LinkRedirectAnalysis from '../components/LinkRedirectAnalysis';

const LinkAnalysisPage: React.FC = () => {
  return (
    <>
      <Helmet>
        <title>Link Redirect Analysis - PhishNet</title>
        <meta name="description" content="Analyze URLs for redirect chains, cloaking detection, and security threats with PhishNet's comprehensive link analysis tool." />
        <meta name="keywords" content="url analysis, redirect detection, cloaking detection, phishing, security, threat analysis" />
      </Helmet>
      
      <div className="min-h-screen bg-gray-50">
        <LinkRedirectAnalysis />
      </div>
    </>
  );
};

export default LinkAnalysisPage;