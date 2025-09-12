"""
Redirect Analysis Repository

Database repository for storing and retrieving redirect analysis results
with support for complex queries and relationship management.
"""

import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import desc, and_, or_, func

from ..models.redirect_models import (
    RedirectAnalysis, RedirectHop, BrowserAnalysisRecord, 
    CloakingAnalysisRecord, TLSCertificateRecord
)
from ..services.redirect_interfaces import (
    IRedirectRepository, RedirectAnalysisResult, RedirectHop as RedirectHopData,
    BrowserAnalysisResult, CloakingDetection, TLSCertificateInfo
)


logger = logging.getLogger(__name__)


class RedirectAnalysisRepository(IRedirectRepository):
    """Repository for redirect analysis data"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    async def save_redirect_analysis(
        self,
        analysis_result: RedirectAnalysisResult,
        threat_result_id: Optional[str] = None
    ) -> str:
        """
        Save redirect analysis to database
        
        Args:
            analysis_result: The analysis result to save
            threat_result_id: Optional ID to link to existing threat result
            
        Returns:
            The ID of the saved analysis
        """
        try:
            # Create main analysis record
            analysis_record = RedirectAnalysis(
                original_url=analysis_result.original_url,
                final_destination=analysis_result.final_destination,
                analysis_timestamp=datetime.fromtimestamp(analysis_result.analysis_timestamp),
                total_execution_time_ms=analysis_result.total_execution_time_ms,
                total_hops=analysis_result.total_hops,
                max_hops_reached=analysis_result.max_hops_reached,
                tls_chain_valid=analysis_result.tls_chain_valid,
                mixed_content_detected=analysis_result.mixed_content_detected,
                chain_reputation_score=analysis_result.chain_reputation_score,
                threat_level=analysis_result.threat_level,
                cloaking_detected=(
                    analysis_result.cloaking_analysis.is_cloaking_detected 
                    if analysis_result.cloaking_analysis else False
                ),
                partial_analysis=analysis_result.partial_analysis,
                insecure_hops=analysis_result.insecure_hops,
                malicious_hops=analysis_result.malicious_hops,
                risk_factors=analysis_result.risk_factors,
                recommendations=analysis_result.recommendations,
                analysis_errors=analysis_result.analysis_errors,
                screenshot_urls=analysis_result.screenshot_urls,
                log_file_paths=analysis_result.log_file_paths,
                threat_result_id=threat_result_id
            )
            
            self.db.add(analysis_record)
            self.db.flush()  # Get the ID
            
            # Save redirect hops
            for hop_data in analysis_result.redirect_chain:
                hop_record = self._create_hop_record(hop_data, analysis_record.id)
                self.db.add(hop_record)
            
            # Save browser analysis results
            if analysis_result.user_browser_result:
                user_browser_record = self._create_browser_record(
                    analysis_result.user_browser_result, 
                    analysis_record.id
                )
                self.db.add(user_browser_record)
            
            if analysis_result.bot_browser_result:
                bot_browser_record = self._create_browser_record(
                    analysis_result.bot_browser_result, 
                    analysis_record.id
                )
                self.db.add(bot_browser_record)
            
            # Save cloaking analysis
            if analysis_result.cloaking_analysis:
                cloaking_record = self._create_cloaking_record(
                    analysis_result.cloaking_analysis,
                    analysis_record.id
                )
                self.db.add(cloaking_record)
            
            self.db.commit()
            logger.info(f"Saved redirect analysis {analysis_record.id} for URL: {analysis_result.original_url}")
            
            return analysis_record.id
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error saving redirect analysis: {str(e)}")
            raise
    
    async def get_redirect_analysis(self, analysis_id: str) -> Optional[RedirectAnalysisResult]:
        """
        Retrieve redirect analysis by ID
        
        Args:
            analysis_id: The analysis ID
            
        Returns:
            The redirect analysis result if found
        """
        try:
            # Query with all relationships loaded
            analysis_record = self.db.query(RedirectAnalysis).options(
                selectinload(RedirectAnalysis.redirect_hops),
                selectinload(RedirectAnalysis.browser_results),
                selectinload(RedirectAnalysis.cloaking_analysis)
            ).filter(RedirectAnalysis.id == analysis_id).first()
            
            if not analysis_record:
                return None
            
            return self._convert_to_analysis_result(analysis_record)
            
        except Exception as e:
            logger.error(f"Error retrieving redirect analysis {analysis_id}: {str(e)}")
            return None
    
    async def get_analyses_for_url(
        self,
        url: str,
        limit: int = 10
    ) -> List[RedirectAnalysisResult]:
        """
        Get recent analyses for a specific URL
        
        Args:
            url: The URL to search for
            limit: Maximum number of results
            
        Returns:
            List of recent analyses for the URL
        """
        try:
            # Query recent analyses for the URL
            analysis_records = self.db.query(RedirectAnalysis).options(
                selectinload(RedirectAnalysis.redirect_hops),
                selectinload(RedirectAnalysis.browser_results),
                selectinload(RedirectAnalysis.cloaking_analysis)
            ).filter(
                RedirectAnalysis.original_url == url
            ).order_by(
                desc(RedirectAnalysis.analysis_timestamp)
            ).limit(limit).all()
            
            results = []
            for record in analysis_records:
                result = self._convert_to_analysis_result(record)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving analyses for URL {url}: {str(e)}")
            return []
    
    async def get_analyses_by_threat_level(
        self,
        threat_levels: List[str],
        hours: int = 24,
        limit: int = 100
    ) -> List[RedirectAnalysisResult]:
        """
        Get recent analyses filtered by threat level
        
        Args:
            threat_levels: List of threat levels to include
            hours: Number of hours to look back
            limit: Maximum number of results
            
        Returns:
            List of analyses matching criteria
        """
        try:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            
            analysis_records = self.db.query(RedirectAnalysis).options(
                selectinload(RedirectAnalysis.redirect_hops),
                selectinload(RedirectAnalysis.browser_results),
                selectinload(RedirectAnalysis.cloaking_analysis)
            ).filter(
                and_(
                    RedirectAnalysis.threat_level.in_(threat_levels),
                    RedirectAnalysis.analysis_timestamp >= since_time
                )
            ).order_by(
                desc(RedirectAnalysis.analysis_timestamp)
            ).limit(limit).all()
            
            results = []
            for record in analysis_records:
                result = self._convert_to_analysis_result(record)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving analyses by threat level: {str(e)}")
            return []
    
    async def get_cloaking_analyses(
        self,
        confidence_threshold: float = 0.5,
        hours: int = 24,
        limit: int = 50
    ) -> List[RedirectAnalysisResult]:
        """
        Get analyses where cloaking was detected
        
        Args:
            confidence_threshold: Minimum confidence for cloaking detection
            hours: Number of hours to look back
            limit: Maximum number of results
            
        Returns:
            List of analyses with cloaking detected
        """
        try:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            
            analysis_records = self.db.query(RedirectAnalysis).options(
                selectinload(RedirectAnalysis.redirect_hops),
                selectinload(RedirectAnalysis.browser_results),
                selectinload(RedirectAnalysis.cloaking_analysis)
            ).join(CloakingAnalysisRecord).filter(
                and_(
                    CloakingAnalysisRecord.is_cloaking_detected == True,
                    CloakingAnalysisRecord.confidence >= confidence_threshold,
                    RedirectAnalysis.analysis_timestamp >= since_time
                )
            ).order_by(
                desc(CloakingAnalysisRecord.confidence),
                desc(RedirectAnalysis.analysis_timestamp)
            ).limit(limit).all()
            
            results = []
            for record in analysis_records:
                result = self._convert_to_analysis_result(record)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrieving cloaking analyses: {str(e)}")
            return []
    
    async def get_analysis_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get analysis statistics for the specified time period
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with analysis statistics
        """
        try:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Basic counts
            total_analyses = self.db.query(RedirectAnalysis).filter(
                RedirectAnalysis.analysis_timestamp >= since_time
            ).count()
            
            # Threat level distribution
            threat_distribution = self.db.query(
                RedirectAnalysis.threat_level,
                func.count(RedirectAnalysis.id)
            ).filter(
                RedirectAnalysis.analysis_timestamp >= since_time
            ).group_by(RedirectAnalysis.threat_level).all()
            
            # Cloaking detection stats
            cloaking_detected = self.db.query(RedirectAnalysis).filter(
                and_(
                    RedirectAnalysis.analysis_timestamp >= since_time,
                    RedirectAnalysis.cloaking_detected == True
                )
            ).count()
            
            # Average execution time
            avg_execution_time = self.db.query(
                func.avg(RedirectAnalysis.total_execution_time_ms)
            ).filter(
                RedirectAnalysis.analysis_timestamp >= since_time
            ).scalar() or 0
            
            # Most common final destinations
            top_destinations = self.db.query(
                RedirectAnalysis.final_destination,
                func.count(RedirectAnalysis.id)
            ).filter(
                RedirectAnalysis.analysis_timestamp >= since_time
            ).group_by(
                RedirectAnalysis.final_destination
            ).order_by(
                desc(func.count(RedirectAnalysis.id))
            ).limit(10).all()
            
            return {
                'total_analyses': total_analyses,
                'threat_level_distribution': dict(threat_distribution),
                'cloaking_detected': cloaking_detected,
                'cloaking_rate': (cloaking_detected / total_analyses) if total_analyses > 0 else 0,
                'average_execution_time_ms': int(avg_execution_time),
                'top_destinations': dict(top_destinations),
                'period_hours': hours
            }
            
        except Exception as e:
            logger.error(f"Error retrieving analysis statistics: {str(e)}")
            return {}
    
    def _create_hop_record(self, hop_data: RedirectHopData, analysis_id: str) -> RedirectHop:
        """Create a redirect hop database record from hop data"""
        
        # Convert TLS info to JSON
        tls_info_json = None
        if hop_data.tls_info:
            tls_info_json = {
                'subject': hop_data.tls_info.subject,
                'issuer': hop_data.tls_info.issuer,
                'san_domains': hop_data.tls_info.san_domains,
                'not_before': hop_data.tls_info.not_before,
                'not_after': hop_data.tls_info.not_after,
                'serial_number': hop_data.tls_info.serial_number,
                'fingerprint_sha256': hop_data.tls_info.fingerprint_sha256,
                'validation_status': hop_data.tls_info.validation_status.value,
                'validation_errors': hop_data.tls_info.validation_errors
            }
        
        return RedirectHop(
            analysis_id=analysis_id,
            hop_number=hop_data.hop_number,
            url=hop_data.url,
            method=hop_data.method,
            status_code=hop_data.status_code,
            redirect_type=hop_data.redirect_type.value if hop_data.redirect_type else None,
            location_header=hop_data.location_header,
            response_time_ms=hop_data.response_time_ms,
            content_length=hop_data.content_length,
            content_type=hop_data.content_type,
            server_header=hop_data.server_header,
            resolved_hostname=hop_data.resolved_hostname,
            resolved_ip=hop_data.resolved_ip,
            vt_score=hop_data.vt_score,
            abuse_score=hop_data.abuse_score,
            domain_reputation=hop_data.domain_reputation,
            response_headers=hop_data.response_headers,
            dom_changes=hop_data.dom_changes,
            javascript_redirects=hop_data.javascript_redirects,
            loaded_resources=hop_data.loaded_resources,
            error=hop_data.error,
            timestamp=datetime.fromtimestamp(hop_data.timestamp),
            tls_info=tls_info_json
        )
    
    def _create_browser_record(
        self, 
        browser_data: BrowserAnalysisResult, 
        analysis_id: str
    ) -> BrowserAnalysisRecord:
        """Create a browser analysis database record from browser data"""
        
        # Count security indicators
        credential_forms = sum(
            1 for form in browser_data.forms_detected
            if 'password' in form.get('input_types', [])
        )
        
        return BrowserAnalysisRecord(
            analysis_id=analysis_id,
            user_agent_used=browser_data.user_agent_used,
            browser_type='chromium',  # Default for now
            final_url=browser_data.final_url,
            page_title=browser_data.page_title,
            dom_content_hash=browser_data.dom_content_hash,
            screenshot_path=browser_data.screenshot_path,
            execution_time_ms=browser_data.execution_time_ms,
            console_logs=browser_data.console_logs,
            network_requests=browser_data.network_requests,
            javascript_errors=browser_data.javascript_errors,
            loaded_scripts=browser_data.loaded_scripts,
            forms_detected=browser_data.forms_detected,
            credential_forms_detected=credential_forms > 0,
            suspicious_scripts_count=len(browser_data.loaded_scripts),
            external_resources_count=len(browser_data.network_requests),
            error=browser_data.error
        )
    
    def _create_cloaking_record(
        self,
        cloaking_data: CloakingDetection,
        analysis_id: str
    ) -> CloakingAnalysisRecord:
        """Create a cloaking analysis database record from cloaking data"""
        
        return CloakingAnalysisRecord(
            analysis_id=analysis_id,
            is_cloaking_detected=cloaking_data.is_cloaking_detected,
            confidence=cloaking_data.confidence,
            user_agent_response_size=cloaking_data.user_agent_response_size,
            bot_response_size=cloaking_data.bot_response_size,
            content_similarity=cloaking_data.content_similarity,
            final_url_user=cloaking_data.final_url_user,
            final_url_bot=cloaking_data.final_url_bot,
            redirect_count_user=cloaking_data.redirect_count_user,
            redirect_count_bot=cloaking_data.redirect_count_bot,
            methods_used=[method.value for method in cloaking_data.methods_used],
            cloaking_indicators=cloaking_data.cloaking_indicators,
            suspicious_patterns=cloaking_data.suspicious_patterns,
            title_differences=cloaking_data.title_differences,
            dom_differences=cloaking_data.dom_differences,
            script_differences=cloaking_data.script_differences,
            link_differences=cloaking_data.link_differences
        )
    
    def _convert_to_analysis_result(self, record: RedirectAnalysis) -> Optional[RedirectAnalysisResult]:
        """Convert database record to analysis result object"""
        try:
            # Convert redirect hops
            redirect_chain = []
            for hop_record in sorted(record.redirect_hops, key=lambda h: h.hop_number):
                hop_data = self._convert_hop_record(hop_record)
                redirect_chain.append(hop_data)
            
            # Convert browser results
            user_browser_result = None
            bot_browser_result = None
            
            for browser_record in record.browser_results:
                browser_data = self._convert_browser_record(browser_record)
                if 'bot' in browser_record.user_agent_used.lower():
                    bot_browser_result = browser_data
                else:
                    user_browser_result = browser_data
            
            # Convert cloaking analysis
            cloaking_analysis = None
            if record.cloaking_analysis:
                cloaking_analysis = self._convert_cloaking_record(record.cloaking_analysis)
            
            # Create analysis result
            result = RedirectAnalysisResult(
                original_url=record.original_url,
                final_destination=record.final_destination,
                analysis_timestamp=record.analysis_timestamp.timestamp(),
                total_execution_time_ms=record.total_execution_time_ms,
                redirect_chain=redirect_chain,
                total_hops=record.total_hops,
                max_hops_reached=record.max_hops_reached,
                tls_chain_valid=record.tls_chain_valid,
                insecure_hops=record.insecure_hops or [],
                mixed_content_detected=record.mixed_content_detected,
                cloaking_analysis=cloaking_analysis,
                user_browser_result=user_browser_result,
                bot_browser_result=bot_browser_result,
                chain_reputation_score=record.chain_reputation_score,
                highest_threat_hop=None,  # Would need to calculate
                malicious_hops=record.malicious_hops or [],
                threat_level=record.threat_level,
                risk_factors=record.risk_factors or [],
                recommendations=record.recommendations or [],
                analysis_errors=record.analysis_errors or [],
                partial_analysis=record.partial_analysis,
                screenshot_urls=record.screenshot_urls or [],
                log_file_paths=record.log_file_paths or []
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error converting analysis record to result: {str(e)}")
            return None
    
    def _convert_hop_record(self, record: RedirectHop) -> RedirectHopData:
        """Convert hop database record to hop data object"""
        # This would be implemented to convert back to RedirectHopData
        # For brevity, showing key concept
        from ..services.redirect_interfaces import RedirectType, TLSValidationStatus
        
        hop_data = RedirectHopData(
            hop_number=record.hop_number,
            url=record.url,
            method=record.method,
            status_code=record.status_code,
            location_header=record.location_header,
            resolved_hostname=record.resolved_hostname,
            resolved_ip=record.resolved_ip,
            response_time_ms=record.response_time_ms,
            content_length=record.content_length,
            content_type=record.content_type,
            server_header=record.server_header,
            response_headers=record.response_headers or {},
            error=record.error,
            timestamp=record.timestamp.timestamp() if record.timestamp else time.time(),
            vt_score=record.vt_score,
            abuse_score=record.abuse_score,
            domain_reputation=record.domain_reputation,
            dom_changes=record.dom_changes,
            javascript_redirects=record.javascript_redirects,
            loaded_resources=record.loaded_resources
        )
        
        # Convert redirect type
        if record.redirect_type:
            hop_data.redirect_type = RedirectType(record.redirect_type)
        
        # Convert TLS info
        if record.tls_info:
            tls_data = record.tls_info
            hop_data.tls_info = TLSCertificateInfo(
                subject=tls_data.get('subject'),
                issuer=tls_data.get('issuer'),
                san_domains=tls_data.get('san_domains', []),
                not_before=tls_data.get('not_before'),
                not_after=tls_data.get('not_after'),
                serial_number=tls_data.get('serial_number'),
                fingerprint_sha256=tls_data.get('fingerprint_sha256'),
                validation_status=TLSValidationStatus(tls_data.get('validation_status', 'unknown')),
                validation_errors=tls_data.get('validation_errors', [])
            )
        
        return hop_data
    
    def _convert_browser_record(self, record: BrowserAnalysisRecord) -> BrowserAnalysisResult:
        """Convert browser database record to browser result object"""
        return BrowserAnalysisResult(
            user_agent_used=record.user_agent_used,
            final_url=record.final_url,
            page_title=record.page_title,
            dom_content_hash=record.dom_content_hash,
            screenshot_path=record.screenshot_path,
            console_logs=record.console_logs or [],
            network_requests=record.network_requests or [],
            javascript_errors=record.javascript_errors or [],
            loaded_scripts=record.loaded_scripts or [],
            forms_detected=record.forms_detected or [],
            execution_time_ms=record.execution_time_ms or 0,
            error=record.error
        )
    
    def _convert_cloaking_record(self, record: CloakingAnalysisRecord) -> CloakingDetection:
        """Convert cloaking database record to cloaking detection object"""
        from ..services.redirect_interfaces import CloakingMethod
        
        methods_used = []
        if record.methods_used:
            methods_used = [CloakingMethod(method) for method in record.methods_used]
        
        return CloakingDetection(
            is_cloaking_detected=record.is_cloaking_detected,
            confidence=record.confidence,
            methods_used=methods_used,
            user_agent_response_size=record.user_agent_response_size,
            bot_response_size=record.bot_response_size,
            content_similarity=record.content_similarity,
            title_differences=record.title_differences,
            dom_differences=record.dom_differences,
            script_differences=record.script_differences,
            link_differences=record.link_differences,
            final_url_user=record.final_url_user,
            final_url_bot=record.final_url_bot,
            redirect_count_user=record.redirect_count_user,
            redirect_count_bot=record.redirect_count_bot,
            cloaking_indicators=record.cloaking_indicators or [],
            suspicious_patterns=record.suspicious_patterns or []
        )
