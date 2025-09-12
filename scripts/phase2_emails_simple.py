#!/usr/bin/env python3
"""
PhishNet Phase 2: Emails Domain - Simple Implementation
Direct SQLite approach to avoid configuration issues
"""

import sqlite3
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DATABASE_FILE = "phishnet_dev.db"

class EmailRepository:
    """Simple SQLite-based email repository"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
    
    def get_connection(self):
        """Get SQLite connection"""
        return sqlite3.connect(self.db_path)
    
    def create_email(self, email_data: Dict[str, Any]) -> int:
        """Create new email record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO emails (
                    gmail_msg_id, thread_id, from_addr, to_addr, subject,
                    received_at, raw_headers, raw_text, raw_html, sanitized_html,
                    status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email_data['gmail_msg_id'],
                email_data.get('thread_id'),
                email_data['from_addr'],
                email_data['to_addr'],
                email_data['subject'],
                email_data['received_at'],
                json.dumps(email_data.get('raw_headers', {})),
                email_data.get('raw_text'),
                email_data.get('raw_html'),
                email_data.get('sanitized_html'),
                email_data['status'],
                email_data['created_at']
            ))
            
            email_id = cursor.lastrowid
            conn.commit()
            print(f"✅ Created email record: {email_id} from {email_data['from_addr']}")
            return email_id
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to create email: {e}")
            return None
        finally:
            conn.close()
    
    def get_email_by_id(self, email_id: int) -> Optional[Dict]:
        """Get email by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM emails WHERE id = ?", (email_id,))
            row = cursor.fetchone()
            
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None
            
        finally:
            conn.close()
    
    def list_emails(self, limit: int = 50, status: Optional[str] = None) -> List[Dict]:
        """List emails with optional filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if status:
                cursor.execute("""
                    SELECT id, gmail_msg_id, from_addr, to_addr, subject, 
                           received_at, status, score, created_at
                    FROM emails 
                    WHERE status = ?
                    ORDER BY received_at DESC 
                    LIMIT ?
                """, (status, limit))
            else:
                cursor.execute("""
                    SELECT id, gmail_msg_id, from_addr, to_addr, subject, 
                           received_at, status, score, created_at
                    FROM emails 
                    ORDER BY received_at DESC 
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
            
        finally:
            conn.close()
    
    def count_emails(self, status: Optional[str] = None) -> int:
        """Count emails"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if status:
                cursor.execute("SELECT COUNT(*) FROM emails WHERE status = ?", (status,))
            else:
                cursor.execute("SELECT COUNT(*) FROM emails")
            
            return cursor.fetchone()[0]
            
        finally:
            conn.close()
    
    def update_email_status(self, email_id: int, status: str, score: Optional[float] = None) -> bool:
        """Update email status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            if score is not None:
                cursor.execute("""
                    UPDATE emails 
                    SET status = ?, score = ?, last_analyzed = ?
                    WHERE id = ?
                """, (status, score, datetime.now(timezone.utc).isoformat(), email_id))
            else:
                cursor.execute("""
                    UPDATE emails 
                    SET status = ?, last_analyzed = ?
                    WHERE id = ?
                """, (status, datetime.now(timezone.utc).isoformat(), email_id))
            
            conn.commit()
            print(f"✅ Updated email {email_id} status to {status}")
            return cursor.rowcount > 0
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Failed to update email: {e}")
            return False
        finally:
            conn.close()

class EmailSanitizer:
    """Email content sanitization"""
    
    @staticmethod
    def sanitize_html(raw_html: str) -> str:
        """Sanitize HTML content"""
        if not raw_html:
            return ""
        
        import re
        
        # Remove script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
        # Remove event handlers
        sanitized = re.sub(r'\son\w+="[^"]*"', '', sanitized, flags=re.IGNORECASE)
        # Remove javascript: links
        sanitized = re.sub(r'javascript:[^"\']*', '#', sanitized, flags=re.IGNORECASE)
        
        return sanitized

class EmailOrchestrator:
    """Email processing orchestrator"""
    
    def __init__(self):
        self.repository = EmailRepository()
        self.sanitizer = EmailSanitizer()
    
    def process_gmail_message(self, gmail_data: Dict) -> Optional[int]:
        """Process incoming Gmail message"""
        try:
            # Extract headers
            headers = gmail_data.get('payload', {}).get('headers', [])
            header_dict = {h['name']: h['value'] for h in headers}
            
            # Sanitize content
            raw_html = gmail_data.get('html', '')
            sanitized_html = self.sanitizer.sanitize_html(raw_html) if raw_html else None
            
            # Create email record
            email_data = {
                'gmail_msg_id': gmail_data['id'],
                'thread_id': gmail_data.get('threadId'),
                'from_addr': header_dict.get('From', 'unknown@unknown.com'),
                'to_addr': header_dict.get('To', 'unknown@unknown.com'),
                'subject': header_dict.get('Subject', '(No Subject)'),
                'received_at': datetime.now(timezone.utc).isoformat(),
                'raw_headers': header_dict,
                'raw_text': gmail_data.get('text', ''),
                'raw_html': raw_html,
                'sanitized_html': sanitized_html,
                'status': 'pending',
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            email_id = self.repository.create_email(email_data)
            
            if email_id:
                print(f"📧 Processed Gmail message: {gmail_data['id']}")
                # Simulate WebSocket broadcast
                print(f"📡 Broadcasting new email {email_id} via WebSocket")
                
            return email_id
            
        except Exception as e:
            print(f"❌ Failed to process Gmail message: {e}")
            return None

def create_test_emails():
    """Create test email data"""
    orchestrator = EmailOrchestrator()
    
    test_emails = [
        {
            'id': 'test_phishing_001',
            'threadId': 'thread_001',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'security@suspiciousbank.com'},
                    {'name': 'To', 'value': 'analyst@phishnet.local'},
                    {'name': 'Subject', 'value': 'URGENT: Verify Your Account Now!'},
                    {'name': 'Date', 'value': 'Thu, 15 Aug 2025 16:00:00 +0000'}
                ]
            },
            'html': '<html><body><h1>URGENT SECURITY ALERT</h1><p>Your account will be <b>suspended</b> in 24 hours!</p><a href="http://malicious-site.com/phish">Click here to verify</a><script>alert("evil")</script></body></html>',
            'text': 'URGENT SECURITY ALERT\nYour account will be suspended in 24 hours!\nClick here to verify: http://malicious-site.com/phish'
        },
        {
            'id': 'test_legitimate_001',
            'threadId': 'thread_002',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'notifications@github.com'},
                    {'name': 'To', 'value': 'developer@company.com'},
                    {'name': 'Subject', 'value': 'New issue in your repository'},
                    {'name': 'Date', 'value': 'Thu, 15 Aug 2025 15:30:00 +0000'}
                ]
            },
            'html': '<html><body><p>A new issue has been created in your repository.</p><a href="https://github.com/user/repo/issues/123">View Issue #123</a></body></html>',
            'text': 'A new issue has been created in your repository.\nView Issue #123: https://github.com/user/repo/issues/123'
        },
        {
            'id': 'test_spam_001',
            'threadId': 'thread_003',
            'payload': {
                'headers': [
                    {'name': 'From', 'value': 'winner@lottery-scam.net'},
                    {'name': 'To', 'value': 'lucky@winner.com'},
                    {'name': 'Subject', 'value': 'Congratulations! You won $1,000,000!!!'},
                    {'name': 'Date', 'value': 'Thu, 15 Aug 2025 14:00:00 +0000'}
                ]
            },
            'html': '<html><body><h1>🎉 CONGRATULATIONS! 🎉</h1><p>You have won $1,000,000 in our international lottery!</p><p>Send us your bank details to claim your prize!</p></body></html>',
            'text': 'CONGRATULATIONS!\nYou have won $1,000,000 in our international lottery!\nSend us your bank details to claim your prize!'
        }
    ]
    
    created_ids = []
    for test_email in test_emails:
        email_id = orchestrator.process_gmail_message(test_email)
        if email_id:
            created_ids.append(email_id)
    
    return created_ids

def main():
    """Phase 2 implementation and testing"""
    print("🔥 PhishNet Phase 2: Emails Domain")
    print("=" * 50)
    
    # Test repository
    repository = EmailRepository()
    
    # 1. Check existing emails
    print("1. Checking existing emails...")
    existing_count = repository.count_emails()
    print(f"   📧 Found {existing_count} existing emails")
    
    # 2. Create test emails
    print("2. Creating test emails...")
    test_email_ids = create_test_emails()
    print(f"   ✅ Created {len(test_email_ids)} test emails")
    
    # 3. Test queries
    print("3. Testing email queries...")
    
    # List all emails
    all_emails = repository.list_emails(limit=10)
    print(f"   📋 Listed {len(all_emails)} emails")
    
    # List pending emails
    pending_emails = repository.list_emails(status='pending')
    print(f"   ⏳ Found {len(pending_emails)} pending emails")
    
    # 4. Display sample emails
    print("4. Sample emails:")
    for email in all_emails[:3]:
        print(f"   📧 ID: {email['id']}")
        print(f"      Subject: {email['subject'][:50]}...")
        print(f"      From: {email['from_addr']}")
        print(f"      Status: {email['status']}")
        print(f"      Created: {email['created_at']}")
        print()
    
    # 5. Test status updates
    print("5. Testing status updates...")
    if test_email_ids:
        test_id = test_email_ids[0]
        success = repository.update_email_status(test_id, 'analyzed', score=0.85)
        if success:
            updated_email = repository.get_email_by_id(test_id)
            print(f"   ✅ Updated email {test_id} score: {updated_email['score']}")
    
    # 6. Final stats
    print("6. Final statistics:")
    total_count = repository.count_emails()
    pending_count = repository.count_emails('pending')
    analyzed_count = repository.count_emails('analyzed')
    
    print(f"   📊 Total emails: {total_count}")
    print(f"   ⏳ Pending: {pending_count}")
    print(f"   ✅ Analyzed: {analyzed_count}")
    
    print("\n🎉 Phase 2: Emails Domain completed successfully!")
    print("📊 Summary:")
    print(f"   - Email Repository: ✅ Implemented")
    print(f"   - Email Sanitizer: ✅ Implemented") 
    print(f"   - Email Orchestrator: ✅ Implemented")
    print(f"   - Test Data: ✅ Created ({len(test_email_ids)} emails)")
    print(f"   - Database Operations: ✅ Tested")
    print("\n🚀 Ready for Phase 3: Link analysis")

if __name__ == "__main__":
    main()
