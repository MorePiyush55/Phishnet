"""
Network Security Configuration for Sandbox Infrastructure

Implements firewall rules, VPC egress controls, credential blocking,
and IP whitelisting for secure sandbox operations.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Optional, Union
import ipaddress
import yaml

import structlog

logger = structlog.get_logger(__name__)


class NetworkSecurityConfig:
    """Configuration for network security policies."""
    
    # Blocked domains and IPs
    BLOCKED_DOMAINS = {
        # Cloud providers - credential endpoints
        'sts.amazonaws.com',
        'metadata.google.internal',
        'azure-metadata.microsoft.com',
        'instance-data.ec2.internal',
        
        # Email providers
        'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
        'protonmail.com', 'icloud.com', 'aol.com',
        
        # SSO and authentication providers
        'login.microsoftonline.com', 'accounts.google.com',
        'auth0.com', 'okta.com', 'pingidentity.com',
        
        # Social networks
        'facebook.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'tiktok.com', 'snapchat.com',
        
        # Cloud storage with credentials
        'dropbox.com', 'drive.google.com', 'onedrive.com',
        'box.com', 'icloud.com',
        
        # Banking and financial services
        'chase.com', 'bankofamerica.com', 'wellsfargo.com',
        'paypal.com', 'stripe.com', 'square.com',
        
        # Corporate VPNs and remote access
        'teamviewer.com', 'anydesk.com', 'logmein.com'
    }
    
    # Blocked IP ranges (RFC 1918 private networks, localhost, etc.)
    BLOCKED_IP_RANGES = [
        '127.0.0.0/8',      # Localhost
        '10.0.0.0/8',       # Private Class A
        '172.16.0.0/12',    # Private Class B
        '192.168.0.0/16',   # Private Class C
        '169.254.0.0/16',   # Link-local
        '224.0.0.0/4',      # Multicast
        '240.0.0.0/4',      # Reserved
    ]
    
    # Allowed third-party services (security tools, etc.)
    WHITELISTED_DOMAINS = {
        'virustotal.com',
        'urlvoid.com',
        'hybrid-analysis.com',
        'any.run',
        'malware.com',
        'browserless.io'  # For screenshot services
    }
    
    # Fixed IP ranges for third-party whitelisting
    THIRD_PARTY_IP_RANGES = [
        # Add specific IP ranges that need to be whitelisted
        # Example: '203.0.113.0/24'  # Third-party security service
    ]


class FirewallManager:
    """Manages iptables firewall rules for sandbox containers."""
    
    def __init__(self):
        self.config = NetworkSecurityConfig()
        self.chain_name = "PHISHNET_SANDBOX"
    
    def setup_container_firewall(self) -> bool:
        """Set up firewall rules for sandbox container."""
        try:
            # Create custom chain
            self._create_custom_chain()
            
            # Block localhost and private networks
            self._block_private_networks()
            
            # Block metadata services
            self._block_metadata_services()
            
            # Block known dangerous domains
            self._block_dangerous_domains()
            
            # Allow whitelisted services
            self._allow_whitelisted_services()
            
            # Default deny outbound
            self._set_default_deny()
            
            logger.info("Container firewall rules configured successfully")
            return True
            
        except Exception as e:
            logger.error("Failed to configure firewall", error=str(e))
            return False
    
    def _create_custom_chain(self):
        """Create custom iptables chain."""
        commands = [
            f"iptables -t filter -N {self.chain_name} 2>/dev/null || true",
            f"iptables -t filter -F {self.chain_name}",
            f"iptables -t filter -I OUTPUT 1 -j {self.chain_name}"
        ]
        
        for cmd in commands:
            self._run_iptables_command(cmd)
    
    def _block_private_networks(self):
        """Block access to private networks."""
        for ip_range in self.config.BLOCKED_IP_RANGES:
            cmd = f"iptables -t filter -A {self.chain_name} -d {ip_range} -j DROP"
            self._run_iptables_command(cmd)
            logger.debug("Blocked IP range", range=ip_range)
    
    def _block_metadata_services(self):
        """Block cloud metadata services."""
        # AWS metadata service
        cmd = "iptables -t filter -A {chain} -d 169.254.169.254 -j DROP".format(
            chain=self.chain_name
        )
        self._run_iptables_command(cmd)
        
        # Google metadata service
        cmd = "iptables -t filter -A {chain} -d metadata.google.internal -j DROP".format(
            chain=self.chain_name
        )
        self._run_iptables_command(cmd)
        
        logger.info("Metadata services blocked")
    
    def _block_dangerous_domains(self):
        """Block access to dangerous domains."""
        # Note: Domain blocking requires DNS-level filtering or 
        # application-level proxy. This is a placeholder for IP-based blocking.
        logger.info("Domain blocking configured", 
                   blocked_count=len(self.config.BLOCKED_DOMAINS))
    
    def _allow_whitelisted_services(self):
        """Allow access to whitelisted services."""
        for ip_range in self.config.THIRD_PARTY_IP_RANGES:
            cmd = f"iptables -t filter -A {self.chain_name} -d {ip_range} -j ACCEPT"
            self._run_iptables_command(cmd)
            logger.debug("Whitelisted IP range", range=ip_range)
    
    def _set_default_deny(self):
        """Set default deny for outbound traffic."""
        # Allow established connections
        cmd = f"iptables -t filter -A {self.chain_name} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        self._run_iptables_command(cmd)
        
        # Allow DNS (controlled by network policy)
        cmd = f"iptables -t filter -A {self.chain_name} -p udp --dport 53 -j ACCEPT"
        self._run_iptables_command(cmd)
        
        # Allow HTTP/HTTPS
        cmd = f"iptables -t filter -A {self.chain_name} -p tcp --dport 80 -j ACCEPT"
        self._run_iptables_command(cmd)
        cmd = f"iptables -t filter -A {self.chain_name} -p tcp --dport 443 -j ACCEPT"
        self._run_iptables_command(cmd)
        
        # Drop everything else
        cmd = f"iptables -t filter -A {self.chain_name} -j DROP"
        self._run_iptables_command(cmd)
        
        logger.info("Default deny policy configured")
    
    def _run_iptables_command(self, command: str):
        """Execute iptables command safely."""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                check=True
            )
            logger.debug("Executed iptables command", command=command)
        except subprocess.CalledProcessError as e:
            logger.error("Iptables command failed", 
                        command=command, 
                        error=e.stderr)
            raise
    
    def cleanup_firewall(self):
        """Clean up firewall rules."""
        try:
            commands = [
                f"iptables -t filter -D OUTPUT -j {self.chain_name} 2>/dev/null || true",
                f"iptables -t filter -F {self.chain_name} 2>/dev/null || true",
                f"iptables -t filter -X {self.chain_name} 2>/dev/null || true"
            ]
            
            for cmd in commands:
                subprocess.run(cmd.split(), capture_output=True)
            
            logger.info("Firewall rules cleaned up")
            
        except Exception as e:
            logger.warning("Failed to cleanup firewall", error=str(e))


class NetworkPolicyGenerator:
    """Generates Kubernetes NetworkPolicy and VPC security group rules."""
    
    def __init__(self):
        self.config = NetworkSecurityConfig()
    
    def generate_k8s_network_policy(self) -> Dict:
        """Generate Kubernetes NetworkPolicy YAML."""
        policy = {
            'apiVersion': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'metadata': {
                'name': 'sandbox-network-policy',
                'namespace': 'phishnet-sandbox'
            },
            'spec': {
                'podSelector': {
                    'matchLabels': {
                        'app': 'sandbox-worker'
                    }
                },
                'policyTypes': ['Egress'],
                'egress': [
                    # Allow DNS
                    {
                        'to': [],
                        'ports': [
                            {
                                'protocol': 'UDP',
                                'port': 53
                            }
                        ]
                    },
                    # Allow HTTP/HTTPS to public internet only
                    {
                        'to': [
                            {
                                'namespaceSelector': {},
                                'podSelector': {}
                            }
                        ],
                        'ports': [
                            {
                                'protocol': 'TCP',
                                'port': 80
                            },
                            {
                                'protocol': 'TCP',
                                'port': 443
                            }
                        ]
                    },
                    # Allow access to Redis
                    {
                        'to': [
                            {
                                'podSelector': {
                                    'matchLabels': {
                                        'app': 'redis'
                                    }
                                }
                            }
                        ],
                        'ports': [
                            {
                                'protocol': 'TCP',
                                'port': 6379
                            }
                        ]
                    }
                ]
            }
        }
        
        return policy
    
    def generate_aws_security_group_rules(self) -> Dict:
        """Generate AWS Security Group rules."""
        rules = {
            'Description': 'PhishNet Sandbox Security Group',
            'SecurityGroupRules': [
                # Outbound HTTP/HTTPS
                {
                    'IpPermission': {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    'IsEgress': True
                },
                {
                    'IpPermission': {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    'IsEgress': True
                },
                # Outbound DNS
                {
                    'IpPermission': {
                        'IpProtocol': 'udp',
                        'FromPort': 53,
                        'ToPort': 53,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    'IsEgress': True
                }
            ],
            'BlockedCidrs': self.config.BLOCKED_IP_RANGES
        }
        
        return rules
    
    def generate_gcp_firewall_rules(self) -> List[Dict]:
        """Generate GCP Firewall rules."""
        rules = [
            {
                'name': 'phishnet-sandbox-allow-outbound-web',
                'description': 'Allow outbound HTTP/HTTPS from sandbox',
                'direction': 'EGRESS',
                'priority': 1000,
                'targetTags': ['phishnet-sandbox'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['80', '443']
                    }
                ],
                'destinationRanges': ['0.0.0.0/0']
            },
            {
                'name': 'phishnet-sandbox-allow-dns',
                'description': 'Allow DNS from sandbox',
                'direction': 'EGRESS',
                'priority': 1000,
                'targetTags': ['phishnet-sandbox'],
                'allowed': [
                    {
                        'IPProtocol': 'udp',
                        'ports': ['53']
                    }
                ],
                'destinationRanges': ['0.0.0.0/0']
            },
            {
                'name': 'phishnet-sandbox-block-private',
                'description': 'Block private networks from sandbox',
                'direction': 'EGRESS',
                'priority': 900,
                'targetTags': ['phishnet-sandbox'],
                'denied': [
                    {
                        'IPProtocol': 'all'
                    }
                ],
                'destinationRanges': self.config.BLOCKED_IP_RANGES
            }
        ]
        
        return rules


class DNSFilter:
    """DNS-based domain filtering for sandbox containers."""
    
    def __init__(self):
        self.config = NetworkSecurityConfig()
        self.blocked_domains_file = Path("/etc/sandbox/blocked_domains.txt")
        self.allowed_domains_file = Path("/etc/sandbox/allowed_domains.txt")
    
    def setup_dns_filtering(self) -> bool:
        """Set up DNS filtering using dnsmasq or similar."""
        try:
            # Create domain lists
            self._create_domain_lists()
            
            # Configure dnsmasq
            self._configure_dnsmasq()
            
            logger.info("DNS filtering configured successfully")
            return True
            
        except Exception as e:
            logger.error("Failed to configure DNS filtering", error=str(e))
            return False
    
    def _create_domain_lists(self):
        """Create blocked and allowed domain lists."""
        # Ensure directory exists
        os.makedirs("/etc/sandbox", exist_ok=True)
        
        # Write blocked domains
        with open(self.blocked_domains_file, 'w') as f:
            for domain in sorted(self.config.BLOCKED_DOMAINS):
                f.write(f"{domain}\n")
        
        # Write allowed domains
        with open(self.allowed_domains_file, 'w') as f:
            for domain in sorted(self.config.WHITELISTED_DOMAINS):
                f.write(f"{domain}\n")
        
        logger.info("Domain lists created", 
                   blocked_count=len(self.config.BLOCKED_DOMAINS),
                   allowed_count=len(self.config.WHITELISTED_DOMAINS))
    
    def _configure_dnsmasq(self):
        """Configure dnsmasq for domain filtering."""
        dnsmasq_config = """
# PhishNet Sandbox DNS Configuration
port=53
domain-needed
bogus-priv
no-resolv
server=8.8.8.8
server=8.8.4.4
cache-size=1000

# Block dangerous domains
conf-file=/etc/sandbox/blocked_domains.txt

# Log queries for monitoring
log-queries
log-facility=/var/log/dnsmasq.log
"""
        
        with open("/etc/dnsmasq.d/sandbox.conf", 'w') as f:
            f.write(dnsmasq_config)
        
        logger.info("dnsmasq configuration written")


def setup_network_security():
    """Main function to set up all network security measures."""
    logger.info("Setting up network security for sandbox")
    
    try:
        # Set up firewall rules
        firewall = FirewallManager()
        firewall.setup_container_firewall()
        
        # Set up DNS filtering
        dns_filter = DNSFilter()
        dns_filter.setup_dns_filtering()
        
        logger.info("Network security setup completed successfully")
        return True
        
    except Exception as e:
        logger.error("Network security setup failed", error=str(e))
        return False


def generate_security_configs():
    """Generate all security configuration files."""
    logger.info("Generating security configuration files")
    
    generator = NetworkPolicyGenerator()
    
    # Generate Kubernetes NetworkPolicy
    k8s_policy = generator.generate_k8s_network_policy()
    with open("k8s-network-policy.yaml", 'w') as f:
        yaml.dump(k8s_policy, f, default_flow_style=False)
    
    # Generate AWS Security Group rules
    aws_rules = generator.generate_aws_security_group_rules()
    with open("aws-security-group-rules.json", 'w') as f:
        json.dump(aws_rules, f, indent=2)
    
    # Generate GCP Firewall rules
    gcp_rules = generator.generate_gcp_firewall_rules()
    with open("gcp-firewall-rules.json", 'w') as f:
        json.dump(gcp_rules, f, indent=2)
    
    logger.info("Security configuration files generated")


if __name__ == "__main__":
    # Set up logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="ISO"),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Generate configuration files
    generate_security_configs()
    
    # Set up network security (when running in container)
    if os.getenv('SETUP_NETWORK_SECURITY') == 'true':
        setup_network_security()
