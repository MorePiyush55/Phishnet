"""
PhishNet Architecture Documentation and Scaling Demo
Generates architecture diagrams and demonstrates scaling capabilities
"""

import asyncio
import json
import time
from typing import Dict, List, Any
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ConnectionPatch
import numpy as np
import seaborn as sns

from app.core.horizontal_scaling import horizontal_scaler, WorkerStatus
from app.core.message_queue import EmailProcessingQueue, QueuePriority
from app.core.feature_flags import feature_flag_manager
from app.services.threat_hunting import threat_hunting_engine
from app.core.redis_client import get_cache_manager
from app.config.logging import get_logger

logger = get_logger(__name__)

class ArchitectureDiagramGenerator:
    """Generates visual architecture diagrams for PhishNet"""
    
    def __init__(self):
        plt.style.use('seaborn-v0_8')
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'accent': '#F18F01',
            'success': '#C73E1D',
            'background': '#F5F5F5',
            'text': '#2C3E50'
        }
    
    def generate_scalable_architecture_diagram(self, save_path: str = "docs/architecture_scalable.png"):
        """Generate comprehensive scalable architecture diagram"""
        fig, ax = plt.subplots(1, 1, figsize=(16, 12))
        ax.set_xlim(0, 16)
        ax.set_ylim(0, 12)
        ax.axis('off')
        
        # Title
        ax.text(8, 11.5, 'PhishNet - Scalable Enterprise Architecture', 
                fontsize=20, fontweight='bold', ha='center', color=self.colors['text'])
        
        # Draw components
        self._draw_load_balancer(ax, 8, 10)
        self._draw_api_gateway(ax, 8, 8.5)
        self._draw_worker_pool(ax, 2, 6.5)
        self._draw_message_queue(ax, 8, 6.5)
        self._draw_feature_flags(ax, 14, 6.5)
        self._draw_threat_hunting(ax, 2, 4)
        self._draw_databases(ax, 8, 2)
        self._draw_monitoring(ax, 14, 2)
        self._draw_security_layer(ax, 14, 8.5)
        
        # Draw connections
        self._draw_connections(ax)
        
        # Add legend
        self._add_legend(ax)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        plt.close()
        
        logger.info(f"Scalable architecture diagram saved to {save_path}")
    
    def _draw_load_balancer(self, ax, x, y):
        """Draw load balancer component"""
        box = FancyBboxPatch((x-1.5, y-0.5), 3, 1, 
                            boxstyle="round,pad=0.1", 
                            facecolor=self.colors['primary'], 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y, 'Load Balancer\n(NGINX)', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
    
    def _draw_api_gateway(self, ax, x, y):
        """Draw API Gateway"""
        box = FancyBboxPatch((x-1.5, y-0.5), 3, 1, 
                            boxstyle="round,pad=0.1", 
                            facecolor=self.colors['secondary'], 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y, 'API Gateway\n(FastAPI)', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
    
    def _draw_worker_pool(self, ax, x, y):
        """Draw horizontal worker pool"""
        # Worker pool container
        container = FancyBboxPatch((x-1.5, y-1), 3, 2, 
                                  boxstyle="round,pad=0.1", 
                                  facecolor=self.colors['background'], 
                                  edgecolor='black', linewidth=2)
        ax.add_patch(container)
        ax.text(x, y+0.7, 'Worker Pool', ha='center', va='center', 
                fontsize=11, fontweight='bold', color=self.colors['text'])
        
        # Individual workers
        worker_positions = [(x-1, y), (x, y), (x+1, y)]
        for i, (wx, wy) in enumerate(worker_positions):
            worker = plt.Circle((wx, wy), 0.2, 
                              facecolor=self.colors['accent'], 
                              edgecolor='black', linewidth=1)
            ax.add_patch(worker)
            ax.text(wx, wy-0.5, f'W{i+1}', ha='center', va='center', 
                    fontsize=8, fontweight='bold')
        
        # Auto-scaling arrows
        ax.annotate('', xy=(x+1.8, y), xytext=(x+1.4, y),
                   arrowprops=dict(arrowstyle='->', lw=2, color=self.colors['success']))
        ax.text(x+2.2, y, 'Auto\nScale', ha='center', va='center', 
                fontsize=8, color=self.colors['success'])
    
    def _draw_message_queue(self, ax, x, y):
        """Draw Redis Streams message queue"""
        box = FancyBboxPatch((x-1.5, y-0.75), 3, 1.5, 
                            boxstyle="round,pad=0.1", 
                            facecolor=self.colors['accent'], 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y+0.2, 'Message Queue', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
        ax.text(x, y-0.2, 'Redis Streams', ha='center', va='center', 
                fontsize=9, color='white')
        
        # Priority queues
        priorities = ['HIGH', 'MED', 'LOW']
        for i, priority in enumerate(priorities):
            qx = x - 1 + i * 1
            queue_rect = plt.Rectangle((qx-0.2, y-0.6), 0.4, 0.3, 
                                     facecolor='white', edgecolor='black', alpha=0.8)
            ax.add_patch(queue_rect)
            ax.text(qx, y-0.45, priority, ha='center', va='center', fontsize=7)
    
    def _draw_feature_flags(self, ax, x, y):
        """Draw feature flags system"""
        box = FancyBboxPatch((x-1.5, y-0.75), 3, 1.5, 
                            boxstyle="round,pad=0.1", 
                            facecolor=self.colors['secondary'], 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y+0.2, 'Feature Flags', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
        ax.text(x, y-0.2, 'Dynamic Config', ha='center', va='center', 
                fontsize=9, color='white')
        
        # Toggle switches
        for i in range(3):
            toggle_x = x - 0.6 + i * 0.6
            toggle = plt.Circle((toggle_x, y-0.5), 0.08, 
                              facecolor='white', edgecolor='black')
            ax.add_patch(toggle)
    
    def _draw_threat_hunting(self, ax, x, y):
        """Draw threat hunting system"""
        box = FancyBboxPatch((x-1.5, y-0.75), 3, 1.5, 
                            boxstyle="round,pad=0.1", 
                            facecolor=self.colors['success'], 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y+0.2, 'Threat Hunting', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
        ax.text(x, y-0.2, 'SIEM Engine', ha='center', va='center', 
                fontsize=9, color='white')
        
        # Search icons
        search_icon = plt.Circle((x-0.5, y-0.5), 0.1, 
                               facecolor='white', edgecolor='black')
        ax.add_patch(search_icon)
        ax.text(x, y-0.5, '🔍', ha='center', va='center', fontsize=12)
    
    def _draw_databases(self, ax, x, y):
        """Draw database components"""
        # PostgreSQL
        pg_box = FancyBboxPatch((x-2.5, y-0.5), 2, 1, 
                               boxstyle="round,pad=0.1", 
                               facecolor=self.colors['primary'], 
                               edgecolor='black', linewidth=2)
        ax.add_patch(pg_box)
        ax.text(x-1.5, y, 'PostgreSQL\nPrimary DB', ha='center', va='center', 
                fontsize=9, fontweight='bold', color='white')
        
        # Redis Cache
        redis_box = FancyBboxPatch((x+0.5, y-0.5), 2, 1, 
                                  boxstyle="round,pad=0.1", 
                                  facecolor=self.colors['accent'], 
                                  edgecolor='black', linewidth=2)
        ax.add_patch(redis_box)
        ax.text(x+1.5, y, 'Redis\nCache & Queue', ha='center', va='center', 
                fontsize=9, fontweight='bold', color='white')
    
    def _draw_monitoring(self, ax, x, y):
        """Draw monitoring stack"""
        box = FancyBboxPatch((x-1.5, y-0.75), 3, 1.5, 
                            boxstyle="round,pad=0.1", 
                            facecolor='#34495E', 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y+0.2, 'Monitoring', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
        ax.text(x, y-0.2, 'Prometheus + Grafana', ha='center', va='center', 
                fontsize=9, color='white')
        
        # Metrics visualization
        ax.plot([x-0.5, x+0.5], [y-0.5, y-0.4], 'white', linewidth=2)
        ax.plot([x-0.3, x+0.3], [y-0.5, y-0.3], 'white', linewidth=2)
    
    def _draw_security_layer(self, ax, x, y):
        """Draw security layer"""
        box = FancyBboxPatch((x-1.5, y-0.5), 3, 1, 
                            boxstyle="round,pad=0.1", 
                            facecolor='#E74C3C', 
                            edgecolor='black', linewidth=2)
        ax.add_patch(box)
        ax.text(x, y, 'Security Layer\nJWT + OAuth', ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
    
    def _draw_connections(self, ax):
        """Draw connections between components"""
        connections = [
            # Load Balancer to API Gateway
            ((8, 9.5), (8, 9)),
            # API Gateway to Workers
            ((8, 8), (2, 7.5)),
            # API Gateway to Message Queue
            ((8, 8), (8, 7.25)),
            # Workers to Message Queue
            ((2, 6.5), (6.5, 6.5)),
            # Message Queue to Threat Hunting
            ((8, 5.75), (2, 4.75)),
            # All to Databases
            ((8, 6.5), (8, 3)),
            ((2, 6), (6.5, 2.5)),
            # Monitoring connections
            ((14, 2.75), (8, 3)),
            ((14, 2.75), (2, 4)),
            # Feature Flags to API Gateway
            ((13, 6.5), (9.5, 8.5)),
            # Security to API Gateway
            ((14, 8), (9.5, 8.5))
        ]
        
        for start, end in connections:
            ax.plot([start[0], end[0]], [start[1], end[1]], 
                   'gray', linewidth=2, alpha=0.7, linestyle='--')
    
    def _add_legend(self, ax):
        """Add architecture legend"""
        legend_items = [
            ('Horizontal Scaling', self.colors['accent']),
            ('Message Queues', self.colors['primary']),
            ('Feature Flags', self.colors['secondary']),
            ('Threat Hunting', self.colors['success']),
            ('Security Layer', '#E74C3C')
        ]
        
        for i, (label, color) in enumerate(legend_items):
            y_pos = 0.5 + i * 0.3
            legend_box = plt.Rectangle((0.5, y_pos), 0.3, 0.2, 
                                     facecolor=color, edgecolor='black')
            ax.add_patch(legend_box)
            ax.text(1, y_pos + 0.1, label, va='center', fontsize=9)
    
    def generate_scaling_performance_chart(self, scaling_data: Dict[str, Any], 
                                         save_path: str = "docs/scaling_performance.png"):
        """Generate scaling performance charts"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Worker count over time
        times = scaling_data.get('timestamps', [])
        worker_counts = scaling_data.get('worker_counts', [])
        queue_sizes = scaling_data.get('queue_sizes', [])
        processing_times = scaling_data.get('processing_times', [])
        cpu_usage = scaling_data.get('cpu_usage', [])
        
        ax1.plot(times, worker_counts, marker='o', linewidth=2, 
                color=self.colors['primary'], label='Active Workers')
        ax1.set_title('Worker Count Over Time', fontsize=12, fontweight='bold')
        ax1.set_ylabel('Number of Workers')
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Queue size vs processing time
        ax2.scatter(queue_sizes, processing_times, alpha=0.6, 
                   s=60, color=self.colors['secondary'])
        ax2.set_title('Queue Size vs Processing Time', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Queue Size')
        ax2.set_ylabel('Processing Time (ms)')
        ax2.grid(True, alpha=0.3)
        
        # CPU Usage
        ax3.fill_between(times, cpu_usage, alpha=0.7, color=self.colors['accent'])
        ax3.set_title('CPU Usage Over Time', fontsize=12, fontweight='bold')
        ax3.set_ylabel('CPU Usage (%)')
        ax3.set_ylim(0, 100)
        ax3.grid(True, alpha=0.3)
        
        # Scaling Events
        scaling_events = scaling_data.get('scaling_events', [])
        event_times = [event['timestamp'] for event in scaling_events]
        event_types = [1 if event['type'] == 'scale_up' else -1 for event in scaling_events]
        
        colors = [self.colors['success'] if et > 0 else self.colors['primary'] for et in event_types]
        ax4.scatter(event_times, event_types, c=colors, s=100, alpha=0.8)
        ax4.set_title('Scaling Events', fontsize=12, fontweight='bold')
        ax4.set_ylabel('Scale Direction')
        ax4.set_yticks([-1, 1])
        ax4.set_yticklabels(['Scale Down', 'Scale Up'])
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info(f"Scaling performance chart saved to {save_path}")

class ScalingDemo:
    """Demonstrates horizontal scaling capabilities"""
    
    def __init__(self):
        self.demo_data = {
            'timestamps': [],
            'worker_counts': [],
            'queue_sizes': [],
            'processing_times': [],
            'cpu_usage': [],
            'scaling_events': []
        }
        self.diagram_generator = ArchitectureDiagramGenerator()
    
    async def run_full_demo(self):
        """Run comprehensive scaling demonstration"""
        logger.info("Starting PhishNet Horizontal Scaling Demo")
        
        try:
            # Initialize components
            await self._initialize_components()
            
            # Generate architecture diagrams
            await self._generate_diagrams()
            
            # Run scaling simulation
            await self._run_scaling_simulation()
            
            # Generate performance reports
            await self._generate_performance_reports()
            
            # Cleanup
            await self._cleanup_demo()
            
            logger.info("Scaling demo completed successfully")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
    
    async def _initialize_components(self):
        """Initialize all scalability components"""
        logger.info("Initializing scalability components...")
        
        # Initialize horizontal scaler
        await horizontal_scaler.initialize()
        
        # Initialize feature flags
        await feature_flag_manager.initialize()
        
        # Initialize threat hunting
        await threat_hunting_engine.initialize()
        
        logger.info("All components initialized")
    
    async def _generate_diagrams(self):
        """Generate architecture diagrams"""
        logger.info("Generating architecture diagrams...")
        
        # Generate scalable architecture diagram
        self.diagram_generator.generate_scalable_architecture_diagram()
        
        logger.info("Architecture diagrams generated")
    
    async def _run_scaling_simulation(self):
        """Run scaling simulation with load generation"""
        logger.info("Starting scaling simulation...")
        
        # Simulate high load scenario
        await self._simulate_high_load()
        
        # Simulate normal load recovery
        await self._simulate_load_recovery()
        
        logger.info("Scaling simulation completed")
    
    async def _simulate_high_load(self):
        """Simulate high load to trigger scaling"""
        logger.info("Simulating high load scenario...")
        
        email_queue = EmailProcessingQueue()
        await email_queue.initialize()
        
        # Generate high volume of messages
        for i in range(100):
            message_data = {
                "email_id": f"demo_email_{i}",
                "sender": f"sender{i}@example.com",
                "recipient": f"recipient{i}@company.com",
                "subject": f"Demo Email {i}",
                "body": f"This is demo email body {i}",
                "priority": "high" if i < 30 else "medium" if i < 70 else "low"
            }
            
            priority = QueuePriority.HIGH if i < 30 else QueuePriority.MEDIUM if i < 70 else QueuePriority.LOW
            await email_queue.enqueue(message_data, priority=priority)
        
        # Monitor scaling for 5 minutes
        start_time = time.time()
        while time.time() - start_time < 300:  # 5 minutes
            status = await horizontal_scaler.get_scaling_status()
            
            self.demo_data['timestamps'].append(time.time())
            self.demo_data['worker_counts'].append(status['workers']['total'])
            self.demo_data['queue_sizes'].append(status['queue']['total_messages'])
            self.demo_data['processing_times'].append(status['performance']['avg_processing_time'])
            self.demo_data['cpu_usage'].append(status['performance']['avg_cpu_usage'])
            
            # Check for scaling events
            recent_events = status['scaling']['recent_events']
            for event in recent_events:
                if event not in self.demo_data['scaling_events']:
                    self.demo_data['scaling_events'].append(event)
            
            await asyncio.sleep(10)  # Sample every 10 seconds
    
    async def _simulate_load_recovery(self):
        """Simulate load recovery and scale down"""
        logger.info("Simulating load recovery...")
        
        # Stop adding new messages and let workers process the queue
        start_time = time.time()
        while time.time() - start_time < 300:  # 5 minutes
            status = await horizontal_scaler.get_scaling_status()
            
            self.demo_data['timestamps'].append(time.time())
            self.demo_data['worker_counts'].append(status['workers']['total'])
            self.demo_data['queue_sizes'].append(status['queue']['total_messages'])
            self.demo_data['processing_times'].append(status['performance']['avg_processing_time'])
            self.demo_data['cpu_usage'].append(status['performance']['avg_cpu_usage'])
            
            await asyncio.sleep(10)
    
    async def _generate_performance_reports(self):
        """Generate performance analysis reports"""
        logger.info("Generating performance reports...")
        
        # Generate scaling performance charts
        self.diagram_generator.generate_scaling_performance_chart(self.demo_data)
        
        # Generate text report
        await self._generate_text_report()
        
        logger.info("Performance reports generated")
    
    async def _generate_text_report(self):
        """Generate detailed text report"""
        report = f"""
# PhishNet Horizontal Scaling Demo Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Scaling Summary
- **Total Demo Duration**: {len(self.demo_data['timestamps']) * 10 / 60:.1f} minutes
- **Peak Workers**: {max(self.demo_data['worker_counts']) if self.demo_data['worker_counts'] else 0}
- **Min Workers**: {min(self.demo_data['worker_counts']) if self.demo_data['worker_counts'] else 0}
- **Peak Queue Size**: {max(self.demo_data['queue_sizes']) if self.demo_data['queue_sizes'] else 0}
- **Scaling Events**: {len(self.demo_data['scaling_events'])}

## Performance Metrics
- **Average Processing Time**: {np.mean(self.demo_data['processing_times']):.2f}ms
- **Peak CPU Usage**: {max(self.demo_data['cpu_usage']) if self.demo_data['cpu_usage'] else 0:.1f}%
- **Average CPU Usage**: {np.mean(self.demo_data['cpu_usage']):.1f}%

## Scaling Events
"""
        
        for event in self.demo_data['scaling_events']:
            report += f"- **{event['type'].title()}**: {event['reason']} (Workers: {event.get('workers_change', 'N/A')})\n"
        
        report += f"""
## Key Features Demonstrated
1. **Automatic Horizontal Scaling**: Workers automatically scaled based on queue size and CPU usage
2. **Message Queue Processing**: Redis Streams handled priority-based message distribution
3. **Real-time Monitoring**: Comprehensive metrics tracking and visualization
4. **Feature Flag Integration**: Dynamic configuration management
5. **Threat Hunting Capabilities**: Advanced security analysis engine

## Architecture Benefits
- **Scalability**: Horizontal scaling supports increased load
- **Reliability**: Message queue ensures no email loss
- **Performance**: Distributed processing reduces latency
- **Flexibility**: Feature flags enable dynamic configuration
- **Security**: Threat hunting provides advanced analysis
"""
        
        with open("docs/scaling_demo_report.md", "w") as f:
            f.write(report)
        
        logger.info("Text report saved to docs/scaling_demo_report.md")
    
    async def _cleanup_demo(self):
        """Clean up demo resources"""
        logger.info("Cleaning up demo resources...")
        
        # Scale down to minimum workers
        current_status = await horizontal_scaler.get_scaling_status()
        current_workers = current_status['workers']['total']
        min_workers = horizontal_scaler.min_workers
        
        if current_workers > min_workers:
            await horizontal_scaler.scale_down(current_workers - min_workers, "demo_cleanup")
        
        logger.info("Demo cleanup completed")

async def run_scaling_demo():
    """Main function to run the scaling demonstration"""
    demo = ScalingDemo()
    await demo.run_full_demo()

if __name__ == "__main__":
    asyncio.run(run_scaling_demo())
