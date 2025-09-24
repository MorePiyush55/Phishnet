"""
Grafana dashboard configurations for PhishNet observability.
JSON configurations for importing dashboards into Grafana.
"""

import json
from typing import Dict, Any

# Main PhishNet Overview Dashboard
PHISHNET_OVERVIEW_DASHBOARD = {
    "dashboard": {
        "id": None,
        "title": "PhishNet - Application Overview",
        "tags": ["phishnet", "overview"],
        "timezone": "browser",
        "panels": [
            {
                "id": 1,
                "title": "HTTP Requests",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_http_requests_total[5m]))",
                        "legendFormat": "Requests/sec"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Response Time",
                "type": "stat",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, rate(phishnet_http_request_duration_seconds_bucket[5m]))",
                        "legendFormat": "95th percentile"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0}
            },
            {
                "id": 3,
                "title": "Error Rate",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_http_requests_total{status_code=~\"5..\"}[5m])) / sum(rate(phishnet_http_requests_total[5m])) * 100",
                        "legendFormat": "Error %"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0},
                "thresholds": [
                    {"color": "green", "value": 0},
                    {"color": "yellow", "value": 1},
                    {"color": "red", "value": 5}
                ]
            },
            {
                "id": 4,
                "title": "Active Users",
                "type": "stat", 
                "targets": [
                    {
                        "expr": "phishnet_active_users{time_period=\"24h\"}",
                        "legendFormat": "24h Active"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
            },
            {
                "id": 5,
                "title": "Request Rate by Endpoint",
                "type": "graph",
                "targets": [
                    {
                        "expr": "sum by (endpoint) (rate(phishnet_http_requests_total[5m]))",
                        "legendFormat": "{{endpoint}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 6,
                "title": "Response Times by Endpoint",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, sum by (endpoint, le) (rate(phishnet_http_request_duration_seconds_bucket[5m])))",
                        "legendFormat": "{{endpoint}} 95th"
                    },
                    {
                        "expr": "histogram_quantile(0.50, sum by (endpoint, le) (rate(phishnet_http_request_duration_seconds_bucket[5m])))",
                        "legendFormat": "{{endpoint}} 50th"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 12, "y": 8}
            }
        ],
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s"
    }
}

# Email Scanning Dashboard
PHISHNET_SCANNING_DASHBOARD = {
    "dashboard": {
        "id": None,
        "title": "PhishNet - Email Scanning",
        "tags": ["phishnet", "scanning"],
        "timezone": "browser",
        "panels": [
            {
                "id": 1,
                "title": "Scan Rate",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_email_scans_total[5m]))",
                        "legendFormat": "Scans/sec"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Threats Detected",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_threats_detected_total[5m]))",
                        "legendFormat": "Threats/sec"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0}
            },
            {
                "id": 3,
                "title": "Avg Scan Time",
                "type": "stat",
                "targets": [
                    {
                        "expr": "avg(rate(phishnet_email_scan_duration_seconds_sum[5m]) / rate(phishnet_email_scan_duration_seconds_count[5m]))",
                        "legendFormat": "Avg seconds"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0}
            },
            {
                "id": 4,
                "title": "Queue Length",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(phishnet_queue_size)",
                        "legendFormat": "Items"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
            },
            {
                "id": 5,
                "title": "Scans by Type",
                "type": "graph",
                "targets": [
                    {
                        "expr": "sum by (scan_type) (rate(phishnet_email_scans_total[5m]))",
                        "legendFormat": "{{scan_type}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 6,
                "title": "Threats by Type",
                "type": "piechart",
                "targets": [
                    {
                        "expr": "sum by (threat_type) (phishnet_threats_detected_total)",
                        "legendFormat": "{{threat_type}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 12, "y": 8}
            },
            {
                "id": 7,
                "title": "Scan Duration Distribution",
                "type": "heatmap",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_email_scan_duration_seconds_bucket[5m])) by (le)",
                        "format": "heatmap",
                        "legendFormat": "{{le}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 24, "x": 0, "y": 17}
            }
        ],
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s"
    }
}

# ML Model Performance Dashboard
PHISHNET_ML_DASHBOARD = {
    "dashboard": {
        "id": None,
        "title": "PhishNet - ML Models",
        "tags": ["phishnet", "ml", "models"],
        "timezone": "browser",
        "panels": [
            {
                "id": 1,
                "title": "Predictions per Second",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(rate(phishnet_ml_predictions_total[5m]))",
                        "legendFormat": "Predictions/sec"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
            },
            {
                "id": 2,
                "title": "Model Accuracy",
                "type": "stat",
                "targets": [
                    {
                        "expr": "avg(phishnet_ml_model_accuracy)",
                        "legendFormat": "Accuracy"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0},
                "thresholds": [
                    {"color": "red", "value": 0.8},
                    {"color": "yellow", "value": 0.9},
                    {"color": "green", "value": 0.95}
                ]
            },
            {
                "id": 3,
                "title": "Model Drift Score",
                "type": "stat",
                "targets": [
                    {
                        "expr": "max(phishnet_ml_model_drift_score)",
                        "legendFormat": "Max Drift"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0},
                "thresholds": [
                    {"color": "green", "value": 0},
                    {"color": "yellow", "value": 0.1},
                    {"color": "red", "value": 0.3}
                ]
            },
            {
                "id": 4,
                "title": "Avg Prediction Time",
                "type": "stat",
                "targets": [
                    {
                        "expr": "avg(rate(phishnet_ml_prediction_duration_seconds_sum[5m]) / rate(phishnet_ml_prediction_duration_seconds_count[5m]))",
                        "legendFormat": "Avg seconds"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
            },
            {
                "id": 5,
                "title": "Prediction Rate by Model",
                "type": "graph",
                "targets": [
                    {
                        "expr": "sum by (model_name) (rate(phishnet_ml_predictions_total[5m]))",
                        "legendFormat": "{{model_name}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 0, "y": 8}
            },
            {
                "id": 6,
                "title": "Model Accuracy Trends",
                "type": "graph",
                "targets": [
                    {
                        "expr": "phishnet_ml_model_accuracy",
                        "legendFormat": "{{model_name}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 12, "y": 8}
            },
            {
                "id": 7,
                "title": "Prediction Duration by Model",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, sum by (model_name, le) (rate(phishnet_ml_prediction_duration_seconds_bucket[5m])))",
                        "legendFormat": "{{model_name}} 95th"
                    },
                    {
                        "expr": "histogram_quantile(0.50, sum by (model_name, le) (rate(phishnet_ml_prediction_duration_seconds_bucket[5m])))",
                        "legendFormat": "{{model_name}} 50th"
                    }
                ],
                "gridPos": {"h": 9, "w": 24, "x": 0, "y": 17}
            }
        ],
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s"
    }
}

# System Resources Dashboard
PHISHNET_SYSTEM_DASHBOARD = {
    "dashboard": {
        "id": None,
        "title": "PhishNet - System Resources",
        "tags": ["phishnet", "system", "resources"],
        "timezone": "browser",
        "panels": [
            {
                "id": 1,
                "title": "CPU Usage",
                "type": "stat",
                "targets": [
                    {
                        "expr": "phishnet_system_cpu_usage_percent",
                        "legendFormat": "CPU %"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0},
                "thresholds": [
                    {"color": "green", "value": 0},
                    {"color": "yellow", "value": 70},
                    {"color": "red", "value": 90}
                ]
            },
            {
                "id": 2,
                "title": "Memory Usage",
                "type": "stat",
                "targets": [
                    {
                        "expr": "phishnet_system_memory_usage_bytes{type=\"used\"} / phishnet_system_memory_usage_bytes{type=\"total\"} * 100",
                        "legendFormat": "Memory %"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 6, "y": 0},
                "thresholds": [
                    {"color": "green", "value": 0},
                    {"color": "yellow", "value": 80},
                    {"color": "red", "value": 95}
                ]
            },
            {
                "id": 3,
                "title": "Disk Usage",
                "type": "stat",
                "targets": [
                    {
                        "expr": "phishnet_system_disk_usage_bytes{type=\"used\"} / phishnet_system_disk_usage_bytes{type=\"total\"} * 100",
                        "legendFormat": "Disk %"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0},
                "thresholds": [
                    {"color": "green", "value": 0},
                    {"color": "yellow", "value": 80},
                    {"color": "red", "value": 95}
                ]
            },
            {
                "id": 4,
                "title": "DB Connections",
                "type": "stat",
                "targets": [
                    {
                        "expr": "sum(phishnet_db_connections)",
                        "legendFormat": "Connections"
                    }
                ],
                "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
            },
            {
                "id": 5,
                "title": "Resource Usage Trends",
                "type": "graph",
                "targets": [
                    {
                        "expr": "phishnet_system_cpu_usage_percent",
                        "legendFormat": "CPU %"
                    },
                    {
                        "expr": "phishnet_system_memory_usage_bytes{type=\"used\"} / phishnet_system_memory_usage_bytes{type=\"total\"} * 100",
                        "legendFormat": "Memory %"
                    },
                    {
                        "expr": "phishnet_system_disk_usage_bytes{type=\"used\"} / phishnet_system_disk_usage_bytes{type=\"total\"} * 100",
                        "legendFormat": "Disk %"
                    }
                ],
                "gridPos": {"h": 9, "w": 24, "x": 0, "y": 8}
            },
            {
                "id": 6,
                "title": "Database Query Performance",
                "type": "graph",
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, sum by (operation, le) (rate(phishnet_db_query_duration_seconds_bucket[5m])))",
                        "legendFormat": "{{operation}} 95th"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 0, "y": 17}
            },
            {
                "id": 7,
                "title": "Queue Sizes",
                "type": "graph",
                "targets": [
                    {
                        "expr": "phishnet_queue_size",
                        "legendFormat": "{{queue_name}}"
                    }
                ],
                "gridPos": {"h": 9, "w": 12, "x": 12, "y": 17}
            }
        ],
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s"
    }
}

# Alerts Configuration
PHISHNET_ALERTS = {
    "groups": [
        {
            "name": "phishnet-alerts",
            "rules": [
                {
                    "alert": "HighErrorRate",
                    "expr": "sum(rate(phishnet_http_requests_total{status_code=~\"5..\"}[5m])) / sum(rate(phishnet_http_requests_total[5m])) > 0.05",
                    "for": "2m",
                    "labels": {"severity": "warning"},
                    "annotations": {
                        "summary": "High error rate detected",
                        "description": "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
                    }
                },
                {
                    "alert": "SlowResponseTime",
                    "expr": "histogram_quantile(0.95, rate(phishnet_http_request_duration_seconds_bucket[5m])) > 5",
                    "for": "5m",
                    "labels": {"severity": "warning"},
                    "annotations": {
                        "summary": "Slow response times",
                        "description": "95th percentile response time is {{ $value }}s"
                    }
                },
                {
                    "alert": "HighCPUUsage",
                    "expr": "phishnet_system_cpu_usage_percent > 90",
                    "for": "5m",
                    "labels": {"severity": "warning"},
                    "annotations": {
                        "summary": "High CPU usage",
                        "description": "CPU usage is {{ $value }}%"
                    }
                },
                {
                    "alert": "HighMemoryUsage",
                    "expr": "phishnet_system_memory_usage_bytes{type=\"used\"} / phishnet_system_memory_usage_bytes{type=\"total\"} > 0.95",
                    "for": "5m",
                    "labels": {"severity": "critical"},
                    "annotations": {
                        "summary": "High memory usage",
                        "description": "Memory usage is {{ $value | humanizePercentage }}"
                    }
                },
                {
                    "alert": "ModelDriftDetected",
                    "expr": "phishnet_ml_model_drift_score > 0.3",
                    "for": "10m",
                    "labels": {"severity": "warning"},
                    "annotations": {
                        "summary": "ML model drift detected",
                        "description": "Model {{ $labels.model_name }} drift score is {{ $value }}"
                    }
                },
                {
                    "alert": "LowModelAccuracy",
                    "expr": "phishnet_ml_model_accuracy < 0.8",
                    "for": "10m",
                    "labels": {"severity": "critical"},
                    "annotations": {
                        "summary": "Low ML model accuracy",
                        "description": "Model {{ $labels.model_name }} accuracy is {{ $value }}"
                    }
                },
                {
                    "alert": "LargeQueueSize",
                    "expr": "phishnet_queue_size > 1000",
                    "for": "5m",
                    "labels": {"severity": "warning"},
                    "annotations": {
                        "summary": "Large queue size",
                        "description": "Queue {{ $labels.queue_name }} has {{ $value }} items"
                    }
                }
            ]
        }
    ]
}

def export_dashboard_json(dashboard_name: str) -> str:
    """Export dashboard configuration as JSON string."""
    dashboards = {
        "overview": PHISHNET_OVERVIEW_DASHBOARD,
        "scanning": PHISHNET_SCANNING_DASHBOARD,
        "ml": PHISHNET_ML_DASHBOARD,
        "system": PHISHNET_SYSTEM_DASHBOARD
    }
    
    if dashboard_name not in dashboards:
        raise ValueError(f"Unknown dashboard: {dashboard_name}")
    
    return json.dumps(dashboards[dashboard_name], indent=2)

def export_alerts_yaml() -> str:
    """Export alerts configuration as YAML string."""
    import yaml
    return yaml.dump(PHISHNET_ALERTS, default_flow_style=False)

# Export all dashboards and alerts
ALL_CONFIGS = {
    "dashboards": {
        "overview": PHISHNET_OVERVIEW_DASHBOARD,
        "scanning": PHISHNET_SCANNING_DASHBOARD,
        "ml": PHISHNET_ML_DASHBOARD,
        "system": PHISHNET_SYSTEM_DASHBOARD
    },
    "alerts": PHISHNET_ALERTS
}