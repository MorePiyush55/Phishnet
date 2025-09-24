"""
Branch protection configuration for GitHub repository.
Ensures code quality through required status checks.
"""

BRANCH_PROTECTION_CONFIG = {
    "required_status_checks": {
        "strict": True,
        "contexts": [
            "Code Quality & Security",
            "Backend Tests", 
            "Frontend Tests",
            "Integration Tests",
            "Database Migration Tests"
        ]
    },
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "required_approving_review_count": 2,
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": True,
        "require_last_push_approval": False
    },
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False
}

# Required environment variables for CI/CD
REQUIRED_SECRETS = [
    "CONTAINER_REGISTRY",
    "REGISTRY_USERNAME", 
    "REGISTRY_PASSWORD",
    "DEPLOY_KEY",
    "DEPLOY_HOST",
    "DEPLOY_USER",
    "SLACK_WEBHOOK",
    "CODECOV_TOKEN",
    "SENTRY_DSN",
    "GMAIL_CLIENT_ID",
    "GMAIL_CLIENT_SECRET"
]

# Quality gates configuration  
QUALITY_GATES = {
    "code_coverage": {
        "minimum_backend": 80,
        "minimum_frontend": 75,
        "minimum_integration": 60
    },
    "security": {
        "max_high_vulnerabilities": 0,
        "max_medium_vulnerabilities": 5
    },
    "performance": {
        "max_response_time_95th": "2s",
        "max_memory_usage": "512MB",
        "max_cpu_usage": "70%"
    },
    "code_quality": {
        "max_complexity": 10,
        "min_maintainability": "B",
        "max_duplication": "5%"
    }
}