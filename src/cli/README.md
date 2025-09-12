# PhishNet CLI Documentation

## Overview

The PhishNet CLI provides a unified command-line interface for all PhishNet operations. This replaces scattered `if __name__ == '__main__'` blocks throughout the codebase with a centralized, well-organized CLI structure.

## Usage

```bash
# General usage
python phishnet-cli.py [command] [subcommand] [options]

# Show help
python phishnet-cli.py --help
python phishnet-cli.py [command] --help
```

## Available Commands

### Setup Commands
Initialize and configure PhishNet components:

```bash
# Initialize database schema and sample data
python phishnet-cli.py setup database

# Setup Phase 1: Core backbone infrastructure  
python phishnet-cli.py setup backbone

# Setup Phase 2: Email processing domain
python phishnet-cli.py setup emails

# Setup Phase 3: Link analysis domain
python phishnet-cli.py setup links
```

### Demo Commands
Run demonstrations of PhishNet features:

```bash
# Run sandbox analysis demonstration
python phishnet-cli.py demo sandbox

# Run enhanced security features demonstration  
python phishnet-cli.py demo security
```

### Test Commands
Execute test suites with various options:

```bash
# Run specific test types
python phishnet-cli.py test --unit           # Unit tests only
python phishnet-cli.py test --integration    # Integration tests only
python phishnet-cli.py test --api           # API tests only

# Quality assurance
python phishnet-cli.py test --lint          # Code linting
python phishnet-cli.py test --coverage      # Generate coverage report
python phishnet-cli.py test --security      # Security scanning
python phishnet-cli.py test --performance   # Performance testing

# Maintenance
python phishnet-cli.py test --cleanup       # Clean test artifacts
python phishnet-cli.py test --ci            # Complete CI test suite

# Combine options
python phishnet-cli.py test --unit --coverage --lint
```

### Server Command
Start the PhishNet API server:

```bash
# Start with defaults (localhost:8000)
python phishnet-cli.py server

# Custom configuration
python phishnet-cli.py server --host 0.0.0.0 --port 8080 --reload
python phishnet-cli.py server --log-level debug
```

### System Commands

```bash
# Validate application configuration
python phishnet-cli.py config

# Run comprehensive health checks
python phishnet-cli.py health
```

## Migration from Old Scripts

### Before (scattered main blocks):
```bash
# Old way - multiple separate scripts
python scripts/init_db.py
python scripts/phase1_backbone.py  
python app/core/sandbox.py         # Had example in main block
python test/run_tests.py --coverage
```

### After (unified CLI):
```bash
# New way - unified interface
python phishnet-cli.py setup database
python phishnet-cli.py setup backbone
python phishnet-cli.py demo sandbox
python phishnet-cli.py test --coverage
```

## Benefits

1. **Consistency**: All commands follow the same pattern and help structure
2. **Discoverability**: `--help` at any level shows available options
3. **Organization**: Related commands are grouped together logically  
4. **Extensibility**: Easy to add new commands and subcommands
5. **Maintenance**: Single place to manage all CLI interactions

## Implementation Details

- **Location**: `src/cli/phishnet.py` (main implementation)
- **Entry Point**: `phishnet-cli.py` (project root convenience script)
- **Architecture**: Uses `argparse` with subparsers for hierarchical commands
- **Async Support**: Handles both sync and async operations seamlessly
- **Error Handling**: Consistent error reporting and exit codes

## Future Enhancements

The CLI framework is designed to easily accommodate:

- Configuration management (Task 9)
- Health check system (Task 10)
- Additional demo scenarios
- Enhanced logging and debugging options
- Plugin system for custom commands
