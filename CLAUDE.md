# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

strongSwan is an OpenSource IPsec-based VPN solution implementing IKEv1 and IKEv2 protocols. It provides secure network communications through the `charon` IKE daemon and associated tools.

## Build Commands

### Initial Setup (from clean checkout)
```bash
./autogen.sh                    # Generate configure script (requires autoreconf)
./configure [options]           # Configure build (see ./configure --help)
make -j$(nproc)                 # Build
```

### Common Configure Options
```bash
# Minimal build with specific features
./configure --disable-defaults --enable-openssl --enable-pki --enable-swanctl --enable-vici

# Full build with all features (for testing)
./configure --enable-all --disable-android-dns --disable-android-log \
            --disable-kernel-pfroute --disable-keychain --disable-padlock \
            --disable-osx-attr --disable-tkm --disable-svc \
            --disable-kernel-wfp --disable-kernel-iph --disable-winhttp
```

### Running Tests
```bash
make check                      # Run unit tests
make -C src/libstrongswan/tests check  # Run only libstrongswan tests
make -C src/libcharon/tests check      # Run only libcharon tests
```

### Integration Tests
Located in `testing/` directory. Requires KVM environment setup:
```bash
./testing/make-testing          # Build test environment
./testing/start-testing         # Start KVM instances
./testing/do-tests [testnames]  # Run tests (all if no names given)
```

### Coverage Reports
```bash
./configure --enable-coverage
make coverage                   # Runs: cov-reset, check, cov-report
```

## Architecture

### Core Libraries

- **libstrongswan** (`src/libstrongswan/`): Foundation library providing crypto abstractions, ASN.1/X.509 handling, collections, threading, settings, and plugin infrastructure
- **libcharon** (`src/libcharon/`): IKE daemon library implementing IKEv1/IKEv2 protocol state machines, SA management, and kernel interfaces

### Key Subsystems in libstrongswan
- `crypto/`: Cryptographic algorithm abstractions and implementations
- `credentials/`: Certificate and key management
- `plugins/`: Plugin loader and crypto provider plugins
- `threading/`: Thread pool, mutexes, condition variables
- `collections/`: linked_list, hashtable, array implementations
- `settings/`: Configuration file parser (strongswan.conf format)

### Key Subsystems in libcharon
- `sa/`: IKE_SA and CHILD_SA state machines and management
- `encoding/`: IKE message parsing and generation
- `kernel/`: Platform kernel interfaces (netlink, pfkey, pfroute)
- `bus/`: Event bus for daemon notifications
- `config/`: Connection and peer configuration
- `plugins/vici/`: VICI protocol for external control (used by swanctl)

### IKE Daemons
- **charon** (`src/charon/`): Main IKE daemon
- **charon-systemd** (`src/charon-systemd/`): systemd-integrated variant
- **charon-cmd** (`src/charon-cmd/`): Command-line IKE client

### Configuration Tools
- **swanctl** (`src/swanctl/`): Modern configuration tool using VICI protocol
- **starter/stroke** (`src/starter/`, `src/stroke/`): Legacy configuration (deprecated)
- **pki** (`src/pki/`): Certificate and key generation utility

### Plugin System
Plugins are loaded dynamically from `${ipseclibdir}/plugins/`. Each plugin registers with libstrongswan's plugin loader and provides crypto implementations, credential backends, or daemon extensions.

## Configuration Files

- `/etc/strongswan.conf`: Daemon configuration (plugin loading, logging, etc.)
- `/etc/swanctl/swanctl.conf`: Connection definitions (modern)
- `/etc/swanctl/x509*/`, `/etc/swanctl/private/`: Credentials

## VICI Protocol

The Versatile IKE Configuration Interface (VICI) at `src/libcharon/plugins/vici/` is the primary control interface. See `src/libcharon/plugins/vici/README.md` for protocol documentation.

Client bindings available in:
- C: libvici
- Python: `src/libcharon/plugins/vici/python/`
- Ruby: `src/libcharon/plugins/vici/ruby/`
- Perl: `src/libcharon/plugins/vici/perl/`

## Docker-Based Build and Tests

The `docker-tests/` directory provides a containerized test environment for validating changes.

### Build and Run All Tests
```bash
cd docker-tests
./run-tests.sh --rebuild    # Rebuild images with current source and run all tests
./run-tests.sh              # Run tests without rebuilding (uses cached images)
```

### Run Specific Tests
```bash
./run-tests.sh test_1_ike_compatibility      # Run single test
./run-tests.sh test_1 test_2                 # Run multiple tests
```

### Interactive Testing
```bash
# Start containers
docker compose up -d

# Execute commands in containers
docker exec moon swanctl --list-sas
docker exec moon swanctl --validate-conns
docker exec sun swanctl --list-sas

# View logs
docker exec moon cat /var/log/charon.log
```

### Before Committing
**Always rebuild and run tests before committing changes:**
```bash
cd docker-tests
./run-tests.sh --rebuild    # Must pass: "All tests passed!"
```

## Code Style

Follow the [strongSwan developer documentation](https://docs.strongswan.org/docs/latest/devs/devs.html) for code style and contribution requirements.
