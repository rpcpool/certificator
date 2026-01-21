#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_DIR="/tmp/haproxy-test"
CERTS_DIR="/tmp/haproxy-certs"

# PIDs for cleanup
HAPROXY_PID=""
DATAPLANEAPI_PID=""

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    log_info "Cleaning up..."

    if [[ -n "${DATAPLANEAPI_PID}" ]] && kill -0 "${DATAPLANEAPI_PID}" 2>/dev/null; then
        log_info "Stopping Data Plane API (PID: ${DATAPLANEAPI_PID})..."
        kill "${DATAPLANEAPI_PID}" 2>/dev/null || true
        wait "${DATAPLANEAPI_PID}" 2>/dev/null || true
    fi

    if [[ -n "${HAPROXY_PID}" ]] && kill -0 "${HAPROXY_PID}" 2>/dev/null; then
        log_info "Stopping HAProxy (PID: ${HAPROXY_PID})..."
        kill "${HAPROXY_PID}" 2>/dev/null || true
        wait "${HAPROXY_PID}" 2>/dev/null || true
    fi

    # Clean up test directories
    rm -rf "${TEST_DIR}" "${CERTS_DIR}" 2>/dev/null || true
    rm -f /tmp/haproxy.sock 2>/dev/null || true

    log_info "Cleanup complete"
}

trap cleanup EXIT

setup_directories() {
    log_info "Setting up test directories..."
    mkdir -p "${TEST_DIR}"/{maps,spoe,spoe-transactions,transactions,general,dataplane,backups}
    mkdir -p "${CERTS_DIR}"
}

generate_test_certificates() {
    log_info "Generating test certificates..."

    # Generate CA
    openssl genrsa -out "${CERTS_DIR}/ca.key" 2048 2>/dev/null
    openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key" \
        -sha256 -days 1 -out "${CERTS_DIR}/ca.crt" \
        -subj "/CN=Test CA" 2>/dev/null

    # Generate test certificates for different domains
    for domain in "example.com" "api.example.com" "test.example.org"; do
        log_info "  Generating certificate for ${domain}..."

        # Generate private key
        openssl genrsa -out "${CERTS_DIR}/${domain}.key" 2048 2>/dev/null

        # Generate CSR
        openssl req -new -key "${CERTS_DIR}/${domain}.key" \
            -out "${CERTS_DIR}/${domain}.csr" \
            -subj "/CN=${domain}" 2>/dev/null

        # Sign with CA
        openssl x509 -req -in "${CERTS_DIR}/${domain}.csr" \
            -CA "${CERTS_DIR}/ca.crt" -CAkey "${CERTS_DIR}/ca.key" \
            -CAcreateserial -out "${CERTS_DIR}/${domain}.crt" \
            -days 1 -sha256 2>/dev/null

        # Create combined PEM file (cert + key) for HAProxy
        cat "${CERTS_DIR}/${domain}.crt" "${CERTS_DIR}/${domain}.key" > "${CERTS_DIR}/${domain}.pem"

        # Clean up intermediate files (HAProxy will try to load .crt files otherwise)
        rm -f "${CERTS_DIR}/${domain}.csr" "${CERTS_DIR}/${domain}.crt" "${CERTS_DIR}/${domain}.key"
    done

    # Also clean up CA files from the certs directory
    rm -f "${CERTS_DIR}/ca.key" "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/ca.srl"

    log_info "Test certificates generated"
}

create_haproxy_config() {
    log_info "Creating HAProxy configuration..."

    cat > "${TEST_DIR}/haproxy.cfg" << EOF
global
    log stdout format raw local0 info
    stats socket /tmp/haproxy.sock mode 660 level admin expose-fd listeners
    stats timeout 30s

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend http_front
    bind *:18080
    default_backend http_back

frontend https_front
    bind *:18443 ssl crt ${CERTS_DIR}/
    default_backend http_back

backend http_back
    server local 127.0.0.1:19999 check
EOF

    log_info "HAProxy configuration created"
}

start_haproxy() {
    log_info "Starting HAProxy..."

    # Start HAProxy with master-worker mode (-W) for runtime API support
    haproxy -W -f "${TEST_DIR}/haproxy.cfg" -D -p "${TEST_DIR}/haproxy.pid"
    sleep 2

    if [[ -f "${TEST_DIR}/haproxy.pid" ]]; then
        HAPROXY_PID=$(cat "${TEST_DIR}/haproxy.pid")
        log_info "HAProxy started (PID: ${HAPROXY_PID})"

        # Verify socket is available
        if [[ -S /tmp/haproxy.sock ]]; then
            log_info "HAProxy socket is available"
        else
            log_warn "HAProxy socket not found at /tmp/haproxy.sock"
        fi
    else
        log_error "Failed to start HAProxy"
        exit 1
    fi
}

start_dataplaneapi() {
    log_info "Starting Data Plane API..."

    # Create Data Plane API configuration file
    cat > "${TEST_DIR}/dataplaneapi.yaml" << EOF
config_version: 2
name: test-dataplaneapi

dataplaneapi:
  host: 127.0.0.1
  port: 5555
  scheme:
    - http
  user:
    - name: admin
      password: adminpwd
      insecure: true
  resources:
    maps_dir: ${TEST_DIR}/maps
    ssl_certs_dir: ${CERTS_DIR}
    spoe_dir: ${TEST_DIR}/spoe
    spoe_transaction_dir: ${TEST_DIR}/spoe-transactions
    general_storage_dir: ${TEST_DIR}/general
    dataplane_storage_dir: ${TEST_DIR}/dataplane
    backups_dir: ${TEST_DIR}/backups
  transaction:
    transaction_dir: ${TEST_DIR}/transactions

haproxy:
  config_file: ${TEST_DIR}/haproxy.cfg
  haproxy_bin: $(which haproxy)
  master_runtime: /tmp/haproxy.sock
  reload:
    reload_delay: 1
    reload_cmd: "echo reload"
    restart_cmd: "echo restart"
    reload_strategy: custom

log:
  log_to: stdout
  log_level: debug
EOF

    # Start the Data Plane API with config file
    dataplaneapi \
        -f "${TEST_DIR}/dataplaneapi.yaml" \
        > "${TEST_DIR}/dataplaneapi.log" 2>&1 &

    DATAPLANEAPI_PID=$!
    log_info "Data Plane API starting (PID: ${DATAPLANEAPI_PID})..."

    # Wait for API to be ready
    local retries=30
    while ! curl -sf http://127.0.0.1:5555/v2/services/haproxy/runtime/info -u admin:adminpwd > /dev/null 2>&1; do
        retries=$((retries - 1))
        if [[ ${retries} -le 0 ]]; then
            log_error "Data Plane API failed to start. Logs:"
            cat "${TEST_DIR}/dataplaneapi.log" || true
            exit 1
        fi
        sleep 0.5
    done

    log_info "Data Plane API is ready"
}

test_list_certs() {
    log_info "Testing 'certificatee list-certs' command..."

    # Set required environment variables
    export HAPROXY_DATAPLANE_API_URLS="http://127.0.0.1:5555"
    export HAPROXY_DATAPLANE_API_USER="admin"
    export HAPROXY_DATAPLANE_API_PASSWORD="adminpwd"
    export HAPROXY_DATAPLANE_API_INSECURE="true"

    # Run list-certs and capture output
    local output
    output=$("${TEST_DIR}/certificatee" list-certs 2>&1) || {
        log_error "certificatee list-certs failed"
        echo "${output}"
        return 1
    }

    log_info "Output from 'certificatee list-certs':"
    echo "${output}"
    echo ""

    # Verify expected certificates are listed
    local expected_certs=("example.com.pem" "api.example.com.pem" "test.example.org.pem")
    local found_count=0

    for cert in "${expected_certs[@]}"; do
        if echo "${output}" | grep -q "${cert}"; then
            log_info "  Found certificate: ${cert}"
            found_count=$((found_count + 1))
        else
            log_warn "  Missing certificate: ${cert}"
        fi
    done

    if [[ ${found_count} -eq ${#expected_certs[@]} ]]; then
        log_info "All expected certificates found!"
        return 0
    else
        log_error "Not all certificates were found (${found_count}/${#expected_certs[@]})"
        return 1
    fi
}

test_list_certs_verbose() {
    log_info "Testing 'certificatee list-certs --verbose' command..."

    # Set required environment variables
    export HAPROXY_DATAPLANE_API_URLS="http://127.0.0.1:5555"
    export HAPROXY_DATAPLANE_API_USER="admin"
    export HAPROXY_DATAPLANE_API_PASSWORD="adminpwd"
    export HAPROXY_DATAPLANE_API_INSECURE="true"

    # Run list-certs with verbose flag
    local output
    output=$("${TEST_DIR}/certificatee" list-certs --verbose 2>&1) || {
        log_error "certificatee list-certs --verbose failed"
        echo "${output}"
        return 1
    }

    log_info "Output from 'certificatee list-certs --verbose':"
    echo "${output}"
    echo ""

    # Verify verbose output contains expected columns
    if echo "${output}" | grep -q "SUBJECT"; then
        log_info "  Verbose output contains SUBJECT column"
    else
        log_error "  Missing SUBJECT column in verbose output"
        return 1
    fi

    if echo "${output}" | grep -q "NOT AFTER"; then
        log_info "  Verbose output contains NOT AFTER column"
    else
        log_error "  Missing NOT AFTER column in verbose output"
        return 1
    fi

    log_info "Verbose output format is correct!"
    return 0
}

test_api_connectivity() {
    log_info "Testing Data Plane API connectivity..."

    # First, check API info endpoint
    log_info "Checking API info..."
    local info
    info=$(curl -s http://127.0.0.1:5555/v2/info -u admin:adminpwd) || true
    echo "API Info: ${info}"

    # Check available endpoints
    log_info "Checking runtime info..."
    local runtime_info
    runtime_info=$(curl -s http://127.0.0.1:5555/v2/services/haproxy/runtime/info -u admin:adminpwd) || true
    echo "Runtime Info: ${runtime_info}"

    # Try to list certificates via storage endpoint
    log_info "Checking storage certs endpoint..."
    local storage_certs
    storage_certs=$(curl -s http://127.0.0.1:5555/v2/services/haproxy/storage/ssl_certificates -u admin:adminpwd) || true
    echo "Storage Certs: ${storage_certs}"

    # Check runtime certs endpoint
    log_info "Checking runtime certs endpoint..."
    local runtime_certs
    runtime_certs=$(curl -s http://127.0.0.1:5555/v2/services/haproxy/runtime/certs -u admin:adminpwd) || true
    echo "Runtime Certs: ${runtime_certs}"

    if echo "${runtime_certs}" | grep -q "404"; then
        log_warn "Runtime certs endpoint returned 404"
        log_info "Data Plane API logs:"
        tail -20 "${TEST_DIR}/dataplaneapi.log" || true
    fi

    log_info "API connectivity test complete"
    return 0
}

main() {
    log_info "=========================================="
    log_info "  Certificatee Integration Tests"
    log_info "=========================================="
    echo ""

    setup_directories
    generate_test_certificates
    create_haproxy_config
    start_haproxy
    start_dataplaneapi
    export BUILD_DIR="${TEST_DIR}"
    build

    echo ""
    log_info "Running tests..."
    echo ""

    local failed=0

    test_api_connectivity || failed=$((failed + 1))
    echo ""

    test_list_certs || failed=$((failed + 1))
    echo ""

    test_list_certs_verbose || failed=$((failed + 1))
    echo ""

    if [[ ${failed} -eq 0 ]]; then
        log_info "=========================================="
        log_info "  All integration tests passed!"
        log_info "=========================================="
        exit 0
    else
        log_error "=========================================="
        log_error "  ${failed} test(s) failed"
        log_error "=========================================="
        exit 1
    fi
}

main "$@"
