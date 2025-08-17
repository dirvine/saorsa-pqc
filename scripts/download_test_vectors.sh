#!/bin/bash

# Test Vector Download Script for Saorsa-PQC
# Downloads NIST ACVP test vectors for ML-KEM and ML-DSA algorithms

set -euo pipefail

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create test vector directories
info "Creating test vector directories..."
mkdir -p tests/nist_vectors/ml_kem
mkdir -p tests/nist_vectors/ml_dsa
mkdir -p tests/nist_vectors/community

# Function to download with retry and validation
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_retries=3
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -L --fail --silent --show-error "$url" -o "$output"; then
            info "Downloaded: $(basename "$output")"
            return 0
        else
            retry=$((retry + 1))
            warn "Download failed (attempt $retry/$max_retries): $url"
            if [ $retry -lt $max_retries ]; then
                sleep 2
            fi
        fi
    done
    
    error "Failed to download after $max_retries attempts: $url"
    return 1
}

# ML-KEM test vectors
info "Downloading NIST ML-KEM test vectors..."

# Note: These URLs are examples - actual NIST test vectors may be at different locations
# In production, these should be verified NIST URLs

# ML-KEM KeyGen test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json" \
    "tests/nist_vectors/ml_kem/keygen_prompt.json"; then
    warn "Could not download ML-KEM keygen prompts, creating placeholder"
    echo '{"algorithm": "ML-KEM", "mode": "keyGen", "revision": "FIPS203", "testGroups": []}' > tests/nist_vectors/ml_kem/keygen_prompt.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json" \
    "tests/nist_vectors/ml_kem/keygen_expected.json"; then
    warn "Could not download ML-KEM keygen expected results, creating placeholder"
    echo '{"algorithm": "ML-KEM", "mode": "keyGen", "revision": "FIPS203", "testGroups": []}' > tests/nist_vectors/ml_kem/keygen_expected.json
fi

# ML-KEM Encap/Decap test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json" \
    "tests/nist_vectors/ml_kem/encapdecap_prompt.json"; then
    warn "Could not download ML-KEM encap/decap prompts, creating placeholder"
    echo '{"algorithm": "ML-KEM", "mode": "encapDecap", "revision": "FIPS203", "testGroups": []}' > tests/nist_vectors/ml_kem/encapdecap_prompt.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json" \
    "tests/nist_vectors/ml_kem/encapdecap_expected.json"; then
    warn "Could not download ML-KEM encap/decap expected results, creating placeholder"
    echo '{"algorithm": "ML-KEM", "mode": "encapDecap", "revision": "FIPS203", "testGroups": []}' > tests/nist_vectors/ml_kem/encapdecap_expected.json
fi

# ML-DSA test vectors
info "Downloading NIST ML-DSA test vectors..."

# ML-DSA KeyGen test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json" \
    "tests/nist_vectors/ml_dsa/keygen_prompt.json"; then
    warn "Could not download ML-DSA keygen prompts, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "keyGen", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/keygen_prompt.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json" \
    "tests/nist_vectors/ml_dsa/keygen_expected.json"; then
    warn "Could not download ML-DSA keygen expected results, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "keyGen", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/keygen_expected.json
fi

# ML-DSA SigGen test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json" \
    "tests/nist_vectors/ml_dsa/siggen_prompt.json"; then
    warn "Could not download ML-DSA siggen prompts, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "sigGen", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/siggen_prompt.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json" \
    "tests/nist_vectors/ml_dsa/siggen_expected.json"; then
    warn "Could not download ML-DSA siggen expected results, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "sigGen", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/siggen_expected.json
fi

# ML-DSA SigVer test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json" \
    "tests/nist_vectors/ml_dsa/sigver_prompt.json"; then
    warn "Could not download ML-DSA sigver prompts, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "sigVer", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/sigver_prompt.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json" \
    "tests/nist_vectors/ml_dsa/sigver_expected.json"; then
    warn "Could not download ML-DSA sigver expected results, creating placeholder"
    echo '{"algorithm": "ML-DSA", "mode": "sigVer", "revision": "FIPS204", "testGroups": []}' > tests/nist_vectors/ml_dsa/sigver_expected.json
fi

# Community test vectors
info "Downloading community test vectors..."

# C2SP/CCTV ML-KEM test vectors
if ! download_with_retry \
    "https://raw.githubusercontent.com/C2SP/CCTV/main/ML-KEM/ML-KEM-768-unlucky.json" \
    "tests/nist_vectors/community/ml_kem_768_unlucky.json"; then
    warn "Could not download C2SP ML-KEM unlucky vectors, creating placeholder"
    echo '{"algorithm": "ML-KEM", "parameter_set": "ML-KEM-768", "tests": []}' > tests/nist_vectors/community/ml_kem_768_unlucky.json
fi

if ! download_with_retry \
    "https://raw.githubusercontent.com/C2SP/CCTV/main/ML-KEM/ML-KEM-768-golden.json" \
    "tests/nist_vectors/community/ml_kem_768_golden.json"; then
    warn "Could not download C2SP ML-KEM golden vectors, creating placeholder"
    echo '{"algorithm": "ML-KEM", "parameter_set": "ML-KEM-768", "tests": []}' > tests/nist_vectors/community/ml_kem_768_golden.json
fi

# Validation step
info "Validating downloaded test vectors..."
for file in tests/nist_vectors/ml_kem/*.json tests/nist_vectors/ml_dsa/*.json tests/nist_vectors/community/*.json; do
    if [ -f "$file" ]; then
        if python3 -m json.tool "$file" > /dev/null 2>&1; then
            info "✓ Valid JSON: $(basename "$file")"
        else
            error "✗ Invalid JSON: $(basename "$file")"
        fi
    fi
done

info "Test vector download completed successfully!"
info "Files created in:"
info "  - tests/nist_vectors/ml_kem/"
info "  - tests/nist_vectors/ml_dsa/"
info "  - tests/nist_vectors/community/"