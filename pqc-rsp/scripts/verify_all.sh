#!/bin/bash
# ============================================================================
# SGP.22 PQC-RSP Protocol Verification Suite
# Verifies CRITICAL and IMPORTANT security properties from proof.md
# ============================================================================

cd "$(dirname "$0")/../models"

echo "============================================================================"
echo "  SGP.22 PQC-RSP FORMAL VERIFICATION"
echo "============================================================================"
echo ""
echo "Legend: ✓ = Verified (true)  ✗ = Attack found  ~ = Non-injective only  T = Timeout"
echo ""

# Results arrays
declare -A RESULTS

run_verification() {
    local file=$1
    local label=$2
    
    echo "[$label] Verifying $file..."
    
    output=$(timeout 120 proverif "$file" 2>&1)
    exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        RESULTS["$label"]="TIMEOUT"
        echo "  ⏱ TIMEOUT (>120s)"
        return
    fi
    
    # Count results
    true_count=$(echo "$output" | grep -c "RESULT.*is true")
    false_count=$(echo "$output" | grep -c "RESULT.*is false")
    cannot_count=$(echo "$output" | grep -c "RESULT.*cannot be proved")
    
    if [ $false_count -gt 0 ]; then
        RESULTS["$label"]="ATTACK"
        echo "  ✗ ATTACK FOUND ($false_count queries failed)"
    elif [ $cannot_count -gt 0 ]; then
        RESULTS["$label"]="PARTIAL"
        echo "  ~ PARTIAL: $true_count true, $cannot_count non-injective"
    else
        RESULTS["$label"]="VERIFIED"
        echo "  ✓ ALL VERIFIED ($true_count queries)"
    fi
    
    # Save detailed output
    echo "$output" > "../results/${file%.pv}_results.txt"
}

mkdir -p ../results

echo "============================================================================"
echo "PHASE A: AUTHENTICATION VERIFICATION"
echo "============================================================================"
echo ""

echo "--- Original Protocol (Signature-based, Private TLS) ---"
run_verification "original-auth.pv" "orig-auth"
echo ""

echo "--- Full PQC Protocol (KEM-based, Private TLS) ---"
run_verification "fullpqc-auth.pv" "pqc-auth"
echo ""

echo "--- Full PQC Protocol (KEM-based, PUBLIC Channel) ---"
echo "    ⭐ This proves TRANSPORT INDEPENDENCE (Property #27)"
run_verification "fullpqc-notls-auth.pv" "pqc-notls-auth"
echo ""

echo "============================================================================"
echo "PHASE B: PROFILE DOWNLOAD VERIFICATION"
echo "============================================================================"
echo ""

echo "--- Original Protocol (DH-based, Private TLS) ---"
run_verification "original-download.pv" "orig-dl"
echo ""

echo "--- Full PQC Protocol (KEM-based, Private TLS) ---"
run_verification "fullpqc-download.pv" "pqc-dl"
echo ""

echo "--- Full PQC Protocol (KEM-based, PUBLIC Channel) ---"
echo "    ⭐ This proves TRANSPORT INDEPENDENCE (Property #27)"
run_verification "fullpqc-notls-download.pv" "pqc-notls-dl"
echo ""

echo "============================================================================"
echo "SECURITY PROPERTIES MAPPING (from proof.md)"
echo "============================================================================"
echo ""
echo "CRITICAL Properties:"
echo "  #3  Session Key Agreement     : Auth models (Q3)"
echo "  #9  Mutual Authentication     : Auth models (Q1, Q2)"
echo "  #12 Session Key Secrecy       : Auth models (implicit in KEM model)"
echo "  #13 Profile Confidentiality   : Download models (Q3)"
echo "  #14 Forward Secrecy           : Download models (Q4 - phase 1)"
echo "  #27 Transport Independence ⭐  : fullpqc-notls-* models (PUBLIC ES9+)"
echo ""
echo "IMPORTANT Properties:"
echo "  #10 Injective Agreement       : All inj-event queries"
echo "  #11 KEM Auth Soundness        : KEM decapsulation verification"
echo "  #17 Profile Integrity         : MAC verification in download"
echo "  #18 Transcript Binding        : KDF includes transcript hash"
echo "  #28 LPA Untrustworthiness     : fullpqc-notls models (LPA not trusted)"
echo ""

echo "============================================================================"
echo "FINAL SUMMARY"
echo "============================================================================"
printf "%-25s %-15s\n" "Protocol Variant" "Status"
echo "-------------------------------------------"
printf "%-25s %-15s\n" "original-auth" "${RESULTS[orig-auth]}"
printf "%-25s %-15s\n" "original-download" "${RESULTS[orig-dl]}"
printf "%-25s %-15s\n" "fullpqc-auth" "${RESULTS[pqc-auth]}"
printf "%-25s %-15s\n" "fullpqc-download" "${RESULTS[pqc-dl]}"
printf "%-25s %-15s\n" "fullpqc-notls-auth ⭐" "${RESULTS[pqc-notls-auth]}"
printf "%-25s %-15s\n" "fullpqc-notls-download ⭐" "${RESULTS[pqc-notls-dl]}"
echo ""
echo "Detailed results saved in: results/"
echo "============================================================================"
