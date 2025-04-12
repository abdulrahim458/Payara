#!/bin/bash

set -euo pipefail

echo "🔍 Detecting Java trust store path..."

# Dynamically detect truststore path
if [ -f "${JAVA_HOME}/jre/lib/security/cacerts" ]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/jre/lib/security/cacerts"
elif [ -f "${JAVA_HOME}/lib/security/cacerts" ]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/lib/security/cacerts"
else
    echo "❌ Java truststore not found under JAVA_HOME."
    exit 1
fi

echo "📌 Detected Trust Store: $JAVA_TRUSTSTORE"

# Convert to temporary JKS for manipulation
TEMP_JKS="temp-cacerts.jks"
echo "🔄 Converting to temporary JKS..."
keytool -importkeystore -srckeystore "$JAVA_TRUSTSTORE" -srcstoretype PKCS12 -srcstorepass changeit \
        -destkeystore "$TEMP_JKS" -deststoretype JKS -deststorepass changeit -noprompt > /dev/null

# Remove expiring certs (within 90 days)
echo "🧹 Removing certificates expiring within 90 days..."
expired_aliases=()
while IFS= read -r line; do
    if [[ "$line" == Alias\ name:* ]]; then
        alias=$(echo "$line" | cut -d':' -f2- | xargs)
    elif [[ "$line" == Valid\ from:* ]]; then
        until_date=$(echo "$line" | grep -oP 'until: \K.*')
        if [[ -n "$until_date" ]]; then
            until_epoch=$(date -d "$until_date" +%s || true)
            now_epoch=$(date +%s)
            threshold_epoch=$((now_epoch + 90*24*3600))
            if [[ "$until_epoch" -lt "$threshold_epoch" ]]; then
                expired_aliases+=("$alias")
            fi
        fi
    fi
done < <(keytool -list -v -keystore "$TEMP_JKS" -storepass changeit)

for alias in "${expired_aliases[@]}"; do
    echo "🗑️ Removing: $alias"
    keytool -delete -alias "$alias" -keystore "$TEMP_JKS" -storepass changeit
done

# Download Mozilla certs
echo "🌐 Downloading Mozilla CA certificates..."
CA_BUNDLE="/tmp/ca-certificates.crt"
curl -fsSL -o "$CA_BUNDLE" https://curl.se/ca/cacert.pem

# Split certs into files
csplit -s -f cert- "$CA_BUNDLE" '/-----BEGIN CERTIFICATE-----/' '{*}' || true

# Import certs avoiding duplicates
echo "➕ Importing Mozilla certs (avoiding duplicates)..."
for cert in cert-*; do
    fingerprint=$(openssl x509 -noout -in "$cert" -fingerprint -sha256 2>/dev/null | cut -d'=' -f2 | tr -d ':')
    if [ -n "$fingerprint" ]; then
        exists=$(keytool -list -keystore "$TEMP_JKS" -storepass changeit -v | grep -i "$fingerprint" || true)
        if [ -z "$exists" ]; then
            alias="mozilla-$(basename $cert)"
            keytool -importcert -keystore "$TEMP_JKS" -storepass changeit -noprompt -file "$cert" -alias "$alias"
        fi
    fi
done

# Convert back to PKCS12
FINAL_TRUSTSTORE="cacerts.p12"
echo "🔁 Converting JKS to PKCS12 truststore..."
keytool -importkeystore -srckeystore "$TEMP_JKS" -srcstoretype JKS -srcstorepass changeit \
        -destkeystore "$FINAL_TRUSTSTORE" -deststoretype PKCS12 -deststorepass changeit -noprompt > /dev/null

# Replace in Payara codebase
echo "📁 Copying to Payara truststore locations..."
PAYARA_P12_PATHS=(
  ".../src/main/resources/config/cacerts.p12"
)

for path in "${PAYARA_P12_PATHS[@]}"; do
    if [ -f "$path" ]; then
        cp -f "$FINAL_TRUSTSTORE" "$path"
        echo "✅ Replaced: $path"
    else
        echo "⚠️ Skipped (not found): $path"
    fi
done

# Final check
echo "🔎 Previewing trust store entries:"
keytool -list -keystore "$FINAL_TRUSTSTORE" -storepass changeit | head -n 15

echo "🏁 Trust store update complete."