#!/bin/bash

set -euo pipefail

TRUSTSTORE_PASSWORD="changeit"

echo "🔍 Detecting Java trust store path..."

# Dynamically detect .p12 Java truststore path in Jenkins AMI
if [[ -f "${JAVA_HOME}/jre/lib/security/cacerts" ]]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/jre/lib/security/cacerts"
elif [[ -f "${JAVA_HOME}/lib/security/cacerts" ]]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/lib/security/cacerts"
else
    echo "❌ Could not locate Java truststore under JAVA_HOME."
    exit 1
fi

echo "📌 Detected Trust Store: $JAVA_TRUSTSTORE"

# Copy truststore to temp p12 file for manipulation
TEMP_TRUSTSTORE="temp-cacerts.p12"
cp "$JAVA_TRUSTSTORE" "$TEMP_TRUSTSTORE"

# === Remove certificates expiring within 90 days ===
echo "🧹 Removing certificates expiring within 90 days..."

keytool -list -v -keystore "$TEMP_TRUSTSTORE" -storepass "$TRUSTSTORE_PASSWORD" -storetype PKCS12 > certs-info.txt 2>/dev/null

mapfile -t expired_aliases < <(
    awk '
        /Alias name:/ { alias=$3 }
        /Valid from:/ {
            match($0, /until: (.*)/, exp)
            cmd = "date -d \"" exp[1] "\" +%s"
            cmd | getline expire_ts
            close(cmd)
            now = systime()
            if (expire_ts < now + 90*24*3600) {
                print alias
            }
        }
    ' certs-info.txt
)

for alias in "${expired_aliases[@]:-}"; do
    echo "🗑️ Removing: $alias"
    keytool -delete -alias "$alias" -keystore "$TEMP_TRUSTSTORE" -storepass "$TRUSTSTORE_PASSWORD" -storetype PKCS12 || true
done

# === Import Mozilla CA Certs (avoiding duplicates) ===
echo "🌐 Downloading Mozilla CA certificates..."
curl -sS -o mozilla.pem https://curl.se/ca/cacert.pem

csplit -sz -f cert- mozilla.pem '/-----BEGIN CERTIFICATE-----/' '{*}' || true

echo "➕ Importing Mozilla certs (no duplicates)..."
for cert in cert-*; do
    if openssl x509 -in "$cert" -noout > /dev/null 2>&1; then
        fingerprint=$(openssl x509 -noout -in "$cert" -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':')
        if [ -n "$fingerprint" ]; then
            exists=$(keytool -list -keystore "$TEMP_TRUSTSTORE" -storepass "$TRUSTSTORE_PASSWORD" -storetype PKCS12 -v | grep -i "$fingerprint" || true)
            if [ -z "$exists" ]; then
                alias="mozilla-$(basename "$cert")"
                keytool -importcert -keystore "$TEMP_TRUSTSTORE" -storepass "$TRUSTSTORE_PASSWORD" -storetype PKCS12 -noprompt -file "$cert" -alias "$alias" || echo "⚠️ Failed to import $cert"
            fi
        fi
    else
        echo "⚠️ Skipping invalid cert: $cert"
    fi
done

# Cleanup
rm -f cert-* mozilla.pem certs-info.txt

# === Replace original truststore ===
cp -f "$TEMP_TRUSTSTORE" "$JAVA_TRUSTSTORE"
echo "✅ Updated truststore at: $JAVA_TRUSTSTORE"

# === Copy to Payara code paths if they exist ===
echo "📁 Copying to Payara truststore paths (if applicable)..."
PAYARA_PATHS=(
    ".../src/main/resources/config/cacerts.p12"
)

for path in "${PAYARA_PATHS[@]}"; do
    if [ -f "$path" ]; then
        cp -f "$TEMP_TRUSTSTORE" "$path"
        echo "✅ Copied to: $path"
    else
        echo "⚠️ Skipped: $path not found"
    fi
done

# === Preview ===
echo "🔎 Final truststore entries:"
keytool -list -keystore "$JAVA_TRUSTSTORE" -storepass "$TRUSTSTORE_PASSWORD" -storetype PKCS12 | head -n 10

echo "🏁 Trust store update complete."