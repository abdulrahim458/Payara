#!/bin/bash

set -euo pipefail

echo "🔍 Detecting Java trust store path..."

# Determine Java trust store path in Jenkins AMI (Linux)
if [ -f "${JAVA_HOME}/jre/lib/security/cacerts" ]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/jre/lib/security/cacerts"
elif [ -f "${JAVA_HOME}/lib/security/cacerts" ]; then
    JAVA_TRUSTSTORE="${JAVA_HOME}/lib/security/cacerts"
else
    echo "❌ ERROR: Unable to find Java trust store. Exiting..."
    exit 1
fi

echo "📌 Detected Trust Store: $JAVA_TRUSTSTORE"

echo "🧹 Removing certificates expiring within 90 days..."

# Convert PKCS12 to JKS temporarily
TEMP_JKS="temp-cacerts.jks"
keytool -importkeystore \
    -srckeystore "$JAVA_TRUSTSTORE" \
    -srcstorepass "changeit" \
    -destkeystore "$TEMP_JKS" \
    -deststorepass "changeit" \
    -deststoretype JKS \
    -noprompt

# Parse expiry dates
keytool -list -v -keystore "$TEMP_JKS" -storepass changeit | awk '
BEGIN { FS="\n"; RS=""; now = systime(); }
{
    for (i = 1; i <= NF; i++) {
        if ($i ~ /Alias name:/) alias = gensub(/.*: /, "", "g", $i);
        if ($i ~ /Valid from:/) {
            match($i, /until: (.*)/, exp);
            cmd = "date -d \"" exp[1] "\" +%s";
            cmd | getline exp_ts;
            close(cmd);
            if (exp_ts < now + 90*24*3600) {
                print alias;
            }
        }
    }
}
' > expired_aliases.txt

# Delete expired certs
if [ -s expired_aliases.txt ]; then
    while read -r alias; do
        echo "🗑️ Removing: $alias"
        keytool -delete -alias "$alias" -keystore "$TEMP_JKS" -storepass changeit -noprompt || true
    done < expired_aliases.txt
    echo "✅ Removed expired certificates."
else
    echo "✅ No certificates expiring within 90 days."
fi

# Clean up
rm -f expired_aliases.txt

# Download and import Mozilla CA certs
echo "🌐 Downloading Mozilla CA bundle..."
CA_BUNDLE="/tmp/cacert.pem"
curl -fsSL -o "$CA_BUNDLE" https://curl.se/ca/cacert.pem

echo "➕ Importing Mozilla certs (avoiding duplicates)..."
csplit -s -z -f cert- "$CA_BUNDLE" '/-----BEGIN CERTIFICATE-----/' '{*}'

for cert in cert-*; do
    [ -s "$cert" ] || continue
    fingerprint=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | cut -d'=' -f2 | tr -d ':')
    alias="imported-$fingerprint"

    # Check if alias exists
    if keytool -list -keystore "$TEMP_JKS" -storepass changeit -alias "$alias" > /dev/null 2>&1; then
        echo "⏩ Skipping duplicate cert: $alias"
        continue
    fi

    keytool -importcert -keystore "$TEMP_JKS" -storepass changeit -noprompt -alias "$alias" -file "$cert" || true
done

# Convert JKS back to PKCS12
keytool -importkeystore \
    -srckeystore "$TEMP_JKS" \
    -srcstorepass "changeit" \
    -destkeystore "$JAVA_TRUSTSTORE" \
    -deststorepass "changeit" \
    -deststoretype pkcs12 \
    -noprompt

# Optional: Copy to Payara truststore paths
PAYARA_PATHS=(
    "../src/main/resources/config/cacerts.p12"
    "nucleus/security/core/src/main/resources/config/cacerts.p12"
)

echo "📁 Copying updated truststore to Payara config paths..."
for path in "${PAYARA_PATHS[@]}"; do
    if [ -f "$path" ]; then
        cp -f "$JAVA_TRUSTSTORE" "$path"
        echo "✅ Copied to: $path"
    else
        echo "⚠️ Skipped missing path: $path"
    fi
done

# Preview
echo "🔎 Previewing trust store entries:"
keytool -list -keystore "$JAVA_TRUSTSTORE" -storepass changeit | head -n 10

# Final cleanup
rm -f cert-*

echo "🏁 Trust store update complete."