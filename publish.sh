#!/bin/bash

# publish order
CRATES=(
    "pingap-util"
    "pingap-core"
    "pingap-discovery"
    "pingap-config"
    "pingap-logger"
    "pingap-certificate"
    "pingap-cache"
    "pingap-location"
    "pingap-health"
    "pingap-upstream"
    "pingap-acme"
    "pingap-otel"
    "pingap-performance"
    "pingap-plugin"
    "pingap-pyroscope"
    "pingap-sentry"
    "pingap-webhook"
    "pingap-imageoptim"
)

for crate in "${CRATES[@]}"; do
    echo "Publishing $crate..."
    cd "$crate"
    cargo publish --registry crates-io 
    if [ $? -ne 0 ]; then
        echo "Failed to publish $crate"
        exit 1
    fi
    cd ..
    # wait for crates.io to process
    sleep 60
done

echo "All crates published successfully!" 