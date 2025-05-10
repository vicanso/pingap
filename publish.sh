#!/bin/bash

# 发布顺序按照依赖关系排序
CRATES=(
    "pingap-util"
    "pingap-core"
    "pingap-config"
    "pingap-logger"
    "pingap-certificate"
    "pingap-cache"
    "pingap-location"
    "pingap-upstream"
    "pingap-discovery"
    "pingap-health"
    "pingap-acme"
    "pingap-otel"
    "pingap-performance"
    "pingap-plugin"
    "pingap-pyroscope"
    "pingap-sentry"
    "pingap-webhook"
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
    # 等待一段时间让 crates.io 处理
    sleep 10
done

echo "All crates published successfully!" 