# Pingap Modules 

```mermaid
graph TD
    acme --> certificate
    acme --> config
    acme --> http-extra
    acme --> service
    acme --> state
    acme --> util
    acme --> webhook

    cache --> config
    cache --> service
    cache --> util

    certificate --> config
    certificate --> service
    certificate --> util
    certificate --> webhook

    config --> discovery
    config --> util

    discovery --> util
    discovery --> webhook

    health --> util
    health --> webhook

    http-extra --> util

    limit --> util

    location --> config
    location --> http-extra
    location --> util

    logger --> config
    logger --> location
    logger --> service
    logger --> state
    logger --> util

    performance --> cache
    performance --> config
    performance --> location
    performance --> service
    performance --> state
    performance --> upstream
    performance --> util

    plugin --> cache
    plugin --> config
    plugin --> http-extra
    plugin --> state
    plugin --> util

    state --> config
    state --> location
    state --> upstream
    state --> util

    upstream --> config
    upstream --> discovery
    upstream --> health
    upstream --> service
    upstream --> util

    webhook --> util

    pingap --> acme
    pingap --> cache
    pingap --> certificate
    pingap --> config
    pingap --> discovery
    pingap --> health
    pingap --> http-extra
    pingap --> limit
    pingap --> location
    pingap --> logger
    pingap --> otel
    pingap --> performance
    pingap --> plugin
    pingap --> pyroscope
    pingap --> sentry
    pingap --> service
    pingap --> state
    pingap --> upstream
    pingap --> util
    pingap --> webhook
```
