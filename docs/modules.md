# Pingap Modules 

```mermaid
graph TD
    acme --> certificate
    acme --> config
    acme --> core
    acme --> util
    acme --> webhook

    cache --> config
    cache --> core
    cache --> util

    certificate --> config
    certificate --> core
    certificate --> util
    certificate --> webhook

    config --> core
    config --> discovery
    config --> util

    discovery --> core
    discovery --> util
    discovery --> webhook

    location --> config
    location --> core
    location --> util

    logger --> core
    logger --> util

    performance --> cache
    performance --> config
    performance --> core
    performance --> location
    performance --> upstream
    performance --> util

    plugin --> cache
    plugin --> config
    plugin --> core
    plugin --> util

    upstream --> config
    upstream --> core
    upstream --> discovery
    upstream --> health
    upstream --> util

    webhook --> core

    pingap --> acme
    pingap --> cache
    pingap --> certificate
    pingap --> config
    pingap --> core
    pingap --> discovery
    pingap --> health
    pingap --> location
    pingap --> logger
    pingap --> otel
    pingap --> performance
    pingap --> plugin
    pingap --> pyroscope
    pingap --> sentry
    pingap --> upstream
    pingap --> util
    pingap --> webhook
```
