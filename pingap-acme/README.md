# Pingap ACME

ACME client for Pingap.

## Overview

Pingap ACME is a client implementation of the Automated Certificate Management Environment (ACME) protocol, designed to automate the process of obtaining and managing SSL/TLS certificates for Pingap services.

## Features

- Automated SSL/TLS certificate issuance and renewal
- Support for Let's Encrypt Certificate Authorities
- Automatic key pair generation

## Dns Api config

- `aliyun`: https://alidns.aliyuncs.com?access_key_id=xxx&access_key_secret=xxx
- `cloudflare`: https://api.cloudflare.com?token=xxx
- `huawei`: https://dns.{region}.myhuaweicloud.com?access_key_id=xxx&access_key_secret=xxx
- `tencent`: https://dnspod.tencentcloudapi.com?access_key_id=xxx&access_key_secret=xxx