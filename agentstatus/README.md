# Agent Deployment Report

Currently composes CEF event, might change to ordinary syslog or some other format.

Uses [cefevent](https://github.com/kamushadenes/cefevent.git) by kamushadenes.

## Configure

Configure by populating the `config.yml`

```yaml
deepsecurity:
  # Deep Security DNS name or IP with port
  server: 3.239.104.249:4119
  # Deep Security as a Service
  # server: app.deepsecurity.trendmicro.com:443
  # Workload Security
  # server: workload.trend-us-1.cloudone.trendmicro.com:443

  # Type is 'ds' or 'ws'
  type: ds

  # API Key
  api_key: "DS/WS API Key"

  # API Keys in multi tenant mode
  # If defined, they overwrite api_key
  api_keys:
    tenant0: "DS API Key for tenant0"
    tenant1: "DS API Key for tenant1"
    tenant2: "DS API Key for tenant2"

  # Enable or disable TLS Verify
  tls_verify: False

# Log receiver
logger:
  host: 192.168.1.122
  port: 50514
  facility: local3
```

Ensure to have the requirements satisfied

```sh
pip3 install -r requirements.txt
```

Run by

```sh
python3 agentstatus.py
```

## Quickly start a Splunk

`docker-compose.yaml`:

```yaml
version: "3.6"

services:
  splunk:
    image: ${SPLUNK_IMAGE:-splunk/splunk:8.2}
    container_name: splunk
    environment:
      - SPLUNK_START_ARGS=--accept-license
      - SPLUNK_PASSWORD=<PASSWORD>
      - SPLUNK_ADD=tcp 1514
      - TZ=Europe/Berlin
      - PHP_TZ=Europe/Berlin
    volumes:
      - opt-splunk-etc:/opt/splunk/etc
      - opt-splunk-var:/opt/splunk/var
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
    ports:
      - 1514:1514
      - 8880:8000
      - 50514:50514/udp

volumes:
  opt-splunk-etc:
  opt-splunk-var:
```

## Configure Splunk

Basic settings:

- Install the CEF Extraction Plug-In
- Input Settings
  - UDP Port: 50514
  - Source type: cefevents
  - App context: cefutils
  - Host: DNS
  - Index: default
