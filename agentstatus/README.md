# Agent Deployment Report

Configure by populating the `config.yml`

```yaml

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

- Install the CEF Extraction Plug-In
- Input Settings
  - UDP Port: 50514
  - Source type: cefevents
  - App context: cefutils
  - Host: DNS
  - Index: default
