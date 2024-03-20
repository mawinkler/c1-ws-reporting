#!/usr/bin/python3
"""
---
module: agentstatus.py

short_description: Queries Cloud One Workload Security or Deep Security for
                   agent deployment and activation related events within a
                   given timeframe.

description:
    - "TODO"

configuration:
    Create a config.yml based on the .sample

usage:
    ./agentdeployment_report.py

options:
    none

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
"""
import ssl
import json
import sys
import socket

import logging
from datetime import datetime
import pprint as pp

import urllib3
import requests
import yaml
from requests import Session
from cefevent.event import CEFEvent

# Globals
# ssl._create_default_https_context = ssl._create_unverified_context

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.getLogger("requests").setLevel(logging.WARNING)
# logging.getLogger("urllib3").setLevel(logging.WARNING)

FACILITY = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

LEVEL = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}

# STATUS_LEVEL_MAPPING = {"active": LEVEL["info"]}

def syslog(message, level=LEVEL["notice"], facility=FACILITY["local3"], host="localhost", port=514) -> None:
    """
    Send syslog UDP packet to given host and port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = "<%d>%s" % (level + facility * 8, message)
    sock.sendto(data.encode(), (host, port))
    sock.close()

def get_paged_computers(headers, host, verify) -> any:
    """Retrieve all computers"""

    paged_computers = []
    id_value, total_num = 0, 0
    max_items = 2000

    session_url = "https://" + host + "/api/computers/search"
    query = {"expand": ["computerStatus", "antiMalware"]}
    # query = {"expand": ["all"]}

    try:
        while True:
            payload = {
                "maxItems": max_items,
                "searchCriteria": [
                    {
                        "idValue": id_value,
                        "idTest": "greater-than",
                    }
                ],
                "sortByObjectID": "true",
            }

            response = requests.post(session_url, headers=headers, params=query, json=payload, verify=verify)
            response.raise_for_status()
            computers = json.loads(response.content)

            num_found = len(computers["computers"])
            if num_found == 0:
                break

            for computer in computers["computers"]:
                paged_computers.append(computer)

            id_value = computers["computers"][-1]["ID"]

            if num_found == 0:
                break

            total_num = total_num + num_found

        return paged_computers

    except requests.exceptions.Timeout as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        _LOGGER.error(response.text)
        raise SystemExit(err)


def get_indexed(data, index) -> dict:
    """Index a list"""

    indexed_data = {}
    for element in data:
        indexed_data[element[index]] = element

    return indexed_data


def get_computers_groups(headers, host, verify=True) -> dict:
    """Retrieve computer groups"""

    session_url = "https://" + host + "/api/computergroups"

    try:
        response = requests.request("GET", session_url, headers=headers, verify=verify)
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        _LOGGER.error(response.text)
        raise SystemExit(err)

    computer_groups = response.json()
    indexed_computer_groups = {}
    for element in computer_groups["computerGroups"]:
        indexed_computer_groups[element["ID"]] = element

    return indexed_computer_groups


def get_policies(headers, host, verify=True) -> any:
    """Retrive policies"""

    session_url = "https://" + host + "/api/policies"

    try:
        response = requests.request("GET", session_url, headers=headers, verify=verify)
        response.raise_for_status()
    except requests.exceptions.Timeout as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        _LOGGER.error(response.text)
        raise SystemExit(err)
    except requests.exceptions.RequestException as err:
        # catastrophic error. bail.
        _LOGGER.error(response.text)
        raise SystemExit(err)

    policies = response.json()
    return policies["policies"]


def add_computer_info(headers, host, tenant, computers, verify) -> list:
    """Add additional information to the computers list"""

    computers_groups = get_computers_groups(headers, host, verify)
    policies = get_policies(headers, host, verify)
    indexed_policies = get_indexed(data=policies, index="ID")
    computer_info_list = []

    for computer in computers:
        computer_info = {
            "tenant": tenant,
            "id": computer["ID"],
            "name": computer["hostName"],
            "os": computer["platform"],
            "am_mode": computer["antiMalware"]["state"],
            "agentStatus": computer["computerStatus"]["agentStatus"],
            "agentStatusMessages": computer["computerStatus"]["agentStatusMessages"],
        }
        if computer["groupID"] != 0:
            computer_info["group"] = computers_groups[computer["groupID"]]["name"]
        if "policyID" in computer:
            computer_info["policy"] = indexed_policies[computer["policyID"]]["name"]
        computer_info_list.append(
            computer_info,
        )

    return computer_info_list


def cef_computer(computer, facility, host, port) -> None:
    """
    Creates a CEF event from a computer

    Parameters
    ----------
    computer
    facility
    host
    port
    """

    # message format:
    # CEF:Version|Device Vendor|Device Product|Rule ID|Name|Severity|Extension
    # sample:
    # CEF:0|Trend Micro|Deep Security|1.0|0|Agent Status Report|6|Extension
    #   Extension:
    #   shost=ip-10-0-4-201.ec2.internal rt=2024-03-20 08:34:54.093413 cs1Label=agentStatus cs1=active
    #   cs2Label=agentStatusMessages cs2=['Managed (Online)'] cs3Label=os cs3=Microsoft Windows Server 2022 (64 bit)  Build 20348
    #   cs4Label=computerPolicy cs4=Playground One Windows Server cs6Label=tenant cs6=tenant0 msg=details am_mode\=on
    c = CEFEvent()

    match computer["agentStatus"]:
        case "active":
            severity = "info"
        case _:
            severity = "notice"

    c.set_field("name", "Agent Status Report")
    c.set_field("shost", computer["name"])
    c.set_field("deviceVendor", "Trend Micro")
    c.set_field("deviceProduct", "Deep Security")
    c.set_field("rt", datetime.now())
    c.set_field("severity", str(LEVEL[severity]))

    c.set_field("cs1Label", "agentStatus")
    c.set_field("cs1", computer["agentStatus"])

    c.set_field("cs2Label", "agentStatusMessages")
    c.set_field("cs2", computer["agentStatusMessages"])

    c.set_field("cs3Label", "os")
    c.set_field("cs3", computer["os"])

    c.set_field("cs4Label", "computerPolicy")
    c.set_field("cs4", computer["policy"])

    # c.set_field("cs5Label", "computerStatus")
    # c.set_field("cs5", computer["agentStatus"])

    c.set_field("cs6Label", "tenant")
    c.set_field("cs6", computer["tenant"])

    c.set_field("message", "details am_mode=" + computer["am_mode"])

    c.build_cef()
    syslog(c, level=LEVEL[severity], facility=FACILITY[facility], host=host, port=port)
    _LOGGER.debug("Runtime event sent")


def query(host_type, host, tenant, api_key, verify) -> list:
    # Authentication for DS and WS
    if host_type == "ws":
        headers = {"api-version": "v1", "Authorization": f"ApiKey {api_key}"}
    else:
        headers = {"api-version": "v1", "api-secret-key": f"{api_key}"}

    # Query Computer Status
    _LOGGER.info("Retrieving computers of tenant %s", tenant)
    computers = get_paged_computers(headers, host, verify=verify)
    computers_info = add_computer_info(headers, host, tenant, computers, verify=verify)
    # indexed_computers = get_indexed(data=computers_info, index="id")

    pp.pprint(computers_info)

    return computers_info


def send(computers, facility, logger_host, logger_port) -> list:
    if len(computers) > 0:
        for computer in computers:
            cef_computer(computer, facility, logger_host, logger_port)


def main() -> None:
    """Main function"""

    # Read configuration
    with open("config.yml", "r", encoding="utf-8") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    host = cfg["deepsecurity"]["server"]
    host_type = cfg["deepsecurity"].get("type", "ws")
    api_key = cfg["deepsecurity"].get("api_key", None)
    api_keys = cfg["deepsecurity"].get("api_keys", None)
    tls_verify = bool(cfg["deepsecurity"].get("tls_verify", True))

    logger_host = cfg["logger"]["host"]
    logger_port = cfg["logger"]["port"]
    facility = cfg["logger"]["facility"]

    if tls_verify is False:
        _LOGGER.info("Disabling TLS verify")
        ssl._create_default_https_context = ssl._create_unverified_context
        urllib3.disable_warnings()

    if api_keys is not None:
        for tenant, api_key in api_keys.items():
            computers = query(host_type, host, tenant, api_key, verify=tls_verify)
            send(computers, facility, logger_host, logger_port)
    elif api_key is not None:
        computers = query(host_type, host, "tenant0", api_key, verify=tls_verify)
        send(computers, facility, logger_host, logger_port)


if __name__ == "__main__":
    main()

        # computers = [
        #     {
        #         "agentStatus": "active",
        #         "agentStatusMessages": ["Managed (Online)"],
        #         "am_mode": "on",
        #         "id": 1,
        #         "name": "10.0.0.100",
        #         "os": "Red Hat Enterprise 9 (64 bit) (5.14.0-284.30.1.el9_2.x86_64)",
        #         "policy": "Deep Security Manager",
        #     },
        #     {
        #         "agentStatus": "active",
        #         "agentStatusMessages": ["Managed (Online)"],
        #         "am_mode": "on",
        #         "id": 2,
        #         "name": "ip-10-0-4-194.ec2.internal",
        #         "os": "Amazon Linux 2 (64 bit) (4.14.336-257.562.amzn2.x86_64)",
        #         "policy": "Playground One Linux Server",
        #     },
        #     {
        #         "agentStatus": "active",
        #         "agentStatusMessages": ["Managed (Online)"],
        #         "am_mode": "on",
        #         "id": 3,
        #         "name": "ip-10-0-4-90.ec2.internal",
        #         "os": "Ubuntu Linux 20 (64 bit) (5.15.0-1041-aws)",
        #         "policy": "Playground One Linux Server",
        #     },
        #     {
        #         "agentStatus": "active",
        #         "agentStatusMessages": ["Managed (Online)"],
        #         "am_mode": "on",
        #         "id": 4,
        #         "name": "ip-10-0-4-195.ec2.internal",
        #         "os": "Microsoft Windows Server 2022 (64 bit)  Build 20348",
        #         "policy": "Playground One Windows Server",
        #     },
        # ]
