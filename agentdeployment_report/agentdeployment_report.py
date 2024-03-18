#!/usr/bin/python3
"""
---
module: agentdeployment_report.py

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
import logging
from datetime import datetime
import pprint as pp

import urllib3
import requests
import yaml
from requests import Session
from zeep.client import Client
from zeep.transports import Transport

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

COMPUTER_DELETED = 251
AGENT_SOFTWARE_INSTALLED = 700
AGENT_ACTIVATED = 704
AGENT_SOFTWARE_DEPLOYED = 711
AGENT_INITIATED_ACTIVATION_REQUESTED = 790


def get_paged_computers(headers, host, verify):
    """Retrieve all computers"""

    paged_computers = []
    id_value, total_num = 0, 0
    max_items = 2000

    session_url = "https://" + host + "/api/computers/search"
    query = {"expand": ["computerStatus", "antiMalware"]}

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

            response = requests.post(
                session_url, headers=headers, params=query, json=payload, verify=verify
            )
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


def get_indexed(data, index):
    """Index a list"""

    indexed_data = {}
    for element in data:
        indexed_data[element[index]] = element

    return indexed_data


def get_computers_groups(headers, host, verify=True):
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


def get_policies(headers, host, verify=True):
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


def add_computer_info(headers, host, computers, verify):
    """Add additional information to the computers list"""

    computers_groups = get_computers_groups(headers, host, verify)
    policies = get_policies(headers, host, verify)
    indexed_policies = get_indexed(data=policies, index="ID")
    computer_info_list = []

    for computer in computers:
        computer_info = {
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


def soap_auth(client, tenant, username, password):
    """Authenticate to the web services"""

    if not tenant:
        return client.service.authenticate(username=username, password=password)
    return client.service.authenticateTenant(
        tenantName=tenant, username=username, password=password
    )


def logout(client, sID):
    """Terminate session"""

    client.service.endSession(sID)
    return True


def create_event_id_filter(factory, id, operator):
    """Create an event id filter"""

    EnumOperator = factory.EnumOperator(operator)
    IDFilterTransport = factory.IDFilterTransport(id=id, operator=EnumOperator)
    return IDFilterTransport


def create_host_filter(factory, groupID, hostID, securityProfileID, enumType):
    """Create a host filter"""

    EnumHostFilter = factory.EnumHostFilterType(enumType)
    HostFilterTransport = factory.HostFilterTransport(
        hostGroupID=groupID,
        hostID=hostID,
        securityProfileID=securityProfileID,
        type=EnumHostFilter,
    )
    return HostFilterTransport


def create_file_filter(factory, TimeRangeFrom, TimeRangeTo, TimeSpecific, type):
    """Create a file filter"""

    Timetype = factory.EnumTimeFilterType(type)
    TimeFilterTransport = factory.TimeFilterTransport(
        rangeFrom=TimeRangeFrom,
        rangeTo=TimeRangeTo,
        specificTime=TimeSpecific,
        type=Timetype,
    )
    return TimeFilterTransport


def get_sys_events(
    client,
    factory,
    timespan_from,
    timespan_to,
    tenant,
    username,
    password,
    indexed_computers,
    event_id=0,
):
    """Retrieve system events"""

    sID = soap_auth(client, tenant, username, password)
    epochStart = datetime.strptime(timespan_from + " 00:00:00", "%m.%d.%Y %H:%M:%S")
    epochEnd = datetime.strptime(timespan_to + " 23:59:59", "%m.%d.%Y %H:%M:%S")

    events = []
    id_value, num_requests = 0, 0

    while True:
        try:
            sysEvents = client.service.systemEventRetrieve(
                timeFilter=create_file_filter(
                    factory, epochStart, epochEnd, None, "CUSTOM_RANGE"
                ),
                hostFilter=create_host_filter(factory, None, None, None, "ALL_HOSTS"),
                eventIdFilter=create_event_id_filter(factory, id_value, "GREATER_THAN"),
                includeNonHostEvents=True,
                sID=sID,
            )
        except Exception as err:
            _LOGGER.error(err)
            raise SystemExit(err)

        if sysEvents["systemEvents"] is not None:
            for event in sysEvents["systemEvents"]["item"]:
                eventID = event["eventID"]
                if event_id == 0 or event_id == eventID:
                    format_event = {
                        "actionPerformedBy": event["actionPerformedBy"],
                        # "description": event["description"],
                        "event": event["event"],
                        "eventID": event["eventID"],
                        "eventOrigin": event["eventOrigin"],
                        "managerHostname": event["managerHostname"],
                        "systemEventID": event["systemEventID"],
                        "tags": event["tags"],
                        "target": event["target"],
                        "targetID": event["targetID"],
                        # "targetType": event["targetType"],
                        "time": event["time"],
                        "type": event["type"],
                    }
                    if "targetID" in event:
                        if event["targetID"] in indexed_computers:
                            if "group" in indexed_computers[event["targetID"]]:
                                format_event["computerGroup"] = indexed_computers[
                                    event["targetID"]
                                ]["group"]
                    if "computerGroup" not in format_event:
                        format_event["computerGroup"] = "None"

                    events.append(
                        format_event,
                    )

            id_value = sysEvents["systemEvents"]["item"][-1]["systemEventID"]

            num_requests += 1
            if num_requests == 100:
                logout(client, sID)
                num_requests = 0
                sID = soap_auth(client, tenant, username, password)
        else:
            logout(client, sID)
            break

    return events


def getSystemEventID(element):
    """Returns the systemEventID of a given event"""

    return element["systemEventID"]


def main():
    """Main function"""

    # Read configuration
    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    host = cfg["deepsecurity"]["server"]
    host_type = cfg["deepsecurity"].get("type", "ws")
    api_key = cfg["deepsecurity"]["api_key"]
    tenant = cfg["deepsecurity"].get("tenant", None)
    tenant_username = cfg["deepsecurity"].get("tenant_username", None)
    tenant_password = cfg["deepsecurity"].get("tenant_password", None)
    timespan_from = cfg["deepsecurity"].get("timespan_from", None)
    timespan_to = cfg["deepsecurity"].get("timespan_to", None)
    tls_verify = bool(cfg["deepsecurity"].get("tls_verify", True))

    # REST API
    if tls_verify is False:
        _LOGGER.info("Disabling TLS verify")
        ssl._create_default_https_context = ssl._create_unverified_context
        urllib3.disable_warnings()

    # Authentication for DS and WS
    if host_type == "ws":
        headers = {"api-version": "v1", "Authorization": f"ApiKey {api_key}"}
        tenant_username = "Authorization:ApiKey"
        tenant_password = api_key
    else:
        headers = {"api-version": "v1", "api-secret-key": f"{api_key}"}

    #
    # Query Computer Status
    #
    _LOGGER.info("Retrieving computers...")
    computers = get_paged_computers(headers, host, verify=tls_verify)
    computers_info = add_computer_info(headers, host, computers, verify=tls_verify)
    indexed_computers = get_indexed(data=computers_info, index="id")

    pp.pprint(indexed_computers)

    #
    # SOAP API
    #
    session = Session()
    session.verify = tls_verify
    transport = Transport(session=session, timeout=1800)
    url = "https://{0}/webservice/Manager?WSDL".format(host)
    client = Client(url, transport=transport)
    factory = client.type_factory("ns0")

    #
    # Query System Events
    #
    _LOGGER.info("Retrieving system events 'Agent-Initiated Activation Requested'")
    sys_events = get_sys_events(
        client,
        factory,
        timespan_from,
        timespan_to,
        tenant,
        tenant_username,
        tenant_password,
        indexed_computers,
        event_id=AGENT_INITIATED_ACTIVATION_REQUESTED,
    )
    _LOGGER.info("Retrieving system events 'Agent Activated'")
    sys_events = sys_events + get_sys_events(
        client,
        factory,
        timespan_from,
        timespan_to,
        tenant,
        tenant_username,
        tenant_password,
        indexed_computers,
        event_id=AGENT_ACTIVATED,
    )
    _LOGGER.info("Retrieving system events 'Computer Deleted'")
    sys_events = sys_events + get_sys_events(
        client,
        factory,
        timespan_from,
        timespan_to,
        tenant,
        tenant_username,
        tenant_password,
        indexed_computers,
        event_id=COMPUTER_DELETED,
    )
    sys_events.sort(key=getSystemEventID)

    for activation in sys_events:
        # if activation["eventID"] == AGENT_INITIATED_ACTIVATION_REQUESTED:
        pp.pprint(activation)
        # _LOGGER.info("Event ID %s for %s at %s", activation["eventID"], activation["targetID"], activation["time"])


if __name__ == "__main__":
    main()
