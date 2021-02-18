#!/usr/bin/python3
import ssl

# ssl._create_default_https_context = ssl._create_unverified_context

import requests
from requests import Session
import sys
import json
import xmltodict
import suds.client
import pprint
import pickle
import os.path
from datetime import datetime
import arrow
import yaml
from zeep.client import Client
from zeep.transports import Transport
from zeep import helpers


pp = pprint.PrettyPrinter()


def soap_auth(client, tenant, username, password):
    return client.service.authenticateTenant(
        tenantName=tenant, username=username, password=password
    )


def logout(client, sID):
    client.service.endSession(sID)
    return True


# Ignoring Timezones, but that should not matter since the interesting info
# is the duration.
# No exception handling
def deep_security_usage_query(
    client,
    dsm_url,
    dsm_user,
    dsm_password,
    dsm_tenant,
    dsm_tenant_id,
    timespan_from,
    timespan_to,
):

    sID = soap_auth(client, "Trend Micro Bocking", dsm_user, dsm_password)
    tID = dsm_tenant_id

    print("sID: {}".format(sID))
    print("tID: {}".format(tID))

    today = datetime.now()

    if timespan_from == "":
        timespan_from = arrow.get(today).replace(
            months=-1, day=1, hour=0, minute=0, second=0
        )
        timespan_from = timespan_from.format("DD MMM YYYY HH:mm")
    if timespan_to == "":
        timespan_to = arrow.get(today).replace(day=1, hour=0, minute=0, second=0)
        timespan_to = arrow.get(timespan_to).replace(minutes=-1)
        timespan_to = timespan_to.format("DD MMM YYYY HH:mm")

    print(
        "ID,Hostname,IP,Instance Type,Protection Start Date,Protection Stop Date,Duration,AM,WRS,FW,DPI,IM,LI,AC,SAP"
    )
    try:
        url = "https://" + dsm_url
        url += "/rest/monitoring/usages/hosts/protection?tID=" + str(tID) + "&sID="
        url += sID
        url += "&from=" + timespan_from + "&to=" + timespan_to
        data = {}
        post_header = {"Content-type": "application/json", "api-version": "v1"}

        print(url)
        pp.pprint(requests.get(url, headers=post_header, verify=False).content)
        response = xmltodict.parse(
            requests.get(
                url, data=json.dumps(data), headers=post_header, verify=False
            ).content
        )

        for comp in response["TenantHostProtectionListing"]["TenantHostProtection"]:
            id = str(comp["hostID"])
            hostName = str(comp["hostID1"])
            hostIp = str(comp["hostID2"])
            instanceType = str(comp["instanceType"])

            protectionStartDate = ""
            protectionStopDate = ""
            protectionStartDateDT = datetime.now()
            protectionStopDateDT = datetime.now()

            if "protectionStartDate" in comp:
                protectionStartDate = str(comp["protectionStartDate"])[:19]
                protectionStartDateDT = datetime.strptime(
                    protectionStartDate, "%Y-%m-%dT%H:%M:%S"
                )
            #                                                          '%Y-%m-%dT%H:%M:%S.%f')

            if "protectionStopDate" in comp:
                protectionStopDate = str(comp["protectionStopDate"])[:19]
                protectionStopDateDT = datetime.strptime(
                    protectionStopDate, "%Y-%m-%dT%H:%M:%S"
                )
            #                                                         '%Y-%m-%dT%H:%M:%S.%f')

            # <moduleUsageList>
            #     <moduleEnabled>false</moduleEnabled>
            #     <moduleName>AM</moduleName>
            # </moduleUsageList>
            moduleUsageList = ""
            for moduleUsage in comp["moduleUsageList"]:
                moduleUsageList += "," + moduleUsage["moduleEnabled"]
            duration = (protectionStopDateDT - protectionStartDateDT).total_seconds()
            print(
                "{},{},{},{},{},{},{}{}".format(
                    id,
                    hostName,
                    hostIp,
                    instanceType,
                    str(protectionStartDateDT),
                    str(protectionStopDateDT),
                    str(int(duration)),
                    moduleUsageList,
                )
            )

    finally:
        logout(client, sID)


def main():

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    host = cfg["deepsecurity"]["server"]
    dsm_user = cfg["deepsecurity"]["username"]
    dsm_password = cfg["deepsecurity"]["password"]
    dsm_tenant = cfg["deepsecurity"]["tenant_id"]
    dsm_token = cfg["deepsecurity"]["token"]
    timespan_from = cfg["deepsecurity"]["timespan_from"]
    timespan_to = cfg["deepsecurity"]["timespan_to"]

    session = Session()
    session.verify = True
    transport = Transport(session=session, timeout=1800)
    url = "https://{0}/webservice/Manager?WSDL".format(host)
    client = Client(url, transport=transport)
    factory = client.type_factory("ns0")

    print("authenticated")
    # deep_security_usage_query(dsm_url, dsm_user, dsm_password, dsm_tenant, dsm_tenant_id, timespan_from, timespan_to)
    deep_security_usage_query(
        client, host, dsm_user, dsm_password, 0, dsm_tenant, timespan_from, timespan_to
    )


if __name__ == "__main__":
    main()
