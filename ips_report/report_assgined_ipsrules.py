#!/usr/bin/env python3

DOCUMENTATION = """
---
module: report_assgined_ipsrules.py

short_description: Creates a report in csv format containing all computer objects
                   and their IPS rules assigned. The rules are included with
                   the covered CVEs and CVE score

description:
    Configuration parameters in config.yml

    deepsecurity:
      server: https://app.deepsecurity.trendmicro.com:443
      api_key: <api key>
    report_file: "report.csv"

options:
    none

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
"""

EXAMPLES = """
./report_assgined_ipsrules.py
"""

RETURN = """
Creates .csv file.
"""

import ssl

ssl._create_default_https_context = ssl._create_unverified_context
import urllib3

urllib3.disable_warnings()
import json
import requests
import yaml

# Constants
RESULT_SET_SIZE = 5000


def build_id_identifier_name(dsm_url, api_key):
    """
    Create a dictionary with
    'ID': {'identifier',
           'name',
           'severity',
           'CVSSScore',
           'CVE' }
    """

    # Return dictionary
    id_identifier_name = {}

    dict_len = 0
    offset = 0
    while True:

        url = "https://" + dsm_url + "/api/intrusionpreventionrules/search"
        data = {
            "maxItems": RESULT_SET_SIZE,
            "searchCriteria": [
                {
                    "fieldName": "ID",
                    "idTest": "less-than",
                    "idValue": offset + RESULT_SET_SIZE,
                }
            ],
        }

        post_header = {
            "Content-type": "application/json",
            "api-secret-key": api_key,
            "api-version": "v1",
        }
        response = requests.post(
            url, data=json.dumps(data), headers=post_header, verify=False
        ).json()

        # Error handling
        if "message" in response:
            if response["message"] == "Invalid API Key":
                raise ValueError("Invalid API Key")

        rules = response["intrusionPreventionRules"]

        # Build dictionary
        for rule in rules:

            cves = []
            for cve in rule.get("CVE", ""):
                cves.append(cve)

            identifier_name = {
                "identifier": str(rule.get("identifier", "")),
                "name": str(rule.get("name", "")),
                "severity": str(rule.get("severity", "")),
                "CVSSScore": str(rule.get("CVSSScore", "")),
                "CVE": cves,
            }
            id_identifier_name[str(rule["ID"]).strip()] = identifier_name

        if len(id_identifier_name) != 0 and len(id_identifier_name) == dict_len:
            dict_len = len(id_identifier_name)
            print("Number of rules in dictionary: {}.".format(dict_len))
            break
        if len(id_identifier_name) != 0 and len(id_identifier_name) != dict_len:
            dict_len = len(id_identifier_name)

        offset += RESULT_SET_SIZE

    return id_identifier_name


def build_computer_rules(dsm_url, api_key, id_identifier_name):
    """
    Create a dictionary for computers with
     'ID': {'assignedRuleIDs': [],
            'displayName': '',
            'hostName': ''},
    """

    # Return dictionary
    computer_info = {}

    dict_len = 0
    offset = 0
    while True:

        url = "https://" + dsm_url + "/api/computers/search"
        post_header = {
            "Content-type": "application/json",
            "api-secret-key": api_key,
            "api-version": "v1",
        }
        data = {
            "maxItems": RESULT_SET_SIZE,
            "searchCriteria": [
                {
                    "fieldName": "ID",
                    "idTest": "less-than",
                    "idValue": offset + RESULT_SET_SIZE,
                }
            ],
        }

        post_header = {
            "Content-type": "application/json",
            "api-secret-key": api_key,
            "api-version": "v1",
        }
        response = requests.post(
            url, data=json.dumps(data), headers=post_header, verify=False
        ).json()

        # Error handling
        if "message" in response:
            if response["message"] == "Invalid API Key":
                raise ValueError("Invalid API Key")

        computers = response["computers"]

        if len(computers) != 0 and len(computers) == dict_len:
            dict_len = len(computers)
            print("Number of Computers in dictionary: {}.".format(dict_len))
            break
        if len(computers) != 0 and len(computers) != dict_len:
            dict_len = len(computers)

        offset += RESULT_SET_SIZE

    # Build dictionary
    for computer in computers:

        print("Processing Computer ID " + str(computer["ID"]))

        url = (
            "https://" + dsm_url
            + "/api/computers/"
            + str(computer["ID"])
            + "/intrusionprevention/assignments"
        )
        post_header = {
            "Content-type": "application/json",
            "api-secret-key": api_key,
            "api-version": "v1",
        }
        computer_rules = requests.get(url, headers=post_header, verify=False).json()

        info = {
            "hostName": str(computer.get("hostName", "")),
            "displayName": str(computer.get("displayName", "")),
            "assignedRuleIDs": computer_rules.get("assignedRuleIDs", []),
        }

        computer_info[str(computer["ID"]).strip()] = info

    return computer_info


def main():

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    print("Running Deep Security IPS Assignment Reporter.")

    print("Build IPS rules lookup table.")
    id_identifier_name = {}
    id_identifier_name = build_id_identifier_name(
        cfg["deepsecurity"]["server"], cfg["deepsecurity"]["api_key"]
    )

    print("Build Computer IPS rules table.")
    computer_rules = {}
    computer_rules = build_computer_rules(
        cfg["deepsecurity"]["server"],
        cfg["deepsecurity"]["api_key"],
        id_identifier_name,
    )

    print("Creating csv file.")

    # variant, if False, IPS rules covering multiple CVEs will result in one line
    # per rule.
    # variant, if True, IPS rules will be duplicated if they cover multiple CVEs
    variant = False
    with open(cfg["report_file"], "w") as file:

        file.write(
            "ID;hostName;displayName;ruleID;ruleIdentifier;ruleName;CVE;CVSSScore\n"
        )
        for id in computer_rules:

            computer = computer_rules[id]

            c0 = id
            c1 = computer.get("hostName", "")
            c2 = computer.get("displayName", "")

            for rule in computer.get("assignedRuleIDs", []):
                c3 = rule
                c4 = id_identifier_name.get(str(rule), "").get("identifier", "")
                c5 = id_identifier_name.get(str(rule), "").get("name", "")

                if not variant:
                    c6 = ""
                    first = True
                    for cve in id_identifier_name.get(str(rule), "").get("CVE", ""):
                        if not first:
                            c6 += ","
                        c6 += cve
                        first = False

                    c7 = id_identifier_name.get(str(rule), "").get("CVSSScore", "")

                    file.write(
                        "{0};{1};{2};{3};{4};{5};{6};{7}\n".format(
                            c0, c1, c2, c3, c4, c5, c6, c7
                        )
                    )
                else:
                    c6 = ""
                    first = True
                    for cve in id_identifier_name.get(str(rule), "").get("CVE", ""):
                        c6 = cve
                        c7 = id_identifier_name.get(str(rule), "").get("CVSSScore", "")

                        file.write(
                            "{0};{1};{2};{3};{4};{5};{6};{7}\n".format(
                                c0, c1, c2, c3, c4, c5, c6, c7
                            )
                        )

    print(cfg["report_file"] + " created.")


if __name__ == "__main__":
    main()
