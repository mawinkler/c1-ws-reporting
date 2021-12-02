#!/usr/bin/env python3

DOCUMENTATION = """
---
module: report_assgined_ipsrules.py

short_description: Creates a mapping file in csv format containing all
                   IPS rules
                   ruleID; ruleIdentifier; ruleName; CVE(s); CVSSScore

description:
    Configuration parameters in config.yml

    deepsecurity:
      server: workload.us-1.cloudone.trendmicro.com
      api_key: <api key>
    report_file: "report.csv"

options:
    none

author:
    - Markus Winkler (markus_winkler@trendmicro.com)
"""

EXAMPLES = """
./ips_rule_id_identifier.py
"""

RETURN = """
Creates .csv file.
"""
import json
import requests
import yaml
import logging
import sys

# Constants
RESULT_SET_SIZE = 1000

_LOGGER = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s (%(threadName)s) [%(funcName)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

def build_id_identifier_name(ws_url, api_key):
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

        url = "https://" + ws_url + "/api/intrusionpreventionrules/search"
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
            url, data=json.dumps(data), headers=post_header, verify=True
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
            _LOGGER.info("Number of rules in dictionary: {}.".format(dict_len))
            break
        if len(id_identifier_name) != 0 and len(id_identifier_name) != dict_len:
            dict_len = len(id_identifier_name)

        offset += RESULT_SET_SIZE

    return id_identifier_name


def main():

    logging.basicConfig(level=logging.DEBUG, format='%(relativeCreated)6d %(threadName)s %(message)s')

    with open("config.yml", "r") as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    _LOGGER.info("Running Deep Security IPS Rules Dump.")
    _LOGGER.info("Build IPS rules lookup table.")
    id_identifier_name = {}
    id_identifier_name = build_id_identifier_name(
        cfg["deepsecurity"]["server"], cfg["deepsecurity"]["api_key"]
    )

    _LOGGER.info("Creating csv file.")
    # variant, if False, IPS rules covering multiple CVEs will result in one line
    # per rule.
    # variant, if True, IPS rules will be duplicated if they cover multiple CVEs
    variant = False
    with open(cfg["report_file"], "w") as file:

        file.write("ruleID;ruleIdentifier;ruleName;CVE;CVSSScore\n")
        for rule in id_identifier_name:

            c0 = rule
            c1 = id_identifier_name.get(str(rule), "").get("identifier", "")
            c2 = id_identifier_name.get(str(rule), "").get("name", "")

            if not variant:
                c3 = ""
                first = True
                for cve in id_identifier_name.get(str(rule), "").get("CVE", ""):
                    if not first:
                        c3 += ","
                    c3 += cve
                    first = False

                c4 = id_identifier_name.get(str(rule), "").get("CVSSScore", "")

                file.write("{0};{1};{2};{3};{4}\n".format(c0, c1, c2, c3, c4))
            else:
                c3 = ""
                first = True
                for cve in id_identifier_name.get(str(rule), "").get("CVE", ""):
                    c3 = cve
                    c4 = id_identifier_name.get(str(rule), "").get("CVSSScore", "")

                    file.write("{0};{1};{2};{3};{4}\n".format(c0, c1, c2, c3, c4))

    _LOGGER.info(cfg["report_file"] + " created.")


if __name__ == "__main__":
    main()
