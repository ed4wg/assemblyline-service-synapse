"""
This simple script can be used to call the Synapse /api/v1/storm endpoint which streams the results.
"""

import argparse
import getpass
import json
from pprint import pprint

import requests


def call_synapse_storm(syn_host, apikey, syn_query):

    headers = {
        "X-API-KEY": apikey,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {"query": syn_query, "opts": {"repr": True}, "stream": "jsonlines"}
    url = f"https://{syn_host}/api/v1/storm"

    response = requests.get(url, json=data, headers=headers, stream=True)
    for line in response.iter_lines(decode_unicode=True):
        if line:
            mesg = json.loads(line)
            pprint(mesg)
            print("---" * 50)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--host",
        required=True,
        help="Synapse API endpoint.",
    )
    parser.add_argument(
        "--query",
        required=True,
        help="Synapse Query. e.g. inet:fqdn | limit 5",
    )
    args = parser.parse_args()

    apikey = getpass.getpass("Synapse API Key:")

    call_synapse_storm(args.host, apikey, args.query)


if __name__ == "__main__":

    main()
