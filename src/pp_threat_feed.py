"""
This program pulls URL message data from the Proof Point TAP SIEM API, parses it, and
appends malicious URL prefixes (host and domain) to a URL block list in a format compatible
with the dynamic URL block lists used by Palo Alto firewalls.
"""

import sys
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import configparser
from models.fetcher import Fetcher
from models.threat import UrlThreat
from common.utils import Utils

__author__ = "bmoore"
__doc__ = "Retrieve and parse json data from the ProofPoint TAP SIEM API"


def main(arguments):
    """
    Main program function
    :param arguments: command line arguments passed to the main function
    :return: 0 on success
    """

    if arguments:
        print("This script does not take any command line arguments. Configure config.ini file and run.")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read_file(open('config.ini'))

    logger = logging.getLogger('pp_threat_feed')
    handler = RotatingFileHandler(config.get("api_config", "log-file-name"), maxBytes=10485760, backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    if config.get("api_config", "Debug-logging").upper() == "TRUE":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Set the sp and secret values that are used to authenticate with the Proof Point API
    sp = config.get("api_config", "sp")
    secret = config.get("api_config", "secret")

    # the time period (seconds) to pull events for. e.g 600 -> get events from last 10 minutes
    time_period = config.get("api_config", "time_period")

    # Define the Proof Point SIEM URLs to query for blocked and delivered url threat events
    siemblocked_url = "{}&sinceSeconds={}".format(config.get("api_config", "siem_url_blocked_url"), time_period)
    siemdelivered_url = "{}&sinceSeconds={}".format(config.get("api_config", "siem_url_delivered_url"), time_period)

    useragent = "Python client"

    headers = {'user-agent': useragent}
    logger.debug("Querying blocked and delivered messages from TAP for last {} seconds".format(time_period))

    response_blocked = Fetcher.query_pp_siem(url=siemblocked_url, auth=(sp, secret), headers=headers)
    response_delivered = Fetcher.query_pp_siem(url=siemdelivered_url, auth=(sp, secret), headers=headers)

    # Store the unique list of url threats in a set. The UrlThreat object matches on url (overriding __eq__)
    url_threats = set()

    # Define a set of known URL shortening services and other domains we can't block at the domain level.
    shorturls = config.get("api_config", "short_urls").split("\n")
    listfull = config.get("api_config", "list_full").split("\n")

    # process the blocked message query response
    if response_blocked.status_code == 200:
        logger.debug("Parsing any blocked messages in Proof Point SIEM API response")
        data = json.loads(response_blocked.text)
        logger.info("Blocked query time: {0}".format(data["queryEndTime"]))
        # Process blocked threats:
        if "messagesBlocked" in data:
            logger.info("{0} blocked messages returned in response".format(len(data["messagesBlocked"])))
            for msg in data["messagesBlocked"]:
                for threat in msg["threatsInfoMap"]:
                    # Process blocked URL threats:
                    if threat["threatType"] == "url":
                        # instantiate a new UrlThreat object, with the full threat URL from ProofPoint
                        urlthreat = UrlThreat(url=threat["threat"], action="blocked")
                        urlthreat.set_classification(classification=threat["classification"])
                        urlthreat.set_status(status=threat["threatStatus"])
                        url_threats.add(urlthreat)
        else:
            logger.info("No blocked messages in response")
    else:
        logger.error("Blocked message request reponse code was {0}".format(str(response_blocked.status_code)))

    # process the delivered message query response
    if response_delivered.status_code == 200:
        logger.debug("Parsing any delivered messages in response")
        data = json.loads(response_delivered.text)
        logger.info("Delivered query time: {0}".format(data["queryEndTime"]))
        # Process delivered threats:
        if "messagesDelivered" in data:  # Check that there are messages listed in the response
            logger.info("{0} delivered messages returned in response".format(len(data["messagesDelivered"])))
            for msg in data["messagesDelivered"]:
                for threat in msg["threatsInfoMap"]:
                    # Process delivered URL threats:
                    if threat["threatType"] == "url":
                        # Intantiate a new UrlThreat object with the full threat URL from ProofPoint
                        urlthreat = UrlThreat(url=threat["threat"], action="delivered")
                        urlthreat.set_classification(classification=threat["classification"])
                        urlthreat.set_status(status=threat["threatStatus"])
                        url_threats.add(urlthreat)
        else:
            logger.info("No delivered messages in response")
    else:
        logger.error("Delivered message request reponse code was {0}".format(str(response_blocked.status_code)))

    logger.info("{0} Distinct Threats in Reponses:".format(str(len(url_threats))))

    # If there are URL Threats resturned, identify new and add to dynamic block list
    if len(url_threats) > 0:
        masterlist = set()
        newthreats = set()

        url_file = config.get("api_config", "urlfile")

        # Populate masterlist with urls from the master URL file
        with open(url_file, 'r') as f:
            for line in f:
                # Format of file: "threat_url\t#urlclass, urlstatus, action, added"
                masterlist.add(line.split("\t")[0])

        # Check urls in response against master list to identify new url threats
        for threat in url_threats:
            threat.set_hostdomain(Utils.get_domain(threat.url))
            if threat.hostdomain not in masterlist:
                newthreats.add(threat)

        # If we have new threat objects, add applicable info to the blocklist file.
        if len(newthreats) > 0:
            addtime = time.strftime("%Y/%m/%d %H:%M:%S")
            logger.debug("{0} new malicious url(s) identified in response".format(len(newthreats)))
            with open(url_file, "a+") as f:
                # Create set for storing recently added domains - can have different URLs from same domain returned.
                added_list = set()
                for threat in newthreats:
                    # Check for short urls
                    if threat.hostdomain in shorturls:
                        threat.forward_url = threat.url
                        forwarder = True
                        # Get destination URL for forwarding URL
                        while forwarder:
                            threat.forward_url = Fetcher.get_forwarded_url(threat.forward_url)
                            if Utils.get_domain(threat.forward_url) not in shorturls:
                                forwarder = False
                                threat.set_hostdomain(Utils.get_domain(threat.forward_url))
                        # Couldn't get the destination URL
                        if threat.forward_url is None:
                            logger.debug("Couldn't get forwarded address. Added: {}".format(threat.url))
                            # add the full URL to the list
                            f.write("{0}\t#{1}, {2}, {3}, {4}\n".format(Utils.strip_http(threat.url),
                                                                        threat.classification,
                                                                        threat.status,
                                                                        threat.action,
                                                                        addtime))
                        # destination URL (hostdomain) is new
                        elif threat.hostdomain not in masterlist and threat.hostdomain not in added_list:
                            if threat.hostdomain in listfull:
                                logger.debug("Added (URL in list_full): {} for {}".format(threat.foward_url,
                                                                                          threat.url))
                                # add the full URL to the list
                                f.write("{0}\t#{1}, {2}, {3}, {4}\n".format(Utils.strip_http(threat.url),
                                                                            threat.classification,
                                                                            threat.status,
                                                                            threat.action,
                                                                            addtime))
                            else:
                                logger.debug("Added fowarded: {} for {}".format(threat.hostdomain, threat.url))
                                added_list.add(threat.hostdomain)
                                # add the url host and domain to the list
                                f.write("{0}\t#{1}, {2}, {3}, {4}\n".format(threat.hostdomain,
                                                                            threat.classification,
                                                                            threat.status,
                                                                            threat.action,
                                                                            addtime))
                        # The destination URL is already on the block list.
                        else:
                            logger.debug("Forwarded URL already on block list: {} for {}".format(threat.forward_url,
                                                                                                 threat.url))

                    elif threat.hostdomain in listfull:
                        # add the full URL to the list
                        logger.debug("Added to block list: {0}".format(threat.url))
                        f.write("{0}\t#{1}, {2}, {3}, {4}\n".format(Utils.strip_http(threat.url),
                                                                    threat.classification,
                                                                    threat.status,
                                                                    threat.action,
                                                                    addtime))
                    elif threat.hostdomain not in added_list:
                        logger.debug("Added to block list: {} for {}".format(threat.hostdomain,
                                                                             threat.url))
                        added_list.add(Utils.get_domain(threat.url))
                        f.write("{0}\t#{1}, {2}, {3}, {4}\n".format(threat.hostdomain,
                                                                    threat.classification,
                                                                    threat.status,
                                                                    threat.action,
                                                                    addtime))
                    else:
                        logger.debug("Duplicate URL domain in response: {}".format(threat.url))
        else:
            logger.debug("No new URL threats identified in response")
    else:
        logger.debug("No URL threats returned in response")

    logger.info("====================================================================================================")


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
