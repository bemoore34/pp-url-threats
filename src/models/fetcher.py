import requests
import logging
import sys

__author__ = "bmoore"

modulelogger = logging.getLogger('pp_threat_feed.Fetcher')


class Fetcher(object):

    @staticmethod
    def get_forwarded_url(url):
        funclogger = logging.getLogger('pp_threat_feed.Fetcher.get_forwarder_url')
        if url[0:4] == "http":
            try:
                resp = requests.head(url, timeout=5)
                if 300 < resp.status_code < 400:
                    funclogger.debug("Response code {} for {}".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        funclogger.debug("{} forwards to {}".format(url, resp.headers["Location"]))
                        return resp.headers["Location"]
                    funclogger.debug("'Location' not in resp.headers. 'None' returned for response")
                    return None
                funclogger.debug("Response code {} for {}. Return None.".format(resp.status_code, url))
                return None
            except requests.exceptions.ConnectionError:
                funclogger.debug("Connection Error for {}. Return None.".format(url))
                return None
        else:
            fullurl = "https://{}".format(url)
            try:
                resp = requests.head(fullurl, timeout=5)
                if 300 < resp.status_code < 400:
                    funclogger.debug("Response code {} for {} (added https)".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        funclogger.debug("{} forwards to {}".format(fullurl, resp.headers["Location"]))
                        return resp.headers["Location"]
                    funclogger.debug("'Location' not in resp.headers. 'None' returned for response")
                    return None
                funclogger.debug("Response code {} for {} (added https. Trying http).".format(resp.status_code, url))
                pass
            except requests.exceptions.ConnectionError:
                funclogger.debug("Connection Error for {} (added https)".format(url))
                pass
            fullurl = "http://{}".format(url)
            try:
                resp = requests.head(fullurl, timeout=5)
                if 300 < resp.status_code < 400:
                    funclogger.debug("Response code {} for {} (added http)".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        funclogger.debug("{} forwards to {}".format(fullurl, resp.headers["Location"]))
                        return resp.headers["Location"]
                    funclogger.debug("'Location' not in resp.headers. 'None' returned for response")
                    return None
                funclogger.debug("Response code {} for {} (added http). Return None.".format(resp.status_code, url))
                return None
            except requests.exceptions.ConnectionError:
                funclogger.debug("Connection Error for {} (added http). Return None.".format(url))
                return None

    @staticmethod
    def test_forwarded_url(url):
        # Call from command line only - testing with any URL
        if url[0:4] == "http":
            try:
                resp = requests.head(url, timeout=5)
                if 300 < resp.status_code < 400:
                    print("Response code {} for {}".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        return resp.headers["Location"]
                    print("'Location' not in resp.headers. 'None' returned for response")
                    return None
                print("Response code {} for {}".format(resp.status_code, url))
                return None
            except requests.exceptions.ConnectionError:
                print("Connection Error for {}".format(url))
                return None
        else:
            fullurl = "https://{}".format(url)
            try:
                resp = requests.head(fullurl, timeout=5)
                if 300 < resp.status_code < 400:
                    print("Response code {} for {} (added https)".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        return resp.headers["Location"]
                    print("'Location' not in resp.headers. 'None' returned for response")
                    return None
                print("Response code {} for {} (added https)".format(resp.status_code, url))
                return None
            except requests.exceptions.ConnectionError:
                print("Connection Error for {} (added https)".format(url))
                pass
            fullurl = "http://{}".format(url)
            try:
                resp = requests.head(fullurl, timeout=5)
                if 300 < resp.status_code < 400:
                    print("Response code {} for {} (added http)".format(resp.status_code, url))
                    if "Location" in resp.headers:
                        return resp.headers["Location"]
                    print("'Location' not in resp.headers. 'None' returned for response")
                    return None
                print("Response code {} for {} (added http)".format(resp.status_code, url))
                return None
            except requests.exceptions.ConnectionError:
                print("Connection Error for {} (added http)".format(url))
                return None

    @staticmethod
    def query_pp_siem(url, auth, headers):
        logger = logging.getLogger('pp_threat_feed.Fetcher.query_pp_siem')
        try:
            response = requests.get(url, headers=headers, auth=auth)
        except requests.exceptions.RequestException:
            logger.exception("Connection Error")
            logger.info(
                "====================================================================================================")
            sys.exit(1)
        return response
