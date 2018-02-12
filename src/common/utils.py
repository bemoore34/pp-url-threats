__author__ = "bmoore"


class Utils(object):

    @staticmethod
    def get_domain(url):
        # return the host and domain component of the URL. e.g. "www.google.com". The method checks whether the
        # URL contains http:// or https:// at the beginning as ProofPoint doesn't always include it.
        if url[0:4] == "http":
            domain = url.split("/", 3)[2]
        else:
            domain = url.split("/")[0]
        return domain

    @staticmethod
    def strip_http(url):
        # remove http:// or https://, if present. Isn't used by the Palo firewall.
        if url[0:4] == "http":
            url = url.split("/", 2)[2]
        return url