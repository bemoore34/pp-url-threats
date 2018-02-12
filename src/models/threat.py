__author__ = "bmoore"


class UrlThreat(object):
    def __init__(self, url, action, status=None, classification=None, forward_url=None, hostdomain=None):
        self.status = status
        self.classification = classification
        self.action = action
        self.url = url
        self.hash = hash(url)
        self.forward_url = forward_url
        self.hostdomain = hostdomain

    # overriding the __hash__ and __eq__ function to enable unique matching by url when adding to set
    def __hash__(self):
        return self.hash

    def __eq__(self, other):
        return isinstance(other, UrlThreat) and self.url == other.url

    def set_status(self, status):
        self.status = status

    def set_classification(self, classification):
        self.classification = classification

    def set_forward_url(self, url):
        self.forward_url = url

    def set_hostdomain(self, hostdomain):
        self.hostdomain = hostdomain

