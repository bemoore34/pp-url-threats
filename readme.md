This project pulls URL threat data from Proof Point's TAP SIEM API, parses the threat data and populates a defined file with malicious URLs.

Configuration information is stored in the "config.ini" file.

It requires an active Proof Point TAP subscription and "Connected Application" service credentials to connect to the TAP SIEM API.

The URL list, defined in config.ini, will be populated with entries with the following format:

host.domain.com   #phish, active, blocked, 2018/02/13 00:56:03

Where:
"phish" = threat category
"active" = threat status
"blocked" = Proof Point action
"2018/02/13 00:56:03" = time added to the file

This format is compatible with Palo Alto's dynamic URL blocklists.

Just the host and domain are added to the block list for most sites, as opposed to the full malicious URL. For example:

"www.badsite.com" would be added to the block list for a malicious URL of "www.badsite.com/wp-admin/sadfklj/o365_login.html"

This is because if Palo Alto has classified a domain as belonging to a category that you allow, like "Computer and Internet Info", then connections will be allowed to the full URL. It will, however, override the Palo classification if you add just the host and domain to the block list.

In order to prevent unwanted blocks to some shared sites, you can specify hosts and domains in the config.ini file under "list_full" that will not be shortened.

Also, a lot of phishing URLs will leverage URL shortening services. The script will attempt to get the destination URL and populate it on the block list as opposed to the shortening URL. Additional URL shortening sites can be defined in the config.ini file under "short_urls".
