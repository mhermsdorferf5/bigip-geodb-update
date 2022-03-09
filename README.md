# Example scripts for updating the BIG-IP IP geolocation database

This repository contains example scripts that update teh BIG-IP geolocation database.  There are currently no API endpoints on the BIG-IP to enable this directly, however the API can be used to run shell commands that automate the updates.  Additionally, there is an API on the BIG-IQ that can be leveraged if you have a BIG-IQ in your environment.

Relevant Documentation:
* Manual steps to update the golocation database on the BIG-IP directly: https://support.f5.com/csp/article/K11176
* Manual steps to update the geolocation database on the BIG-IP using BIG-IQ are here: https://support.f5.com/csp/article/K22650515
* BIG-IQ API docs: https://clouddocs.f5.com/products/big-iq/mgmt-api/v7.1.0/ApiReferences/bigiq_public_api_ref/r_device_geoip_update_manager.html


## Example Python Script: deploy-geoip-update.py

Included in this repository is the 'deploy-geoip-update.py' script.  This is a python script that will upload the new geolocation database zip file to a BIG-IP, extract the individual update RPM files from the zip, and install each update on the BIG-IP.

The script is intended to be an example and/or called from another automation tool, it currently only takes a single BIG-IP hostname.

* Requirements:
    * Python3: with requests & json libraries.
* Arguments:
    * Hostname/IP addess of BIG-IP to update.
    * Credentials for the BIG-IP, note these must have administrative privileges.
        * These can either be passed as "user:password" or simply as a username, with the password being set in an environment variable "BIGIP_SECRET"
    * Location on the filesystem of the geolocation update zip as downloaded from https://downloads.f5.com


### Example:
```
$ export BIGIP_SECRET="adminPassword"
$ python3 deploy-geoip-update.py 10.2.1.88 admin ../ip-geolocation-v2-2.0.0-20220228.573.0.zip
Uploading GeoIP Zip File...
Extracting ZIP file & Installing RPMs...
Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-Region2-2.0.0-20220228.573.0.i686.rpm
Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-ISP-2.0.0-20220228.573.0.i686.rpm
Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-Org-2.0.0-20220228.573.0.i686.rpm
Testing GeoIP DB version...
Prior to install GeoIP Version: 20210119
Post Install GeoIP Version: 20220228
GeoIP DB updated!
```