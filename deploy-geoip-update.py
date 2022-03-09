#!/usr/bin/python

# Python script to update GeoIP DB on a BIG-IP
#
# This script expects the following:
# Argument 1 => hostname/IP address of BIG-IP
# Argument 2 => Credentials, either username alone or username:password
#               If only providing username alone, the password must be set in an environment variable BIGIP_SECRET
# Argument 3 => Path to GeoIP Zip file to use for updates.
#
# Example:
#$ export BIGIP_SECRET="adminPassword"
#$ python3 deploy-geoip-update.py 10.2.1.88 admin ../ip-geolocation-v2-2.0.0-20220228.573.0.zip
#Uploading GeoIP Zip File...
#Extracting ZIP file & Installing RPMs...
#Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-Region2-2.0.0-20220228.573.0.i686.rpm
#Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-ISP-2.0.0-20220228.573.0.i686.rpm
#Installing GeoIP RPM: /var/tmp/geoIpUpdate/geoip-data-v2-Org-2.0.0-20220228.573.0.i686.rpm
#Testing GeoIP DB version...
#Prior to install GeoIP Version: 20210119
#Post Install GeoIP Version: 20220228
#GeoIP DB updated!
#

# Sub to get F5 auth-token:
def get_token(bigip, url_base, creds):
    payload = {}
    payload['username'] = creds[0]
    payload['password'] = creds[1]
    payload['loginProviderName'] = 'tmos'

    url_auth = '%s/shared/authn/login' % url_base
 
    response = bigip.post(url_auth, json.dumps(payload))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        print(error)
        print(error.response.text)
        sys.exit(1)
    token = response.json()['token']['token']
    return token
# End get_token sub

# Sub to upload files:
# Note this sub does not use the existing session, but creates it's own.
def upload_file(url_base, token, fp):
    # Upload will create a new session, not re-use parent session due to funky headers.

    session = requests.session()
    session.headers.update({'Content-Type':'application/octet-stream'})
    session.headers.update({'X-F5-Auth-Token': token})
    session.verify = False

    chunk_size = 512 * 1024

    fileobj = open(fp, 'rb')
    filename = os.path.basename(fp)
    if os.path.splitext(filename)[-1] == '.iso':
        # This drops the file into: /shared/images/ on the BIG-IP file system.
        uri = '%s/cm/autodeploy/software-image-uploads/%s' % ( url_base, filename)
    else:
        # This drops the file into: /var/config/rest/downloads/ on the BIG-IP file system.
        uri = '%s/shared/file-transfer/uploads/%s' % (url_base, filename)
        
    size = os.path.getsize(fp)

    start = 0

    while True:
        file_slice = fileobj.read(chunk_size)
        if not file_slice:
            break

        current_bytes = len(file_slice)
        if current_bytes < chunk_size:
            end = size
        else:
            end = start + current_bytes

        content_range = "%s-%s/%s" % (start, end - 1, size)
        session.headers.update({'Content-Range':content_range})
        response = session.post(uri,
                      data=file_slice
                      )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as error:
            print(error)
            print(error.response.text)
            sys.exit(1)

        start += current_bytes
# end upload_file sub

# Sub to run bash command.
def run_command(command):
    payload = {}
    payload['command'] = "run"
    payload['utilCmdArgs'] = "-c \'%s\'" % command
    payload[''] = 'tmos'

    url_bash = '%s/tm/util/bash' % url_base
 
    response = bigip.post(url_bash, json.dumps(payload))
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as error:
        print(error)
        print(error.response.text)
        sys.exit(1)
    if 'commandResult' in response.json():
        cmd_output = response.json()['commandResult']
        return cmd_output
    else:
        return ""
# End run_command sub

# Sub to Extract ZIP & install GeoIP RPMs.
def install_geoip_zip(file):
    run_command("mkdir /var/tmp/geoIpUpdate")
    run_command("mv /var/config/rest/downloads/%s /var/tmp/geoIpUpdate" % file)
    unzipOutput = run_command("unzip -u /var/tmp/geoIpUpdate/%s -d /var/tmp/geoIpUpdate" % file)
    rpmFiles = []
    for line in unzipOutput.splitlines():
        if "rpm" in line:
            match = re.match(r'\s+inflating:\s+(\S+)', line)
            rpmFiles.append(match.group(1))
    for rpm in rpmFiles:
        print("Installing GeoIP RPM: %s" % rpm)
        run_command("geoip_update_data %s" % rpm)
    run_command("rm -r /var/tmp/geoIpUpdate")

def test_geoip():
    geoIPLookupTestOutput = run_command("geoip_lookup 192.0.2.1")
    dbVer = "null"
    for line in geoIPLookupTestOutput.splitlines():
        if "Copyright" in line:
            # Grab the last 8 digit number, which should always be the date/version for the db in-use.
            match = re.match(r'^size of geoip database.*\s+(\d{8})$', line)
            dbVer = match.group(1)
    return(dbVer)

# End get_token sub


if __name__ == "__main__":
    import os, sys, requests, json, urllib3, re

    hostname       = sys.argv[1]
    creds          = sys.argv[2]
    geoZipFilePath = sys.argv[3]
    geoZipFileName = os.path.basename(geoZipFilePath)

    if (os.environ['BIGIP_SECRET'] is not None) and (not ":" in creds):
        username = creds
        password = os.environ['BIGIP_SECRET']
    else:
        creds = creds.split(':',1)
        username = creds[0]
        password = creds[1]

    url_base = 'https://%s/mgmt' % hostname

    # Disable/supress warnings about unverified SSL:
    requests.packages.urllib3.disable_warnings()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create a new requests session for our big-ip:
    bigip = requests.session()
    bigip.headers.update({'Content-Type':'application/json'})
    bigip.auth = (username, password)
    bigip.verify = False

    token = get_token(bigip, url_base, (username, password))

    bigip.auth = None
    bigip.headers.update({'X-F5-Auth-Token': token})

    # Check GeoDB version prior to upgrade:
    startVersion = test_geoip()

    # Upload ZIP file to BIG-IP:
    print("Uploading GeoIP Zip File...")
    upload_file(url_base, token, geoZipFilePath)

    # Extract zip file & install RPMs:
    print("Extracting ZIP file & Installing RPMs...")
    install_geoip_zip(geoZipFileName)

    # Check GeoDB version post upgrade:
    print("Testing GeoIP DB version...")

    # Compare versions and exit:
    endVersion = test_geoip()
    if int(endVersion) > int(startVersion):
        print("Prior to install GeoIP Version: %s\nPost Install GeoIP Version: %s" % (startVersion, endVersion))
        print("GeoIP DB updated!")
        sys.exit(0)
    else:
        print("Prior to install GeoIP Version: %s\nPost Install GeoIP Version: %s" % (startVersion, endVersion))
        print("ERROR GeoIP DB NOT updated!")
        sys.exit(1)


