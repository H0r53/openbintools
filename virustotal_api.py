#!/usr/bin/python3
import requests
APIKEY = ''

def queue(filename):
    params = {'apikey': APIKEY}
    files = {'file': (filename, open(filename,'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    return response.json()

def reports(resource):
    params = {'apikey': APIKEY, 'resource': resource}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username" }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    data = response.json()

    detections = [[vendor,data['scans'][vendor]] for vendor in data['scans'] if data['scans'][vendor]['detected'] == True]

    retval = """
response_code:\t{}
verbose_msg:\t{}
resource:\t{}
scan_id:\t{}
md5:\t\t{}
sha1:\t\t{}
sha256:\t\t{}
scan_date:\t{}
positives:\t{}
total:\t\t{}
permalink:\t{}
    """.format(
    data['response_code'],
    data['verbose_msg'],
    data['resource'],
    data['scan_id'],
    data['md5'],
    data['sha1'],
    data['sha256'],
    data['scan_date'],
    data['positives'],
    data['total'],
    data['permalink'])

    if len(detections) > 0:
        retval += "\ndetections:"
        for vendor in detections:
            retval += "\n\tvendor: {}, detected: true, version: {}, result: {}, update: {}".format(vendor[0],vendor[1]['version'],vendor[1]['result'],vendor[1]['update'])


    return retval
