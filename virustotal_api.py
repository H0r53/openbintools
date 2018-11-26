#!/usr/bin/python3

"""
    File:
        - virustotal_api.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart

    Date: 11/24/2018

    Description:
        - A shim for using the VirusTotal API to communicate with VirusTotal Services.
         The shim sends a queue to VirusTotal through the queue() function then retrieves
         the result via the report() function.

        - A valid VirusTotal Community API key must be copied below where you see:
            APIKEY = 'Copy your personal VirusTotal Community API key here'

        - For more information on the VirusTotal API see:
            https://www.virustotal.com/en/documentation/public-api/

        if __name__ == "__main__":
            docs()

    Changelog:
        - 11/25 Handle when a correct API key has not been supplied
        - 11/24 Documented
        - 11/24 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/24 Expanded single line list comprehensions into readable loops
        - 11/24 PyLint score ??? --> 10.00/10
"""

from requests import get, post

APIKEY = 'Copy your personal VirusTotal Community API key here'


def docs():
    """
    Function:
        virustotal_api.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(queue.__doc__)
    print(reports.__doc__)


def queue(filename):
    """
    Function:
        virustotal_api.queue()

        Description:
            - Sends a file with the VirusTotal API to performs the first part of the
            request to VirusTotal: https://www.virustotal.com/vtapi/v2/file/scan .

        Parameters:
            - filename:
                Description - path to target file,
                Data Type - string,
                Requirement - mandatory,
                Argument Type - Positional(1st)

        Return:
            - response.json():
                Description - Response from VirusTotal after sending or queue request.
                Data Type - JSON Object
    """
    params = {
        'apikey': APIKEY
    }

    files = {
        'file': (
            filename,
            open(filename, 'rb')
        )
    }

    response = post(
        'https://www.virustotal.com/vtapi/v2/file/scan',
        files=files,
        params=params
    )
    print(response)
    try:
        return response.json()
    except ValueError as error:
        if response.status_code == 403:
            retval = "Error: Missing VirusTotal API Key"
        else:
            retval = error
        return retval


def reports(resource):
    """
    Function:
        virustotal_api.reports()

        Description:
            - Performs the second half of running a file against VirusTotal.

            - Using the resource key provided in the queue response check and retrieve
            results from VirusTotal.


        Parameters:
            - resource:
                Description - resource key corresponding to our request made with the queue()
                Data Type - String / Hex String ,
                Requirement - mandatory,
                Argument Type - Positional(1st)

        Return:
            - retval:
                Description - Result of the VirusTotal Scan
                Data Type - string
    """
    params = {
        'apikey': APIKEY,
        'resource': resource
    }

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }

    response = get(
        'https://www.virustotal.com/vtapi/v2/file/report',
        params=params,
        headers=headers
    )

    data = response.json()

    detections = []
    for vendor in data['scans']:
        if data['scans'][vendor]['detected'] is True:
            detections.append([vendor, data['scans'][vendor]])

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
        data['permalink']
    )

    if detections:
        retval += "\ndetections:"
        for vendor in detections:
            retval += "\n\tvendor: {}, detected: true, version: {}, result: {}, update: {}".format(
                vendor[0],
                vendor[1]['version'],
                vendor[1]['result'],
                vendor[1]['update']
            )

    return retval


if __name__ == "__main__":
    docs()
