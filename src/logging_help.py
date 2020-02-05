# Use this code snippet in your app.
# If you need more information about configurations or implementing the sample code, visit the AWS docs:   
# https://aws.amazon.com/developers/getting-started/python/

import os
import boto3
import json
import base64
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError

def get_secret():

    secret_name = 'LogDNAIngestionKey' # os.environ['LOGGING_KEY']
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    secret = 'default'

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        print(get_secret_value_response)
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret)

def log_scan(db_data):
    logdna = get_secret()

    logdata = {
        "lines": [
            {
                "line": "A new scan was initiated.",
                "app": "glimpse",
                "level": "INFO",
                "env": "experiment",
                "meta": {
                    "urlhash": db_data["urlhash"],
                    "url": db_data["url"],
                    "effectiveurl": db_data["effectiveurl"],
                    "title": db_data["title"],
                    "timescanned": db_data["timescanned"],
                    "numscans": int(db_data["numscans"])
                }
            }
        ]
    }

    h_data = {"Content-Type": "application/json; charset=UTF-8"}

    submission = requests.post('https://logs.logdna.com/logs/ingest?hostname=GLIMPSE', json=logdata, headers=h_data, auth=HTTPBasicAuth(logdna['logdna-ingestion'], ''))

    if submission.status_code != 200: # or submission.json['status'] != "ok":
        raise ValueError('Got status {}'.format(submission.status_code))
