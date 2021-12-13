# Use this code snippet in your app.
# If you need more information about configurations or implementing the sample code, visit the AWS docs:   
# https://aws.amazon.com/developers/getting-started/python/

import os
import boto3
import json
import time
import base64
import requests
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError

h_data = {"Content-Type": "application/json; charset=UTF-8"}

def get_env():
    log_env = "unknown"

    if "CI" in os.environ and os.environ.get("CI") == "true":
        log_env = "test"
    else:
        log_env = "production"

    return log_env

def get_parameter():
    paramter_name = 'LogDNAIngestionKey'
    region_name = "us-east-1"

    ssm_client = boto3.client('ssm', region_name=region_name)
    response = ssm_client.get_parameter(
        Name=paramter_name,
        WithDecryption=True
    )
    return response['Parameter']['Value']

def get_secret():

    secret_name = 'LogDNAIngestionKey' # os.environ['LOGGING_KEY']
    region_name = "us-east-1"


    #secrets_client = boto3.client('secretsmanager')
    #secret_arn = "arn:aws:secretsmanager:us-east-1:358663747217:secret:LogDNAIngestionKey-HEKYmj"
    #auth_token = secrets_client.get_secret_value(SecretId=secret_arn).get('logdna-ingestion')

    #return auth_token


    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    secret = '{}'

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
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret).get('logdna-ingestion')

def log_msg(message):
    log_env = get_env()

    try:
        logdna = get_parameter()
    except:
        return

    logdata = {
        "lines": [
            {
                "line": message,
                "app": "glimpse",
                "level": "INFO",
                "env": log_env
            }
        ]
    }

    submission = requests.post('https://logs.logdna.com/logs/ingest?hostname=GLIMPSE&now={}'.format(int(time.time())), json=logdata, headers=h_data, auth=HTTPBasicAuth(logdna, ''))

    if submission.status_code != 200: # or submission.json['status'] != "ok":
        print('Got status {}'.format(submission.status_code))
        print(submission.json())
        #raise ValueError('Got status {}'.format(submission.status_code))



def log_scan(db_data):
    log_env = get_env()

    logdna = get_parameter()


    logdata = {
        "lines": [
            {
                "line": "A new scan was initiated | {}".format(db_data["title"]),
                "app": "glimpse",
                "level": "INFO",
                "env": log_env,
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

    submission = requests.post('https://logs.logdna.com/logs/ingest?hostname=GLIMPSE&now={}'.format(int(time.time())), json=logdata, headers=h_data, auth=HTTPBasicAuth(logdna, ''))

    if submission.status_code != 200: # or submission.json['status'] != "ok":
        print('Got status {}'.format(submission.status_code))
        #raise ValueError('Got status {}'.format(submission.status_code))
