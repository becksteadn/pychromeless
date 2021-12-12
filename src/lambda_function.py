import os
import hashlib
import urllib
import requests
import pprint
from datetime import datetime
import glimpse_driver as gd
from s3_help import S3
from db_help import DynamoDB
import logging_help
from selenium.common.exceptions import WebDriverException

# MD5 hash a string like the URL
def md5_str(string):
    m = hashlib.md5()
    m.update(string.encode('utf-8'))
    return str(m.hexdigest())

# Fail if URL matches any bad words
def filter(url):
    bad_words = ['file://', 'ftp://']
    if any(word in url for word in bad_words):
        raise Exception('suspicious string found in URL')

# Check that the URL leads to a legit web server by
# making a HEAD request before spending resources
# renderiing with Selenium
def check_connection(url):
    requests.head(url, timeout=2.0, verify=False)
    return True

# Main function that is called when function is
# invoked
def lambda_handler(event, context):

    # Decode the url argument and fix if no protocol
    url = urllib.parse.unquote(event['url'])

    logging_help.log_msg('Scan requested for URL: {}'.format(url))

    # Filter for potentially malicious or invalid URLs
    filter(url)

    protocols = ['http', 'https']
    if not any(proto + '://' in url for proto in protocols):
        url = 'http://' + url
    check_connection(url)

    BUCKET_NAME = os.environ.get('GLIMPSE_BUCKET_NAME')
    SCREENSHOT_DIR = os.environ.get('GLIMPSE_SCREENSHOT_DIR')
    DB_TABLE = os.environ.get('GLIMPSE_DB_TABLE')
    pp = pprint.PrettyPrinter(indent=4)

    print('[!] Getting Environment Variables')
    print(f'Using S3 bucket "{BUCKET_NAME}"')
    print(f'    with path "{SCREENSHOT_DIR}"')
    print(f'Using DynamoDB table "{DB_TABLE}"')

    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

    # Calculate MD5 hash of URL
    url_hash = md5_str(url)
    return_data = {'urlhash': url_hash} 
    screenshot_filename = url_hash + '.png'
    local_path = '/tmp/' + screenshot_filename
    remote_path = SCREENSHOT_DIR + screenshot_filename

    db = DynamoDB(DB_TABLE)

    exists = False
    db_data = db.get({'urlhash': url_hash})
    
    if db_data is None:
        db_data = {'urlhash': url_hash, 'url': url, 'timescanned': timestamp, 'numscans': 0}
    else:
        exists = True
        db_data['timescanned'] = timestamp

    # Don't update if update==false or the parameter doesn't exist
    if 'update' not in event.keys() or str(event['update']).lower() != 'true':
        if exists:
            print('[!] Existing Data')
            pp.pprint(return_data)

            print('[!] Logging Scan')
            logging_help.log_msg('Existing data returned for hash {}'.format(url_hash))

            return return_data

    try:
        glimpse = None
        if 'user-agent' in event.keys():
            print(f"[!] Using User-Agent: {event['user-agent']}")
            glimpse = gd.GlimpseDriver(gd.Chromium(ua=event['user-agent']))
        else:
            print('[!] Using default User-Agent: Chrome/61.0')
            glimpse = gd.GlimpseDriver()

        print('[!] Rendering Page')

        glimpse.driver.get(url)

        if not glimpse.verify_user_agent():
            print('[!] User-Agents do not match')
            raise Exception('User-Agents do not match')
        else:
            print('[!] User-Agents match')
        glimpse.screenshot(local_path)
        
        s3 = S3(BUCKET_NAME)
        s3.upload_file(local_path, remote_path)

        db_data['effectiveurl'] = glimpse.driver.current_url
        db_data['title'] = glimpse.driver.title
        if db_data['title'] == '':
            db_data['title'] = 'No title given'

        db_data['net-requests'] = glimpse.get_network_history()

        # Don't need if db_data['numscans'] is set to 0 when
        # the DB GET doesn't exist 
        #if exists:
        #    db_data['numscans'] += 1
        #else:
        #    db_data['numscans'] = 1
        db_data['numscans'] += 1

        print('[!] Adding New Data')
        pp.pprint(db_data)

        db.put(db_data)

        print('[!] Logging Scan')
        logging_help.log_scan(db_data)

        return return_data

    except WebDriverException as e:
        return {'error_message': e.msg}
