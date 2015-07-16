from oauth2client.client import SignedJwtAssertionCredentials
import os
import json
import argparse
from httplib2 import Http
from googleapiclient import discovery
from googleapiclient.http import BatchHttpRequest


KEY_FILE = "%s/oauthkey.json" % os.path.dirname(os.path.realpath(__file__))
print KEY_FILE
SCOPE = ['https://mail.google.com/', 'https://www.googleapis.com/auth/drive']
_version = '1'


class Gamit:
    http_auth = None
    user_email = None

    def __init__(self, user_email):
        self.user_email = user_email
        oauth_key = json.load(file(KEY_FILE, 'r'))
        credentials = SignedJwtAssertionCredentials(oauth_key['client_email'], oauth_key['private_key'], scope=SCOPE,
                                                    user_agent="Gamit %s" % _version, sub=user_email)
        self.http_auth = credentials.authorize(Http())

        # Check if storage folder exists
        data_path = os.path.expanduser("~") + '/gamitdata'
        if not os.path.isdir(data_path):
            os.mkdir(data_path)
            print "Data directory ~/gamitdata initialized"
        user_path = data_path + '/' + self.user_email
        if not os.path.isdir(user_path):
            os.mkdir(user_path)
        mail_path = user_path + '/' + 'mail'
        if not os.path.isdir(mail_path):
            os.mkdir(mail_path)
        self.data_path = data_path
        self.user_path = user_path
        self.mail_path = mail_path

    def download_email(self):
        """
        Download email
        """
        service = discovery.build('gmail', 'v1', http=self.http_auth)

        # Get total number of messages in mailbox
        response = service.users().getProfile(userId=self.user_email).execute()
        total_messages = response['messagesTotal']
        current_count = 0

        def save_message(request_id, response, exception):
            if exception is not None:
                print "There was an exception"
                pass
            else:
                print "Saving message %s" % response['id']
                f = open("%s/%s.json" % (self.mail_path, response['id']), 'w')
                json.dump(response, f)

        def download_messages(messages):
            batch = BatchHttpRequest()
            for message in messages:
                batch.add(service.users().messages().get(userId=self.user_email, id=message['id'], format='raw'),
                          callback=save_message)
            batch.execute(http=self.http_auth)

        response = service.users().messages().list(userId=self.user_email).execute()
        if 'messages' in response:
            current_count = current_count + len(response['messages'])
            print "Downloading %s/%s messages" %(current_count, total_messages)
            download_messages(response['messages'])

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId=self.user_email, pageToken=page_token).execute()
            current_count = current_count + len(response['messages'])
            print "Downloading %s/%s messages" %(current_count, total_messages)
            download_messages(response['messages'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Google Apps Mitigator')
    parser.add_argument('action', help='What action to take on this user', choices=['download_email'])
    parser.add_argument('-u', '--user', help="Email address of user", required=True)
    args = parser.parse_args()

    gamit = Gamit(args.user)
    method = getattr(gamit, args.action)
    method()