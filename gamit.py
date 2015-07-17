from oauth2client.client import SignedJwtAssertionCredentials
import os
import json
import argparse
from httplib2 import Http
from googleapiclient import discovery
from googleapiclient.http import BatchHttpRequest
import gdata
import gdata.apps.emailsettings.client
import gdata.gauth
import email
import base64
import datetime
import unicodedata
import re
import codecs


KEY_FILE = "%s/oauthkey.json" % os.path.dirname(os.path.realpath(__file__))
SCOPE = ['https://mail.google.com/', 'https://www.googleapis.com/auth/drive',
         'https://apps-apis.google.com/a/feeds/emailsettings/2.0/']
_version = '1'


class Gamit:
    def __init__(self, user_email):
        self.user_email = user_email
        oauth_key = json.load(file(KEY_FILE, 'r'))
        if args.admin is not None:
            sub_user = args.admin
        else:
            sub_user = user_email
        credentials = SignedJwtAssertionCredentials(oauth_key['client_email'], oauth_key['private_key'], scope=SCOPE,
                                                    user_agent="Gamit %s" % _version, sub=sub_user)
        self.http_auth = credentials.authorize(Http())
        self.credentials = credentials

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

    def download_drive(self):
        service = discovery.build('drive', 'v2', http=self.http_auth)

        result = []
        page_token = None
        while True:
            param = {}
            if page_token:
                param['pageToken'] = page_token
            files = service.files().list(**param).execute()

            result.extend(files['items'])
            page_token = files.get('nextPageToken')
            if not page_token:
                break
        print result

    def mail_export_to_files(self):
        save_dir = "%s/export" % self.mail_path
        if not os.path.isdir(save_dir):
            os.mkdir(save_dir)

        file_list = os.listdir(self.mail_path)
        num_of_files = len(file_list) - 3
        num_saved = 0

        for msg_file in file_list:
            if not msg_file.endswith('.json'):
                continue
            data = json.load(open("%s/%s" % (self.mail_path, msg_file)))
            msg = email.message_from_string(base64.urlsafe_b64decode(data['raw'].encode('ASCII')))
            body = ''
            html = ''
            subject = msg['Subject']
            labels = ' '.join(data['labelIds'])
            internal_date = datetime.datetime.fromtimestamp((float(data['internalDate'])) / 1000).isoformat()
            msg_id = data['id']

            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain':
                    body = body + part.get_payload(decode=True)
                elif content_type == 'text/html':
                    html = html + part.get_payload(decode=True)
                else:
                    if part.is_multipart():
                        continue

                    # This is an attachment
                    filename = part.get_filename()
                    if not filename:
                        filename = 'inline.%s' % part.get_content_type().replace('/', '.')
                    filename = safe_filename(unicode(filename))

                    save_path = "%s/%s_%s" % (save_dir, msg_id, filename)
                    f = open(save_path, 'w')
                    f.write(part.get_payload(decode=True))
                    f.close()
                    print "Attachment saved to %s" % save_path

            if html != '':
                html_path = "%s/%s.html" % (save_dir, msg_id)
                f = open(html_path, 'w')
                f.write(html)
                f.close()

            if num_saved == 24:
                print body

            text_file = """
Subject: %s
Date & Time: %s
Labels: %s
Body:
%s
            """ % (
                subject,
                internal_date,
                labels,
                body.decode('utf-8', 'ignore')
            )
            txt_path = "%s/%s.txt" % (save_dir, msg_id)
            with codecs.open(txt_path, 'w', encoding='utf-8') as f:
                f.write(text_file)
                f.close()

            num_saved += 1
            print "Saved %s/%s emails" % (num_saved, num_of_files)

    def set_forward(self):
        if args.domain is None:
            print "You must provide the domain name"
            return None
        if args.forward is None:
            print "You must provide an email address"
            return None
        if args.admin is None:
            print "You must specify a domain administrator user"
            return None

        auth2token = gdata.gauth.OAuth2TokenFromCredentials(self.credentials)
        client = gdata.apps.emailsettings.client.EmailSettingsClient(domain=args.domain)
        auth2token.authorize(client)
        client.UpdateForwarding(username=self.user_email, enable=True, forward_to=args.forward, action='ARCHIVE')

    def download_email(self):
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


def safe_filename(filename):
    value = unicodedata.normalize('NFKD', filename).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\\.s-]', '', value).strip().lower())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Google Apps Mitigator')
    parser.add_argument('action', help='What action to take on this user', choices=['download_email', 'set_forward',
                                                                                    'mail_export_to_files',
                                                                                    'download_drive'])
    parser.add_argument('-u', '--user', help="Email address of user", required=True)
    parser.add_argument('-a', '--admin', help='Domain administrator user')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-f', '--forward', help='Email address to forward to')
    args = parser.parse_args()

    gamit = Gamit(args.user)
    method = getattr(gamit, args.action)
    method()