#!/usr/bin/env python
from oauth2client.client import SignedJwtAssertionCredentials
from oauth2client.keyring_storage import Storage
import os
import json
import argparse
from httplib2 import Http
from googleapiclient import discovery
from oauth2client import client
from googleapiclient.http import BatchHttpRequest
import googleapiclient
import googleapiclient.errors
import gdata
import gdata.apps.emailsettings.client
import gdata.gauth
import email
import base64
import unicodedata
import re
import codecs
import time
import datetime


KEY_FILE = "%s/oauthkey.json" % os.path.dirname(os.path.realpath(__file__))
KEY_FILE_NATIVE = "%s/oauth_native.json" % os.path.dirname(os.path.realpath(__file__))
SCOPE = ['https://mail.google.com/', 'https://www.googleapis.com/auth/drive',
         'https://apps-apis.google.com/a/feeds/emailsettings/2.0/',
         'https://www.googleapis.com/auth/admin.directory.group',
         'https://www.googleapis.com/auth/admin.directory.user']
_version = '1'


class Gamit:
    def __init__(self, user_email):
        self.user_email = user_email
        oauth_key = json.load(file(KEY_FILE, 'r'))
        self.oauth_key = oauth_key
        if args.admin is not None:
            sub_user = args.admin
        else:
            sub_user = user_email

        if args.oauth is not None:
            storage = Storage('Gamit', self.user_email)
            credentials = storage.get()
            if not credentials:
                flow = client.flow_from_clientsecrets(
                    KEY_FILE_NATIVE,
                    scope=SCOPE,
                    redirect_uri='urn:ietf:wg:oauth:2.0:oob'
                )
                auth_uri = flow.step1_get_authorize_url()
                print "Open your browser and go to:\n%s" % auth_uri
                auth_code = raw_input('Enter code: ')
                credentials = flow.step2_exchange(auth_code)
                storage.put(credentials)
        else:
            credentials = SignedJwtAssertionCredentials(oauth_key['client_email'], oauth_key['private_key'], scope=SCOPE,
                                                    user_agent="Gamit %s" % _version, sub=sub_user)
        self.http_auth = credentials.authorize(Http())
        self.credentials = credentials

        # Check if storage folder exists
        if args.base is None:
            data_path = os.path.expanduser("~") + '/gamitdata'
        else:
            data_path = args.base + '/gamitdata'
        if not os.path.isdir(data_path):
            os.mkdir(data_path)
            print "Data directory ~/gamitdata initialized"
        user_path = data_path + '/' + self.user_email
        if not os.path.isdir(user_path):
            try:
                os.mkdir(user_path)
            except OSError as e:
                print "Soft error when creating folder: %s" % e
        mail_path = user_path + '/' + 'mail'
        if not os.path.isdir(mail_path):
            try:
                os.mkdir(mail_path)
            except OSError as e:
                print "Soft error when creating folder: %s" % e
        drive_path = user_path + '/' + 'drive'
        if not os.path.isdir(drive_path):
            try:
                os.mkdir(drive_path)
            except OSError as e:
                print "Soft error when creating folder: %s" % e
        self.data_path = data_path
        self.user_path = user_path
        self.mail_path = mail_path
        self.drive_path = drive_path

    def access_info(self):
        print "Client Name: %s" % self.oauth_key['client_id']
        print "Scopes: %s" % ','.join(SCOPE)

    def reset_permissions(self):
        if args.src is None:
            print "You must provide the parent ID of a folder to start with"
            return None

        service = discovery.build('drive', 'v2', http=self.http_auth)

        try:
            parent = service.files().get(fileId=args.src).execute()
        except googleapiclient.errors.HttpError, error:
            print "Was not able to fetch parent ID, %s" % error
            return None

        def walk_folder(folder_id):
            page_token = None
            while True:
                try:
                    param = {}
                    if page_token:
                        param['pageToken'] = page_token
                    children = service.children().list(
                        folderId=folder_id, **param).execute()
                except googleapiclient.errors.HttpError, error:
                    print "An error occurred, %s" % error
                    break

                for child in children.get('items', []):
                    print 'File ID: %s' % child['id']

                    # Reset permissions on that ID
                    while True:
                        try:
                            perm_list = service.permissions().list(fileId=child['id']).execute()
                            break
                        except googleapiclient.errors.HttpError, error:
                            print "Error when getting permission list, %s" % error
                            try:
                                details = json.loads(error.content)['error']
                                if details.get('code') in (404):
                                    for err in details.get('errors', []):
                                        print "Error: %s Reason: %s" % (err['message'], err['reason'])
                                    break
                                else:
                                    print error.content
                            except:
                                print error
                            print "Re-trying request in 5 seconds"
                            time.sleep(5)

                    for perm in perm_list.get('items', []):
                        if perm['role'] != 'owner':
                            perm_name = 'N/A'
                            if perm.get('name'):
                                perm_name = perm['name']
                            elif perm.get('emailAddress'):
                                perm_name = perm['emailAddress']
                            print "Removing Permissions for %s" % perm_name
                            while True:
                                try:
                                    service.permissions().delete(fileId=child['id'], permissionId=perm['id']).execute()
                                    break
                                except googleapiclient.errors.HttpError, error:
                                    print "Error when deleting permission, %s" % error
                                    print perm
                                    try:
                                        details = json.loads(error.content)['error']
                                        if details.get('code') in (403, 404):
                                            for err in details.get('errors', []):
                                                print "Error: %s Reason: %s" % (err['message'], err['reason'])
                                            break
                                        else:
                                            print error.content
                                    except:
                                        print error
                                    print "Re-trying request in 5 seconds"
                                    time.sleep(5)
                    while True:
                        try:
                            file_info = service.files().get(fileId=child['id'], fields='mimeType').execute()
                            break
                        except googleapiclient.errors.HttpError, error:
                            print "Error when getting file info, %s" % error
                            try:
                                details = json.loads(error.content)['error']
                                if details.get('code') in (404):
                                    for err in details.get('errors', []):
                                        print "Error: %s Reason: %s" % (err['message'], err['reason'])
                                    break
                                else:
                                    print error.content
                            except:
                                print error
                            print "Re-trying request in 5 seconds"
                            time.sleep(5)

                    if file_info['mimeType'] == 'application/vnd.google-apps.folder':
                        walk_folder(child['id'])
                page_token = children.get('nextPageToken')
                if not page_token:
                    break

        walk_folder(parent['id'])

    def download_groups(self):
        service = discovery.build('admin', 'directory_v1', http=self.http_auth)
        domain = self.user_email.split('@')[1]

        response = service.groups().list(domain=domain).execute()
        groups = []
        page_token = None
        while page_token is not False:
            for group in response['groups']:
                print "Fetching members for group %s" % group['email']
                page_token2 = None
                members = []
                while page_token2 is not False:
                    if page_token2 is None:
                        members_response = service.members().list(groupKey=group['id']).execute()
                    else:
                        members_response = service.members().list(groupKey=group['id'], pageToken=page_token2).execute()

                    for member in members_response.get('members', []):
                        members.append(member)

                    if 'nextPageToken' in members_response:
                        page_token2 = members_response['nextPageToken']
                    else:
                        page_token2 = False

                groups.append({
                    'group': group,
                    'members': members
                })

            response = service.groups().list(domain=domain, pageToken=response['nextPageToken']).execute()
            if 'nextPageToken' in response:
                page_token = response['nextPageToken']
            else:
                page_token = False

        file_name = "%s/groups_%s.json" % (self.data_path, domain)
        f = open(file_name, 'w')
        json.dump(groups, f)
        f.close()
        print "Groups have been saved to %s" % file_name

    def restore_groups(self):
        if args.src is None:
            print "You must provide a data file to restore groups from"
            return None

        service = discovery.build('admin', 'directory_v1', http=self.http_auth)

        f = open(args.src, 'r')
        data = json.load(f)
        for group in data:
            time.sleep(2)  # Wait to prevent exceeding request rate
            if args.domain is None:
                primary_email = group['group']['email']
            else:
                primary_email = "%s@%s" % (group['group']['email'].split('@')[0], args.domain)
            print "Creating group: %s" % primary_email
            group_obj = {
                'email': primary_email,
                'description': group['group']['description'],
                'name': group['group']['name']
            }
            try:
                new_group = service.groups().insert(body=group_obj).execute()
            except googleapiclient.errors.HttpError, e:
                try:
                    data = json.loads(e.content)
                except:
                    print e
                    continue
                if data['error']['code'] == 409:
                    print "Group already exists"
                else:
                    print e.content

            # Add members to group
            for member in group['members']:
                if member['type'] == 'CUSTOMER':
                    continue  # We don't support CUSTOMER types at this point
                member_obj = {
                    'role': member['role'],
                    'email': member['email']
                }
                print "Adding member %s" % member['email']
                try:
                    service.members().insert(groupKey=primary_email, body=member_obj).execute()
                except googleapiclient.errors.HttpError, e:
                    try:
                        data = json.loads(e.content)
                    except:
                        print e
                        continue
                    if data['error']['code'] == 409:
                        print "Member already exists, skipping"
                        time.sleep(1)
                    else:
                        print e.content


            # Add aliases to group
            for alias in group['group'].get('aliases', []):
                if args.domain is None:
                    alias_email = alias
                else:
                    alias_email = "%s@%s" % (alias.split('@')[0], args.domain)
                print "Adding alias to group: %s" % alias_email
                try:
                    service.groups().aliases().insert(groupKey=primary_email, body={'alias': alias_email}).execute()
                except googleapiclient.errors.HttpError, e:
                    try:
                        data = json.loads(e.content)
                    except:
                        print e
                        continue
                    if data['error']['code'] == 409:
                        print "Alias already exists, skipping"
                        time.sleep(1)
                    else:
                        print e.content

            print "Finished creating group"

    def download_prev(self):
        if args.date is None:
            print "Must provide --date argument"
            return None
        service = discovery.build('drive', 'v2', http=self.http_auth)

        file_list = []
        page_token = None
        print "Downloading list of files"
        while True:
            try:
                param = {}
                if page_token:
                    param['pageToken'] = page_token
                files = service.files().list(**param).execute()

                file_list.extend(files['items'])
                page_token = files.get('nextPageToken')
                if not page_token:
                    break
            except googleapiclient.errors.HttpError, e:
                print "There was an error: %s" % e
                time.sleep(5)

        print "Walking through list of files"
        revert_to = datetime.datetime.strptime(args.date, '%Y-%m-%d')
        for df in file_list:
            if df['mimeType'] == 'application/vnd.google-apps.folder':
                continue  # skipping folder which does not support revisions
            file_title = df['title'].encode('utf-8', 'ignore')
            print "\n%s" % file_title
            print "Type: %s" % df['mimeType']

            resp = service.revisions().list(fileId=df['id']).execute()
            most_recent_found = None
            for rev in resp.get('items', []):
                print "--Found revision: %s" % rev['modifiedDate']
                rev_date = datetime.datetime.strptime(rev['modifiedDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
                if rev_date <= revert_to:
                    print "Is eligible for reversion"
                    if most_recent_found is None:
                        most_recent_found = rev
                        print "This is the only good revision we know of so far"
                    elif rev_date > datetime.datetime.strptime(most_recent_found['modifiedDate'], '%Y-%m-%dT%H:%M:%S.%fZ'):
                        most_recent_found = rev
                        print "This is now the most recent good revision"
                    else:
                        print "We already found a revision newer than this one"
                else:
                    print "It too new for reversion"
            if most_recent_found is not None:
                print "#Looking like we could revert to revision modified %s" % most_recent_found['modifiedDate']
                while True:
                    download_url = most_recent_found.get('downloadUrl')
                    if not download_url:
                        if most_recent_found['mimeType'] == 'application/vnd.google-apps.spreadsheet':
                            export_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                            file_ext = 'xlsx'
                        elif most_recent_found['mimeType'] == 'application/vnd.google-apps.presentation':
                            export_type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                            file_ext = 'pptx'
                        elif most_recent_found['mimeType'] == 'application/vnd.google-apps.document':
                            export_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                            file_ext = 'docx'
                        elif most_recent_found['mimeType'] == 'application/vnd.google-apps.drawing':
                            export_type = 'application/pdf'
                            file_ext = 'pdf'
                        elif most_recent_found['mimeType'] == 'application/vnd.google-apps.script':
                            export_type = 'application/vnd.google-apps.script+json'
                            file_ext = 'json'
                        else:
                            print "This type is unsupported for download: %s" % most_recent_found['mimeType']
                            break
                        download_url = most_recent_found['exportLinks'][export_type]
                        file_name = "%s.%s" % (file_title, file_ext)
                    else:
                        file_name = most_recent_found['originalFilename'].encode('utf-8', 'ignore')

                    try:
                        file_name = file_name.replace('/', '-')
                        if len(file_name) > 200:
                            # Shorten file name to 200 characters
                            file_name = file_name[:200]

                        save_path = "%s/%s" % (self.drive_path, file_name)
                        if os.path.exists(save_path):
                            print "Path %s exists" % save_path
                            incr = 1
                            while True:
                                save_path = "%s/%s.%s" % (self.drive_path, incr, file_name)
                                if not os.path.exists(save_path):
                                    print "Changed path to %s" % save_path
                                    break
                                else:
                                    incr += 1

                        # If file has already been downloaded skip it
                        if os.path.exists(save_path):
                            print "File already exists"
                            break

                        resp, content = service._http.request(download_url)
                        if resp.status == 200:
                            print "Saving file %s" % file_name
                            f = open(save_path, 'w')
                            f.write(content)
                            f.close()
                            break
                        else:
                            if resp.status == 429:
                                # Too many requests, back off for 10 seconds
                                print "Too many requests, going to back off for a bit"
                                time.sleep(10)
                            elif resp.status == 400:
                                print "Data error: %s" % resp
                                time.sleep(1)
                                break
                            elif resp.status == 503:
                                print "Error 503 does not seem to recover, sleep for 15 seconds and go to next"
                                time.sleep(15)
                                break
                            elif resp.status == 403:
                                print "Access forbidden: %s" % resp
                                time.sleep(1)
                                break
                            elif resp.status == 404:
                                print "Item not found: %s" % resp
                                time.sleep(1)
                                break
                            else:
                                print "Unknown error: %s" % resp
                                print "Sleeping for 1 second before trying again"
                                time.sleep(1)
                    except googleapiclient.errors.HttpError, e:
                        print "Error occured: %s" % e.content
                        print "Going to re-try download in 1 second"
                        time.sleep(1)
            else:
                print "!This file has no revisions we can revert to"

    def download_drive(self):
        service = discovery.build('drive', 'v2', http=self.http_auth)

        file_list = []
        page_token = None
        print "Downloading list of files"
        while True:
            try:
                param = {}
                if page_token:
                    param['pageToken'] = page_token
                files = service.files().list(**param).execute()

                file_list.extend(files['items'])
                page_token = files.get('nextPageToken')
                if not page_token:
                    break
            except googleapiclient.errors.HttpError, e:
                print "There was an error: %s" % e
                time.sleep(5)

        parent_cache = {}

        def get_file_path(fr):
            if len(fr['parents']) < 1:
                return '/'

            result = parent_cache.get(fr['parents'][0]['id'])
            if result:
                return result

            print "Building path for this parent ID: %s" % fr['parents'][0]['id']
            last_item = None
            parent_path = ''
            while True:
                if last_item is None:
                    last_item = fr
                if len(last_item['parents']) < 1:
                    parent_path += '/'
                    break
                if last_item['parents'][0]['isRoot'] is True:
                    parent_path += '/'
                    break
                else:
                    parent_item = service.files().get(fileId=last_item['parents'][0]['id']).execute()
                    parent_path = "/%s/%s" % (parent_item['title'].encode('utf-8', 'ignore'), parent_path)
                    last_item = parent_item

            parent_cache[fr['parents'][0]['id']] = parent_path
            # Make sure path exists on the filesystem
            path = self.drive_path + parent_path
            if not os.path.isdir(path):
                print "Creating path: %s" % path
                print "Parent path is: %s" % parent_path
                os.makedirs(path)

            return parent_path

        for fr in file_list:
            fr_title = fr['title'].encode('utf-8', 'ignore')
            print "Downloading file %s" % fr_title
            if fr['mimeType'] == 'application/vnd.google-apps.folder':
                print "File is a folder, skipping"
                continue

            while True:
                download_url = fr.get('downloadUrl')
                if not download_url:
                    if fr['mimeType'] == 'application/vnd.google-apps.spreadsheet':
                        export_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                        file_ext = 'xlsx'
                    elif fr['mimeType'] == 'application/vnd.google-apps.presentation':
                        export_type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                        file_ext = 'pptx'
                    elif fr['mimeType'] == 'application/vnd.google-apps.document':
                        export_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                        file_ext = 'docx'
                    elif fr['mimeType'] == 'application/vnd.google-apps.drawing':
                        export_type = 'application/pdf'
                        file_ext = 'pdf'
                    elif fr['mimeType'] == 'application/vnd.google-apps.script':
                        export_type = 'application/vnd.google-apps.script+json'
                        file_ext = 'json'
                    else:
                        print "This type is unsupported for download: %s" % fr['mimeType']
                        break
                    download_url = fr['exportLinks'][export_type]
                    file_name = "%s.%s" % (fr_title, file_ext)
                else:
                    file_name = fr['originalFilename'].encode('utf-8', 'ignore')

                try:
                    file_name = file_name.replace('/', '-')
                    if len(file_name) > 200:
                        # Shorten file name to 200 characters
                        file_name = file_name[:200]
                    file_name = "%s%s" % (get_file_path(fr), file_name)

                    # If file has already been downloaded skip it
                    if os.path.exists("%s%s" % (self.drive_path, file_name)):
                        print "File already exists"
                        break

                    resp, content = service._http.request(download_url)
                    if resp.status == 200:
                        print "Saving file %s" % file_name
                        file_save_path = "%s%s" % (self.drive_path, file_name)
                        f = open(file_save_path, 'w')
                        f.write(content)
                        f.close()
                        break
                    else:
                        if resp.status == 429:
                            # Too many requests, back off for 10 seconds
                            print "Too many requests, going to back off for a bit"
                            time.sleep(10)
                        elif resp.status == 400:
                            print "Data error: %s" % resp
                            time.sleep(1)
                            break
                        elif resp.status == 503:
                            print "Error 503 does not seem to recover, sleep for 15 seconds and go to next"
                            time.sleep(15)
                            break
                        elif resp.status == 403:
                            print "Access forbidden: %s" % resp
                            time.sleep(1)
                            break
                        elif resp.status == 404:
                            print "Item not found: %s" % resp
                            time.sleep(1)
                            break
                        else:
                            print "Unknown error: %s" % resp
                            print "Sleeping for 1 second before trying again"
                            time.sleep(1)
                except googleapiclient.errors.HttpError, e:
                    print "Error occured: %s" % e.content
                    print "Going to re-try download in 1 second"
                    time.sleep(1)

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

    def restore_email(self):
        if args.src is None:
            print "You must provide a source user address"
            return None

        service = discovery.build('gmail', 'v1', http=self.http_auth)

        # Start by rebuilding labels
        existing_labels = []
        labels_resp = service.users().labels().list(userId=self.user_email).execute()
        for label in labels_resp['labels']:
            existing_labels.append(label['name'])

        mail_path = "%s/%s/mail" % (self.data_path, args.src)
        f = open(mail_path+ '/labels.json', 'r')
        labels = json.load(f)
        for label in labels['labels']:
            if label['type'] == 'system':
                continue
            if label['name'] in existing_labels:
                continue
            label_obj = {
                'messageListVisibility': label.get('messageListVisibility', 'show'),
                'name': label['name'],
                'labelListVisibility': label.get('labelListVisibility', 'labelShow')
            }
            print "Creating label with name: %s" % label['name']
            try:
                service.users().labels().create(userId=self.user_email, body=label_obj).execute()
            except googleapiclient.errors.HttpError, e:
                print e

        # Map old label IDs to their new label IDs
        label_map = {}
        new_labels = service.users().labels().list(userId=self.user_email).execute()
        for new_label in new_labels['labels']:
            for label in labels['labels']:
                if label['name'] == new_label['name']:
                    label_map[label['id']] = new_label['id']

        # Restore emails
        mail_dir = "%s/%s/mail" % (self.data_path, args.src)

        file_list = os.listdir(mail_dir)
        num_of_files = len(file_list) - 2
        num_restored = 0

        for msg_file in file_list:
            if os.path.exists("%s/%s.done" % (mail_dir, msg_file)):
                num_restored += 1
                print "Message %s/%s already restored" % (num_restored, num_of_files)
                continue

            if not msg_file.endswith('.json'):
                continue
            if msg_file == 'labels.json':
                continue
            data = json.load(open("%s/%s" % (mail_dir, msg_file)))

            # Skip chat messages
            if 'CHAT' in data.get('labelIds', []):
                num_restored += 1
                continue

            label_ids = []
            for lbl in data.get('labelIds', []):
                if label_map.get(lbl) is None:
                    print "Label with ID %s cannot be matched to new account" % lbl
                    continue
                label_ids.append(label_map[lbl])

            email_obj = {
                'labelIds': label_ids
            }

            def http_callback(resp, content):
                try:
                    print "Restored message %s" % json.loads(content)['id']
                except:
                    print "Error in HTTP request"
                    print resp

            while True:
                multi_part_body = "--gamit_multipart_bound\nContent-Type: application/json; charset=UTF-8\n" \
                                  "\n%s\n\n--gamit_multipart_bound\nContent-Type: message/rfc822\n\n%s\n" \
                                  "--gamit_multipart_bound--" % (
                    json.dumps(email_obj),
                    base64.urlsafe_b64decode(data['raw'].encode('ASCII'))
                )

                try:
                    googleapiclient.http.HttpRequest(http=self.http_auth, postproc=http_callback,
                                           uri="https://www.googleapis.com/upload/gmail/v1/users/%s/messages/import?uploadType=%s" % (
                                               self.user_email,
                                               'multipart'
                                           ), method='POST', body=multi_part_body,
                                                           headers={'Content-Type': 'multipart/related; boundary="gamit_multipart_bound"'}).execute()

                    # Save migrated status file
                    sf = open("%s/%s.done" % (mail_dir, msg_file), 'w')
                    sf.write("\n")
                    sf.close()
                    break
                except googleapiclient.http.HttpError, e:
                    try:
                        error = json.loads(e.content)['error']
                        if error.get('code') == 400:
                            for err in error.get('errors', []):
                                print "Error: %s Reason: %s" % (err['message'], err['reason'])
                            break  # Email cannot be migrated so don't re-try this request
                        else:
                            print e.content
                    except:
                        print e
                    print "Re-trying request in 1 second"
                    time.sleep(1)

            num_restored += 1
            print "Restored %s/%s emails" % (num_restored, num_of_files)

    def download_email(self):
        print "Starting download at %s" % datetime.datetime.now().isoformat()
        service = discovery.build('gmail', 'v1', http=self.http_auth)

        # Get total number of messages in mailbox
        response = service.users().getProfile(userId=self.user_email).execute()
        total_messages = response['messagesTotal']
        current_count = 0

        # Save labels
        labels_resp = service.users().labels().list(userId=self.user_email).execute()
        f = open(self.mail_path + '/labels.json', 'w')
        json.dump(labels_resp, f)
        f.close()

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

        page_token = None
        while page_token is not False:
            # Try listing messages
            try:
                if page_token is None:
                    response = service.users().messages().list(userId=self.user_email).execute()
                else:
                    response = service.users().messages().list(userId=self.user_email, pageToken=page_token).execute()

                # Try downloading messages
                try:
                    for message in response.get('messages', []):
                        # Check if message is already downloaded
                        if os.path.exists("%s/%s.json" % (self.mail_path, message['id'])):
                            print "Message %s has already been downloaded" % message['id']
                            response['messages'].remove(message)
                            print "Length of list is now %s" % len(response['messages'])
                    if len(response.get('messages', [])) <= 0:
                        print "This batch has already been downloaded"
                    else:
                        download_messages(response['messages'])
                        current_count = current_count + len(response['messages'])
                        print "Downloading %s/%s messages" % (current_count, total_messages)
                    if 'nextPageToken' in response:
                        page_token = response['nextPageToken']
                    else:
                        page_token = False
                except:
                    print "Problem downloading batch of messages, will re-try in 1 second"
                    time.sleep(1)
            except:
                print "Problem with listing messages for download. Will re-try in 1 second"
                time.sleep(1)

        print "Ended download at %s" % datetime.datetime.now().isoformat()


def safe_filename(filename):
    value = unicodedata.normalize('NFKD', filename).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\\.s-]', '', value).strip().lower())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Google Apps Mitigator')
    parser.add_argument('action', help='What action to take on this user', choices=['download_email', 'set_forward',
                                                                                    'mail_export_to_files',
                                                                                    'download_drive', 'restore_email',
                                                                                    'download_groups', 'restore_groups',
                                                                                    'access_info', 'download_prev',
                                                                                    'reset_permissions'])
    parser.add_argument('-u', '--user', help="Email address of user", required=True)
    parser.add_argument('-b', '--base', help='Path of base folder to store gamitdata')
    parser.add_argument('-a', '--admin', help='Domain administrator user')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-f', '--forward', help='Email address to forward to')
    parser.add_argument('-s', '--src', help='Source email address or path to file to restore from')
    parser.add_argument('--oauth', help='Authenticate as a user vs. using a service account')
    parser.add_argument('--date', help='Date in format YYYY-MM-DD')
    args = parser.parse_args()

    gamit = Gamit(args.user)
    method = getattr(gamit, args.action)
    method()