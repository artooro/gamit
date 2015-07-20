# Gamit - Google Apps Mitigator

Gamit is a tool written for google apps administrators and currently has the following capabilities

 - Download a user's mailbox
 - Restore a mailbox to a user
 - Export a downloaded mailbox to a human-readable structure
 - Set a forwarding rule for a user
 - Download a user's Google Drive files
 
## Getting Started

Gamit requires an authkey.json configuration file. To generate this file create a Google Cloud project at
https://cloud.google.com/console and configure an API. Enable the Gmail and Drive APIs.
Generate a service account for the API and download the JSON configuration, name it authkey.json and save it inside the
gamit folder.

The final thing you need to do is whitelist the client ID on any Google Apps domains you are going to be using the
tool to operate on.

