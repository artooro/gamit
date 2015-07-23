# Gamit - Google Apps Mitigator

Gamit is a tool written for google apps administrators and currently has the following capabilities

 - Download a user's mailbox
 - Restore a mailbox to a user
 - Download a restorable list of groups from a domain
 - Restore the downloaded list of groups to the same domain name or to a new domain name
 - Export a downloaded mailbox to a human-readable structure
 - Set a forwarding rule for a user
 - Download a user's Google Drive files while keeping the folder structure in place, native docs, slides, and sheets are
  saved as Microsoft Office files

## Getting Started

Gamit requires an authkey.json configuration file. To generate this file create a Google Cloud project at
https://cloud.google.com/console and configure an API. Enable the Gmail and Drive APIs.
Generate a service account for the API and download the JSON configuration, name it authkey.json and save it inside the
gamit folder.

The final thing you need to do is whitelist the client ID on any Google Apps domains you are going to be using the
tool to operate on.

