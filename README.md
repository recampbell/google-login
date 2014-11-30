google-login
============

A Jenkins plugin which lets you login to Jenkins with your Google account.


To use this plugin, you must obtain OAuth 2.0 credentials
    from the [Google Developers Console](https://console.developers.google.com)

Instructions to create the Client ID and Secret:

 1. Login to the [Google Developers Console](https://console.developers.google.com)
 1. Create a new project
 1. Under APIs & Auth -> Credentials, Create a new Client ID
 1. The application type should be "Web Application"
 1. The authorized redirect URLs should contain ${JENKINS_ROOT_URL}/securityRealm/finishLogin
 1. Enter the created Client Id and secret in the Security Realm Configuration
