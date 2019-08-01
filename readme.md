#HTTP Request Smuggler

This is an extension for Burp Suite designed to help you launch [HTTP Request Smuggling](https://portswigger.net/blog/http-desync-attacks) attacks. It supports scanning for Request Smuggling vulnerabilities, and also aids exploitation by handling cumbersome offset-tweaking for you.



###Install

The easiest way to install this is in Burp Suite, via Extender->BApp Store.

If you prefer to load the jar manually, in Burp Suite (community or pro), use Extender->Extensions->Add to load build/libs/desynchronize-all.jar 

###Compile
Build with 'gradle build fatjar'

###Use
Right click on a request and click 'Launch Desync probe', then watch the extension's output pane. 

For more advanced use watch the video at https://portswigger.net/blog/http-desync-attacks

###Practise

We've released free online labs to practise against at   https://portswigger.net/web-security/request-smuggling
