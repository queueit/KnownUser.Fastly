# Queue-it KnownUser VCL for Fastly edge computing
The Queue-it Security Framework is used to ensure that end users cannot bypass the queue by adding a custom VCL integration to your Fastly account.
## Introduction
When a user is redirected back from the queue to your website, the queue engine can attach a query string parameter (`queueittoken`) containing some information about the user. 
The most important fields of the `queueittoken` are:

 - q - the users unique queue identifier
 - ts - a timestamp of how long this redirect is valid
 - h - a hash of the token


The high level logic is as follows:

![The KnownUser validation flow](https://github.com/queueit/KnownUser.V3.ASPNET/blob/master/Documentation/KnownUserFlow.png)

 1. User requests a page on your server
 2. The validation method sees that the has no Queue-it session cookie and no `queueittoken` and sends him to the correct queue based on the configuration
 3. User waits in the queue
 4. User is redirected back to your website, now with a `queueittoken`
 5. The validation method validates the `queueittoken` and creates a Queue-it session cookie
 6. The user browses to a new page and the Queue-it session cookie will let him go there without queuing again

## Implementation
There are three steps in the implementation: Add data dictionary, Add custom VCL, update main VCL.

### Add Data Dictionary 
Add a dictionary called `queueit_config` and the followning Keys:
- *CustomerId* - The id of your Queue-it account
- *EventId* - The id of the queue users will be send to
- *Queue_Baseurl* - The base URL of the queue, must end with trailing slash / e.g. https://[CUSTOMER_ID].queue-it.net/
- *Secrete_key* - The secrete key that is shared between you and Queue-it. It can be found in the Go Queue-it account under Account | Settings | Integration
- *Website_Host* - OPTIONAL. If the public facing host name is overwritten in Fastly use this to correct

### Add a new Custom VCL
Add a new Custom VCL and call it `Queue-it Connector`. The VCL can be found here: [Queue-it Connector]( https://github.com/queueit/KnownUser.Fastly/blob/master/Queue-it%20Connector.vcl)

### Update the main VCL
In the current main VCL:
1) insert at the top: 
```vcl
include "Queue-it Connector"
```

2) insert inside the sub vcl_recv {} before the return(lookup);
```vcl
call queueit_recv;
```

3) insert inside the sub vcl_deliver {} before the return(deliver);
```vcl
if (req.http.Queue-IT-Set-Cookie){
  add resp.http.Set-Cookie = req.http.Queue-IT-Set-Cookie;
}
```

4) insert indsite the sub vcl_error {}
```vcl
call queueit_error;
```
