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
- *EventId* - The id of the queue users will be sent to
- *Queue_Baseurl* - The base URL of the queue, must end with trailing slash / e.g. https://[CUSTOMER_ID].queue-it.net/
- *Secret_key* - The secret key that is shared between you and Queue-it
- *Website_Host* - OPTIONAL. If the public facing host name is overwritten in Fastly use this to correct
![Image of Dictionary](https://github.com/queueit/KnownUser.Fastly/blob/master/Dictionary.PNG)

### Add a new Custom VCL
Add a new Custom VCL and call it `Queue-it Connector`. The VCL can be found here: [Queue-it Connector]( https://github.com/queueit/KnownUser.Fastly/blob/master/Queue-it%20Connector.vcl)

### Update the main VCL
In the current main VCL:
1) insert at the top: 
```vcl
include "Queue-it Connector"
```

2) insert inside the *sub vcl_recv {}* before the *return(lookup);*
```vcl
call queueit_recv;
```

3) insert inside the *sub vcl_deliver {}* before the *return(deliver);*
```vcl
if (req.http.Queue-IT-Set-Cookie){
  add resp.http.Set-Cookie = req.http.Queue-IT-Set-Cookie;
}
```

4) insert inside the *sub vcl_error {}*
```vcl
call queueit_error;
```

## Customization
The [Queue-it Connector](https://github.com/queueit/KnownUser.Fastly/blob/master/Queue-it%20Connector.vcl) file needs to be customized a few places to fit the concrete use case.
- There is a list of Good Bots like googlebot, bingbot etc. that are allowed to bypass the queue. This list should be verified against the concrete use case.
- There is a list of Dynamic pages. This list is used to ensure that bad actors cannot bypass the queue by spoofing the User Agent string. No good bot should need to access this list of dynamic pages as only non-personalised pages should be indexed.
- There is a list of URL exceptions that should always be accessible to end-users. This could e.g. be a store locator page. Be careful to only include pages here that can handle large user spikes. 

```vcl
sub queueit_recv {
  declare local var.client_status STRING;
  declare local var.page_type STRING;
  /* First detect if request is not one of the following client types, 
   * otherwise we'll assume they're a customer and set the status. */
  if (req.http.User-Agent ~ "(?i)(ads|google|bing|msn|yandex|baidu|ro|career|face|duckduck|twitter)bot"
      || req.http.User-Agent ~ "(?i)(baidu|jike|symantec)spider"
      || req.http.User-Agent ~ "(?i)scanner"
      || req.http.User-Agent ~ "(?i)(web)crawler"
      || req.http.User-Agent ~ "(?i)facebookexternalhit")  {
  set var.client_status = "bypass"; 
  }
  /* Second check that the URL isn't dynamic like logon, checkout logic etc. 
   * could be exploited if customers spoof the UA string. */
 if (req.url ~ "LogonForm"
    || req.url ~ "OrderItemDisplay"
    || req.url ~ "OrderShippingBillingView"
    || req.url ~ "AjaxLogonForm"
    || req.url ~ "CheckoutPlaceOrder"
    || req.url ~ "MyAccount"
    || req.url ~ "UserRegistrationForm") {
  set var.page_type = "dynamic"; 
  }
  /* Now return request back to main otherwise move to queue. */
  if (var.client_status == "bypass"
    && var.page_type != "dynamic") {
      return;
    }
  /* Now check for URL exceptions*/
  if (req.url ~ "^/stores/locator") {
    return;
  }
  .....
```  

## Limitations
The current implementation only supports one active queue.
Trigger & Action configuration found in Go Queue-it Self-service platform is unsupported.
