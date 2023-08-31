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
  else {
  call queueit_recv_internal;
    /* strip queueittoken from query string if present */
    if (req.url ~ "[?&]queueittoken=") {
        declare local var.location STRING;
        declare local var.host STRING;
        set var.host = if(table.lookup(queueit_config, "Website_Host"), table.lookup(queueit_config, "Website_Host"), req.http.host);
        set var.location = if(req.is_ssl, "https://", "http://") + var.host
          + querystring.filter(req.url, "queueittoken");
    error 602 var.location;
    }
  }
}

sub queueit_recv_internal {
  declare local var.location STRING;
  /* PageUrl contains the protocol, the Host header and the path */
  declare local var.pageurl STRING;
  declare local var.host STRING;
  set var.host = if(table.lookup(queueit_config, "Website_Host"), table.lookup(queueit_config, "Website_Host"), req.http.host);
  set var.pageurl = if(req.is_ssl, "https://", "http://") + var.host + req.url;
  /*
   * Variables (like var.pageurl above) are only local, not request wide. So we use
   * request headers to store things for other subs. We unset them at the start to prevent
   * their presence in the request from the client from doing anything (untoward).
   * But only do this the first time we process a particular request.
   */
  if (req.restarts == 0) {
    unset req.http.Queue-IT-EventId;
    unset req.http.Queue-IT-Cookie-Valid;
    unset req.http.Queue-IT-Token-Valid;
    unset req.http.Queue-IT-Set-Cookie;
    unset req.http.Queue-IT-Error;
    unset req.http.Queue-IT-Token;
    unset req.http.Queue-IT-Script-Version;
  }
  set req.http.Queue-IT-Script-Version = "fastly-vcl-1.0&cver=0";
  set req.http.Queue-IT-EventId = table.lookup(queueit_config, "EventId");
  call validate_Queueit_cookie;
  if (req.http.Queue-IT-Cookie-Valid == "true") {
    /* valid cookie, do nothing */
    return;
  }
  call validate_queueit_token;
  if (req.http.Queue-IT-Token-Valid == "true") {
    /* valid token, do nothing */
    return;
  }
  /* No Cookie, no token, redirect to queue
   * URL comprises of the base URL, queueit variables and the page URL. */
  set var.location = table.lookup(queueit_config, "Queue_Baseurl")
              + "?c=" + table.lookup(queueit_config, "CustomerId") 
              + "&e=" + table.lookup(queueit_config, "EventId") 
              + "&ver=" + req.http.Queue-IT-Script-Version
              + "&t=" + urlencode(var.pageurl);
  error 602 var.location;

}

sub validate_Queueit_cookie {
  declare local var.decoded_cookie STRING;
  declare local var.extendable STRING;
  declare local var.expires STRING;
  declare local var.hash STRING;
  declare local var.queueid STRING;
  declare local var.computed_hash STRING;
  declare local var.exptime TIME;
  declare local var.cookie_exp STRING;
  declare local var.cookie_eventId STRING;
  /* Prefix with a `?` to fool querystring into sorting things */
  set var.decoded_cookie = "?" + urldecode(req.http.Cookie:QueueITAccepted-SDFrts345E);
  set var.decoded_cookie = boltsort.sort(var.decoded_cookie);
  if (var.decoded_cookie ~ "^\?EventId=([^&]*)&Expires=([^&]*)&Hash=([^&]*)&IsCookieExtendable=([^&]*)&QueueId=([^&]*)$") {
      /* extract data from cookie to check validity */
    set var.cookie_eventId = re.group.1;
    set var.expires = re.group.2;
    set var.hash = re.group.3;
    set var.extendable = re.group.4;
    set var.queueid = re.group.5;
    /* validate event id in cookie */
    if (var.cookie_eventId != req.http.Queue-IT-EventId) {
      /* Cookie not for current active event Id, so return and redirect to queue */
      return;
    }
    /* include eventId to hash calc */
    set var.computed_hash = digest.hmac_sha256(table.lookup(queueit_config, "Secret_key"),
                                               var.queueid + var.extendable + var.expires);
    set var.computed_hash = regsub(var.computed_hash, "^0x", "");
    if (var.computed_hash != var.hash) {
      return;
    }
    set var.exptime = std.time(var.expires, 0s);
    if (var.exptime < now) {
      return;
    }
    set req.http.Queue-IT-Cookie-Valid = "true";
    if (var.extendable == "true") {
      set var.exptime = time.add(now, 20m);
      set var.expires = strftime({"%s"}, var.exptime);
      set var.computed_hash = digest.hmac_sha256(table.lookup(queueit_config, "Secret_key"),
                                                 var.queueid + var.extendable + var.expires);
      set var.computed_hash = regsub(var.computed_hash, "^0x", "");
      # add EventId to cookie value
      set var.decoded_cookie = "EventId=" + var.cookie_eventId + "&QueueId=" + var.queueid + "&IsCookieExtendable=true&Expires="
                               + var.expires + "&Hash=" + var.computed_hash;
      set var.cookie_exp = now + 24h;
      set req.http.Queue-IT-Set-Cookie = table.lookup(queueit_config, "Session_cookie_name") +"="+ urlencode(var.decoded_cookie)
                                         + "; expires=" + var.cookie_exp
      #   "CookieDomain" : ""
                                         + "; path=/; HttpOnly";
    }
  }
}

sub validate_queueit_token {
  declare local var.token STRING;
  declare local var.token_wo_hash STRING;
  declare local var.hash STRING;
  declare local var.queueid STRING;
  declare local var.eventid STRING;
  declare local var.extendable STRING;
  declare local var.expires STRING;
  declare local var.computed_hash STRING;
  declare local var.exptime TIME;
  declare local var.decoded_cookie STRING;
  declare local var.cookie_exp STRING;
  declare local var.cookie_eventId STRING;
  declare local var.rt STRING;
  declare local var.cookie_validitytime STRING;
  declare local var.url STRING;
  if (req.url ~ ".[?&]queueittoken=((e_([^~]*)~q_([^~]*)~ts_([^~]*)~ce_([^~]*)~cv_([^~]*)~rt_([^~]*))~h_([^&]*))(&|$)") {
    set var.token = re.group.1;
    set var.token_wo_hash = re.group.2;
    set var.eventid = re.group.3;
    set var.queueid = re.group.4;
    set var.expires = re.group.5;
    set var.extendable = re.group.6;
    set var.rt = re.group.8;
    set var.hash = re.group.9;
  }
  else if (req.url ~ ".[?&]queueittoken=((e_([^~]*)~q_([^~]*)~ts_([^~]*)~ce_([^~]*)~rt_([^~]*))~h_([^&]*))(&|$)") {
    set var.token = re.group.1;
    set var.token_wo_hash = re.group.2;
    set var.eventid = re.group.3;
    set var.queueid = re.group.4;
    set var.expires = re.group.5;
    set var.extendable = re.group.6;
    set var.rt = re.group.7;
    set var.hash = re.group.8;
  }
  else {
    return;
  }
  set var.computed_hash = digest.hmac_sha256(table.lookup(queueit_config, "Secret_key"), var.token_wo_hash);
  set var.computed_hash = regsub(var.computed_hash, "^0x", "");
  # check the hash matches
  if (var.hash != var.computed_hash) {
    set req.http.Queue-IT-Error = "hash";
    set req.http.Queue-IT-Token = var.token;
    call queueit_err_redir;
  }
  # check the event Id matches
  if (std.tolower(var.eventid) != std.tolower(req.http.Queue-IT-EventId)) { 
    set req.http.Queue-IT-Error = "eventid";
    set req.http.Queue-IT-Token = var.token;
    call queueit_err_redir;
  }
  set var.cookie_validitytime = table.lookup(queueit_config, "Session_validity_time");
  # In Idle phase cookie validity time is fixed at 3 minutes
  if (std.tolower(var.rt) == "idle"){
    set var.cookie_validitytime = "3m";
  }
  set var.exptime = std.time(var.expires, 0s);
  # check the expiry
  if (var.exptime < now) {
    set req.http.Queue-IT-Error = "timestamp";
    set req.http.Queue-IT-Token = var.token;
    call queueit_err_redir;
  }
  /* Succesful token parse, set cookie and allow through */
  set var.exptime = now;
  set var.exptime += std.time(var.cookie_validitytime, 20m);
  set var.expires = strftime({"%s"}, var.exptime);
  set var.computed_hash = digest.hmac_sha256(table.lookup(queueit_config, "Secret_key"),
                                              var.queueid + var.extendable + var.expires);
  set var.computed_hash = regsub(var.computed_hash, "^0x", "");
  set var.decoded_cookie = "EventId=" + var.eventid
                            + "&QueueId=" + var.queueid
                            + "&IsCookieExtendable=" + std.tolower(var.extendable)
                            + "&Expires=" + var.expires + "&Hash=" + var.computed_hash;
  set var.cookie_exp = now + 24h;
  set req.http.Queue-IT-Set-Cookie = table.lookup(queueit_config, "Session_cookie_name") +"="+ urlencode(var.decoded_cookie)
                                      + "; expires=" + var.cookie_exp
  #   "CookieDomain" : ""
                                      + "; path=/; HttpOnly";
  set req.http.Queue-IT-Token-Valid = "true";
}

sub queueit_err_redir {
  declare local var.location STRING;
  set var.location = table.lookup(queueit_config, "Queue_Baseurl") + "error/" + req.http.Queue-IT-Error
                + "?c=" + table.lookup(queueit_config, "CustomerId")
                + "&e=" + table.lookup(queueit_config, "EventId") 
                + "&ver=" + req.http.Queue-IT-Script-Version
                + "&queueittoken=" req.http.Queue-IT-Token
                + "&ts=" + strftime({"%s"}, now);
  # URL comprises of the base error URL, queueit variables, the page URL and formated date and time
  error 602 var.location;
}

sub queueit_error {
  if (obj.status == 602) {
    set obj.status = 302;
    set obj.http.Location = obj.response;
    set obj.response = "Moved Temporarily";
    set obj.http.Expires = "Fri, 01 Jan 1990 00:00:00 GMT";
    set obj.http.Cache-Control = "no-store, no-cache, must-revalidate, max-age=0";
    set obj.http.Pragma = "no-cache";
    return(deliver);
  }
}
