DEPRECATION WARNING
===================

It's been a long time since this module has seen updates, and it will probably
not see any more. My [connect-saml2](https://github.com/deoxxa/connect-saml2)
module is far more robust, and escapes all of the hacky things that had to be
done to get passport to play nicely with SAML. If you absolutely must use
passport and SAML, it might be a good idea to look for a different module.

passport-saml2
==============

SAML 2.0 authentication strategy for Passport.

Overview
--------

This module provides a SAML 2.0 authentication strategy for Passport.JS using
the [node-saml2](http://github.com/siphon-io/node-saml2) library.

Installation
------------

> $ npm install passport-saml2

OR

> $ npm install git://github.com/siphon-io/passport-saml2.git

Usage
-----

Pretty standard fare for a Passport strategy.

```javascript
var express = require("express"),
    passport = require("passport"),
    passport_saml2 = require("passport-saml2");

passport.use("saml2", new passport_saml2({
  idp: {
    singleSignOnService: "https://openidp.feide.no/simplesaml/saml2/idp/SSOService.php",
    certificate: "-----BEGIN X509 CERTIFICATE-----\nMIICizCCAfQCCQCY8tKaMc0BMjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMC\nTk8xEjAQBgNVBAgTCVRyb25kaGVpbTEQMA4GA1UEChMHVU5JTkVUVDEOMAwGA1UE\nCxMFRmVpZGUxGTAXBgNVBAMTEG9wZW5pZHAuZmVpZGUubm8xKTAnBgkqhkiG9w0B\nCQEWGmFuZHJlYXMuc29sYmVyZ0B1bmluZXR0Lm5vMB4XDTA4MDUwODA5MjI0OFoX\nDTM1MDkyMzA5MjI0OFowgYkxCzAJBgNVBAYTAk5PMRIwEAYDVQQIEwlUcm9uZGhl\naW0xEDAOBgNVBAoTB1VOSU5FVFQxDjAMBgNVBAsTBUZlaWRlMRkwFwYDVQQDExBv\ncGVuaWRwLmZlaWRlLm5vMSkwJwYJKoZIhvcNAQkBFhphbmRyZWFzLnNvbGJlcmdA\ndW5pbmV0dC5ubzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAt8jLoqI1VTlx\nAZ2axiDIThWcAOXdu8KkVUWaN/SooO9O0QQ7KRUjSGKN9JK65AFRDXQkWPAu4Hln\nO4noYlFSLnYyDxI66LCr71x4lgFJjqLeAvB/GqBqFfIZ3YK/NrhnUqFwZu63nLrZ\njcUZxNaPjOOSRSDaXpv1kb5k3jOiSGECAwEAATANBgkqhkiG9w0BAQUFAAOBgQBQ\nYj4cAafWaYfjBU2zi1ElwStIaJ5nyp/s/8B8SAPK2T79McMyccP3wSW13LHkmM1j\nwKe3ACFXBvqGQN0IbcH49hu0FKhYFM/GPDJcIHFBsiyMBXChpye9vBaTNEBCtU3K\njjyG0hRT2mAQ9h+bkPmOvlEo/aH0xR68Z9hw4PF13w==\n-----END X509 CERTIFICATE-----\n",
  },
  sp: {
    entityId: "fknsrsbiz-testing",
  },
}));

// ... express app setup ...

// note that this will probably need to match some configuration on the IDP side
app.get("/login", passport.authenticate("saml2", {
  successRedirect: "/",
  failureRedirect: "/login",
}));
```

License
-------

3-clause BSD. A copy is included with the source.

Contact
-------

* GitHub ([siphon-io](http://github.com/siphon-io))
* Email ([opensource@siphon.io](mailto:opensource@siphon.io))
