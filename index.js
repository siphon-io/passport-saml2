var dsig = require("xml-dsig"),
    passport = require("passport"),
    querystring = require("querystring"),
    url = require("url"),
    saml2 = require("saml2"),
    xmldom = require("xmldom"),
    zlib = require("zlib");

var SAML2Strategy = module.exports = function SAML2Strategy(options, verify) {
  options = options || {};

  passport.Strategy.call(this, options, verify);

  if (!options.idp || !options.sp) {
    throw new Error("`idp' and `sp' parameters are both required");
  }

  this.idp = new saml2.IdentityProvider(options.idp);
  this.sp = new saml2.ServiceProvider(options.sp);
};
SAML2Strategy.prototype = Object.create(passport.Strategy.prototype, {constructor: {value: SAML2Strategy}});

SAML2Strategy.prototype.initiateRedirect = function initiateRedirect(type, target, message, res, cb) {
  zlib.deflateRaw(message.toString(), function(err, deflated) {
    if (err) {
      return next(err);
    }

    var uri = url.parse(target, true);
    uri.query[type] = deflated.toString("base64");
    uri.query.RelayState = Date.now() + "-" + Math.round(Math.random() * 1000000);

    if (this.sp.privateKey) {
      uri.query.SigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

      var toSign = {};
      toSign[type]      = uri.query[type];
      toSign.RelayState = uri.query.RelayState;
      toSign.SigAlg     = uri.query.SigAlg;
      toSign = querystring.stringify(toSign);

      uri.query.Signature = dsig.signatures[uri.query.SigAlg].sign({privateKey: this.sp.privateKey}, toSign);
    }

    uri.search = null;
    return res.redirect(url.format(uri));
  }.bind(this));
};

SAML2Strategy.prototype.ssoInitiator = function ssoInitiator(req, res, next) {
  this.initiateRedirect("SAMLRequest", this.idp.singleSignOnService, this.sp.createAuthnRequest(), res, next);
};

SAML2Strategy.prototype.sloInitiator = function sloInitiator(req, res, next) {
  this.initiateRedirect("SAMLRequest", this.idp.singleLogOutService, this.sp.createLogoutRequest(), res, next);
};

SAML2Strategy.prototype.sloHandler = function sloHandler(req, res, next) {
  res.type("xml");
  res.send(req.samlMessage.toString());
};

SAML2Strategy.prototype.ssoHandler = function ssoHandler(req, res, next) {
  res.type("xml");
  res.send(req.samlMessage.toString());
};

SAML2Strategy.prototype.handlePost = function handlePost(req, res, next) {
  if (!req.body || (!req.body.SAMLRequest && !req.body.SAMLResponse)) {
    return next(Error("no SAML fields found in body"));
  }

  if (req.body.SAMLRequest && req.body.SAMLResponse) {
    return next(Error("too many SAML fields found in body"));
  }

  var key = req.body.SAMLRequest ? "SAMLRequest" : "SAMLResponse";

  var xml;
  try {
    xml = (new xmldom.DOMParser()).parseFromString(Buffer(req.body[key], "base64").toString("utf8"));
  } catch (e) {
    return next(e);
  }

  if (!xml) {
    return next(Error("couldn't parse XML"));
  }

  if (this.idp.certificate) {
    var valid;
    try {
      valid = this.idp.verify(xml);
    } catch (e) {
      return next(e);
    }

    if (!valid) {
      return next(Error("signature for IDP response was invalid"));
    }
  }

  var message;
  try {
    message = saml2.Protocol.fromXML(xml.documentElement);
  } catch (e) {
    return next(e);
  }

  if (!message) {
    return next(Error("couldn't construct message from tag: " + xml.documentElement.localName));
  }

  req.samlMessage = message;

  return next();
};

SAML2Strategy.prototype.handleRedirect = function handleRedirect(req, res, next) {
  if (!req.query || (!req.query.SAMLRequest && !req.query.SAMLResponse)) {
    return next(Error("no SAML fields found in query"));
  }

  if (req.query.SAMLRequest && req.query.SAMLResponse) {
    return next(Error("too many SAML fields found in query"));
  }

  var key = req.query.SAMLRequest ? "SAMLRequest" : "SAMLResponse";

  var data;
  try {
    data = Buffer(req.query[key], "base64");
  } catch (e) {
    return next(e);
  }

  zlib.inflateRaw(data, function(err, inflated) {
    if (err) {
      return next(err);
    }

    var xml;
    try {
      xml = (new xmldom.DOMParser()).parseFromString(inflated.toString("utf8"));
    } catch (e) {
      return next(e);
    }

    if (!xml) {
      return next(Error("couldn't parse XML"));
    }

    if (this.idp.certificate) {
      var valid;
      try {
        valid = this.idp.verify(xml);
      } catch (e) {
        return next(e);
      }

      if (!valid) {
        return next(Error("signature for IDP response was invalid"));
      }
    }

    var message;
    try {
      message = saml2.Protocol.fromXML(xml.documentElement);
    } catch (e) {
      return next(e);
    }

    if (!message) {
      return next(Error("couldn't construct message from tag: " + xml.documentElement.localName));
    }

    req.samlMessage = message;

    return next();
  });
};

SAML2Strategy.prototype.handleMessage = function handleMessage(req, res, next) {
  var fn;

  if (req.method === "GET" && (req.query.SAMLRequest || req.query.SAMLResponse)) {
    fn = this.handleRedirect;
  }

  if (req.method === "POST" && (req.body.SAMLRequest || req.body.SAMLResponse)) {
    fn = this.handlePost;
  }

  if (!fn) {
    return next(Error("couldn't figure out how to handle this request"));
  }

  fn.call(this, req, function(err, element) {
    if (err) {
      return next(err);
    }

    req.samlMessage = element;

    return next();
  });
};

SAML2Strategy.prototype.authenticate = function(req, options) {
  if (!req.samlMessage) {
    return this.fail();
  }

  if (!req.samlMessage.Status || !req.samlMessage.Status.StatusCode || req.samlMessage.Status.StatusCode.Value !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
    return this.fail();
  }

  var conditions = req.samlMessage.Assertion.Conditions ? Array.isArray(req.samlMessage.Assertion.Conditions) ? req.samlMessage.Assertion.Conditions : [req.samlMessage.Assertion.Conditions] : [];

  var notBefore, notOnOrAfter;

  for (var i in conditions) {
    if (conditions[i].NotBefore && (notBefore = new Date(conditions[i].NotBefore)) && !Number.isNaN(notBefore.valueOf()) && notBefore.valueOf() > Date.now()) {
      return this.fail();
    }

    if (conditions[i].NotOnOrAfter && (notOnOrAfter = new Date(conditions[i].NotOnOrAfter)) && !Number.isNaN(notOnOrAfter.valueOf()) && notOnOrAfter.valueOf() < Date.now()) {
      return this.fail();
    }
  }

  var nameId;
  if (req.samlMessage.Assertion && req.samlMessage.Assertion.Subject && req.samlMessage.Assertion.Subject.NameID) {
    nameId = req.samlMessage.Assertion.Subject.NameID._content;
  }

  if (!nameId) {
    return this.fail();
  }

  var attributes;
  if (req.samlMessage.Assertion && req.samlMessage.Assertion.AttributeStatement && req.samlMessage.Assertion.AttributeStatement.Attribute) {
    attributes = req.samlMessage.Assertion.AttributeStatement.Attribute;

    if (!Array.isArray(attributes)) {
      attributes = [attributes];
    }

    attributes = attributes.map(function(e) {
      return {
        name: e.Name,
        friendlyName: e.FriendlyName,
        values: (Array.isArray(e.AttributeValue) ? e.AttributeValue : [e.AttributeValue]).map(function(e) {
          return e._content;
        }),
      };
    }).reduce(function(i, v) {
      i[v.name] = v.values[0];

      return i;
    }, {});
  }

  var user = {
    id: nameId,
    attributes: attributes,
  };

  return this.success(user);
};
