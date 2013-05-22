var passport = require("passport"),
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
SAML2Strategy.prototype = Object.create(passport.Strategy.prototype);

SAML2Strategy.prototype.authenticate = function(req, options) {
  if (req.body && req.body.SAMLResponse) {
    var xml;
    try {
      xml = (new xmldom.DOMParser()).parseFromString(Buffer(req.body.SAMLResponse, "base64").toString("utf8"));
    } catch (e) {
      return this.error(e);
    }

    if (!xml) {
      return this.error(Error("couldn't parse XML"));
    }

    var valid;
    try {
      valid = this.idp.verify(xml);
    } catch (e) {
      return this.error(e);
    }

    if (!valid) {
      return this.error(Error("signature for IDP response was invalid"));
    }

    var element;
    try {
      element = saml2.Protocol.fromXML(xml.documentElement);
    } catch (e) {
      return this.error(e);
    }

    if (!element) {
      return this.error(Error("couldn't construct element from tag: " + xml.documentElement.localName));
    }

    if (!element.Status || !element.Status.StatusCode || element.Status.StatusCode.Value !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
      return this.fail();
    }

    var conditions = element.Assertion.Conditions ? Array.isArray(element.Assertion.Conditions) ? element.Assertion.Conditions : [element.Assertion.Conditions] : [];

    var notBefore, notOnOrAfter;

    for (var i in conditions) {
      if (conditions[i].NotBefore && (notBefore = new Date(conditions[i].NotBefore)) && !Number.isNaN(notBefore.valueOf()) && notBefore.valueOf() > Date.now()) {
        return this.fail();
      }

      if (conditions[i].NotOnOrAfter && (notOnOrAfter = new Date(conditions[i].NotOnOrAfter)) && !Number.isNaN(notOnOrAfter.valueOf()) && notOnOrAfter.valueOf() < Date.now()) {
        return this.fail();
      }
    }

    var user = {
      id: element.Assertion.Subject.NameID._content,
    };

    return this.success(user);
  }

  var authnRequest = this.sp.createAuthnRequest();
  zlib.deflateRaw(authnRequest.toString(), function(err, deflated) {
    if (err) {
      return this.error(err);
    }

    var uri = url.parse(this.idp.singleSignOnService, true);
    uri.query.SAMLRequest = deflated.toString("base64");

    return this.redirect(url.format(uri));
  }.bind(this));
};
