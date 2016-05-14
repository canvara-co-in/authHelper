'use strict';

var jwt = require('jwt-simple');
var moment = require('moment');
var _ = require('lodash');
var Errors = require('./errors');

/**
* Returns a encoded payload token using the provided sub, secret and expiry.
* @param {*} subject to be encoded
* @param {String} Secret key for encoding
* @param {Number=} An integer to set the expiry days (optional)
* @returns {String} encoded token as a string
*/
var encodeToken = function (sub, secret, expiry) {
  expiry = (_.isInteger(expiry)) ? expiry : 14;
  var payload =  {
    exp: moment().add(expiry, 'days').unix(),
    iat: moment().unix(),
    sub: sub,
  };
  return jwt.encode(payload, secret);
};

/**
* Returns a decoded payload from the token
* @param {String} token to be decoded
* @param {String} Secret key for decoding
* @returns {Object} decoded payload
*/
var decodeToken = function (token, secret) {
  try {
    return { payload: jwt.decode(token, secret) };
  } catch (e) {
    return { error: Errors.DECODE_ERROR,
    };
  }
};

/**
* Returns a decoded payload from the http headers
* @param {String} String containing the authorization heade4r
* @param {String} Secret key for decoding
* @returns {Object} decoded payload
*/
var decodeAuthHeader = function (authHeader, secret) {
  try {
    var header = authHeader.split(' ');
    var token = header[1];
    return decodeToken(token, secret);
  } catch (e) {
    return { error: Errors.INVALID_TOKEN };
  }
};

/**
* Verifies the auth header is valid and has not expired
* @param {String} String containing the authorization heade4r
* @param {String} Secret key for decoding
* @returns {Object} result of the operation with decoded payload as part of the result.
*                   if successful flag isSuccess is set to true in the response
*/
var isAuthenticated = function (authHeader, secret) {

  var result = decodeAuthHeader(authHeader, secret);

  if (result.error) return { isSuccess: false, error: result.error };

  return { isSuccess: true, payload: result.payload };
};

module.exports  = {
  encodeToken: encodeToken,
  decodeToken: decodeToken,
  decodeAuthHeader: decodeAuthHeader,
  isAuthenticated: isAuthenticated,
};
