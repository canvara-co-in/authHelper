'use strict';

var jwt = require('jwt-simple');
var moment = require('moment');
var _ = require('lodash');

var encodeToken = function (sub, secret, expiry) {
  expiry = (_.isInteger(expiry) && expiry > 0) ? expiry : 14;
  var payload =  {
    exp: moment().add(expiry, 'days').unix(),
    iat: moment().unix(),
    sub: sub,
  };
  return jwt.encode(payload, secret);
};

var decodeToken = function (token, secret) {
  try {
    return { payload: jwt.decode(token, secret) };
  } catch (e) {
    return { error: { code: 'DECODE_ERROR', message: 'Error while decoding JWT token' } };
  }
};

var decodeAuthHeader = function (headers, secret) {
  try {
    var header = headers.authorization.split(' ');
    var token = header[1];
    return { payload: decodeToken(token, secret) };
  } catch (e) {
    return { error: { code:'INVALID_TOKEN', message:'Authorization header is not valid!' } };
  }
};

modules.export  = {
  encodeToken: encodeToken,
  decodeToken: decodeToken,
  decodeAuthHeader: decodeAuthHeader,
};
