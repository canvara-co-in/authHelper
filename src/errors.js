'use strict';

module.exports = {
  DECODE_ERROR: {
      code: 'DECODE_ERROR',
      message: 'Error while decoding JWT token or the token could have expired',
    },
  INVALID_TOKEN: {
    code:'INVALID_TOKEN',
    message:'Authorization header is not valid!',
  },
};
