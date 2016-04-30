# authHelper
JWT Authorization Helper

Provides four helper methods to encode and decode JWT tokens.

  * encodeToken (sub, secret, expiry)
  * decodeToken (payload, secret)
  * decodeHeader (authHeader, secret)  
  * isAuthenticated (authHeader, secret)
