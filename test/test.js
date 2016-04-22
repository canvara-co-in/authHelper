var authHelper = require('../src');
var expect = require('chai').expect;

describe('Token Creation', function () {
  describe('all', function () {
    it('should encode a string', function () {
      var result = authHelper.encodeToken('payload', 'SECRET', 10);
      expect(result).to.be.a('string');
    });

    it('should encode an object', function () {
      var result = authHelper.encodeToken(
        { user: 'user', roles: ['admin', 'staff'] },
        'SECRET', 10);
      expect(result).to.be.a('string');
    });
  });
});
