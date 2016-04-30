var authHelper = require('../src');
var expect = require('chai').expect;
var should = require('chai').should();

describe('Encode Token', function () {
  describe('all', function () {
    it('Should encode a string and return a string', function () {
      var result = authHelper.encodeToken('payload', 'SECRET', 10);
      expect(result).to.be.a('string');
    });

    it('Should encode an object and return a string', function () {
      var result = authHelper.encodeToken(
        { user: 'user', roles: ['admin', 'staff'] },
        'SECRET', 10);
      expect(result).to.be.a('string');
    });

    it('Should return an encoded string containig three parts separated by [.] ', function () {
      var result = authHelper.encodeToken(
        { user: 'user', roles: ['admin', 'staff'] },
        'SECRET', 10);
      expect(result).to.be.a('string');
      expect(result.split('.')).to.have.length.of(3);
    });

    it('Should return valid token even if expiry days are not passed  ', function () {
      var result = authHelper.encodeToken(
        { user: 'user', roles: ['admin', 'staff'] },
        'SECRET');
      expect(result).to.be.a('string');
      expect(result.split('.')).to.have.length.of(3);
    });

    it('Should throw an error if secret is not provided ', function () {
      var fn = function () {
        var result = authHelper.encodeToken(
          { user: 'user', roles: ['admin', 'staff'] });
      };

      expect(fn).to.throw(Error);
    });
  });
});

describe('Decode Token', function () {
  var validToken = authHelper.encodeToken({ user: 'user', roles: ['admin', 'staff'] }, 'SECRET');
  var invalidToken = invalidAuthHeader = '';
  var validAuthHeader = 'Bearer ' + validToken;

  describe('all', function () {
    it('Should decode a valid auth header', function () {
      var result = authHelper.decodeAuthHeader(validAuthHeader);
      expect(result).to.be.a('object');
    });

    it('Should return an error object for an undefined auth header', function () {
      var result = authHelper.decodeAuthHeader();
      expect(result).to.be.a('object');
      expect(result.error).to.be.a('object');
      expect(result.error.code).to.equal('INVALID_TOKEN');
      should.equal(result.payload, undefined);
    });

    it('Should return an error object for an invalid auth header', function () {
      var result = authHelper.decodeAuthHeader(invalidAuthHeader);
      expect(result).to.be.a('object');
      expect(result.error).to.be.a('object');
      expect(result.error.code).to.equal('DECODE_ERROR');
      should.equal(result.payload, undefined);
    });
  });

});

describe('Authenticate Token', function () {
  var SECRET = 'SECRET';
  var validToken = authHelper.encodeToken({ user: 'user', roles: ['admin', 'staff'] }, SECRET);

  var expiredToken = authHelper.encodeToken(
    { user: 'user', roles: ['admin', 'staff'] }, SECRET, -14
  );
  var invalidToken = invalidAuthHeader = '';
  var validAuthHeader = 'Bearer ' + validToken;
  var expiredAuthHeader = 'Bearer ' + expiredToken;

  describe('all', function () {
    it('Should successfully authenticate a valid auth header', function () {
      var result = authHelper.isAuthenticated(validAuthHeader, SECRET);
      expect(result).to.be.a('object');
      expect(result.isSuccess).to.equal(true);
    });

    it('Should return an  error if secret is not passed in', function () {
      var result = authHelper.isAuthenticated(validAuthHeader);
      expect(result).to.be.a('object');
      expect(result.isSuccess).to.equal(false);
    });

    it('Should return an  error if token has expired', function () {
      var result = authHelper.isAuthenticated(expiredAuthHeader, SECRET);
      expect(result).to.be.a('object');
      expect(result.isSuccess).to.equal(false);
      expect(result.error.code).to.equal('DECODE_ERROR');
    });

    it('Should return an error object for an undefined auth header', function () {
      var result = authHelper.isAuthenticated();
      expect(result).to.be.a('object');
      expect(result.error).to.be.a('object');
      expect(result.error.code).to.equal('INVALID_TOKEN');
      expect(result.isSuccess).to.equal(false);
    });

    it('Should return an error object for an invalid auth header', function () {
      var result = authHelper.isAuthenticated(invalidAuthHeader);
      expect(result).to.be.a('object');
      expect(result.error).to.be.a('object');
      expect(result.error.code).to.equal('DECODE_ERROR');
      expect(result.isSuccess).to.equal(false);
    });
  });
});
