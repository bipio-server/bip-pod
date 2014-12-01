var assert = require('assert'),
    should = require('should');

describe('attach custom pod', function() {
  var
    dao = {
      registerModel : function() {

      }
    },
    cdn = {},
    logger = function(msg, errorLevel) {
      console[errorLevel || 'log'](msg);
    },
    options = {
      config : {},
      blacklist : [],
      baseUrl : '/',
      cdnPublicBaseUrl : '/',
      emitterBaseUrl : '/',
      timezone : 'UTC',
      reqLiteral : true
    },
    podName = 'boilerplate',
    simplePod = require('../' + podName + '/index.js');

  simplePod.init(podName, dao, cdn, logger, options);

  it('can describe pod', function(done) {
    simplePod.getName().should.equal(podName);
    done();
  });


});