var assert = require('assert'),
    should = require('should'),
    _ = require('underscore');

describe('attach pod (boilerplate)', function() {
  var
    dao = {
      registerModel : function() {

      }
    },
    cdn = {},
    logger = function(channel, msg, errorLevel) {
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
    pod;

  beforeEach(function() {
    pod = require('../' + podName + '/index.js');
    pod.init(podName, dao, cdn, logger, options);
  });

  it('can describe pod', function() {
    pod.getName().should.equal(podName);
  });

  it('can provide a (pre-disposed) description', function() {
    var descriptions = pod.dispositionDescribe('simple'),
      expectedDisposition = [
        "value",
        "str_in",
        "opt_str_in",
        "in_obj",
        "in_arr",
        "in_mixed",
        "in_bool",
        "config_option"
      ];

    for (var i = 0; i < expectedDisposition.length; i++) {
      descriptions[i].name.should.equal(expectedDisposition[i]);
    }
  });
/*
  it('can derive config and imports from a (pre-disposed) payload', function() {
    var payload = {
        'imports.value' :'pl_value',
        'imports.str_in' : 'pl_str_in',
        'imports.opt_str_in' : 'pl_opt_str_in',
        'imports.in_obj' : 'pl_in_obj',
        'imports.in_arr' : 'pl_in_arr',
        'imports.in_mixed' : 'pl_in_mixed',
        'config.config_option' : false
      },
      unpacked = pod.dispositionUnpack('simple', _.uniq(_.values(payload), true));

    // test all set
    unpacked.imports.should.be.an.Object;
    unpacked.imports.should.have.ownProperty('value');
    unpacked.imports.should.have.ownProperty('str_in');
    unpacked.imports.should.have.ownProperty('opt_str_in');
    unpacked.imports.should.have.ownProperty('in_obj');
    unpacked.imports.should.have.ownProperty('in_arr');
    unpacked.imports.should.have.ownProperty('in_mixed');
    unpacked.imports.should.have.ownProperty('config_option');

    _.each(unpacked, function(values, key) {
      _.each(values, function(pVal, pKey) {
        payload[key + '.' + pKey].should.equal(pVal)
      })
    });
  });
*/
  it('honors action required fields', function(done) {
    var channel = {
        config : {

        }
      },
      imports = {
      },
      sysImports = {},
      contentParts = {};

    pod.invoke('simple', channel, imports, sysImports, contentParts, function(err, exports) {
      err.should.equal('Missing Required Field(s):value,str_in');
      done();
    });
  });

  it('can invoke action', function(done) {
    var channel = {
        config : {

        }
      },
      imports = {
        str_in : 'echo',
        value : '123'
      },
      sysImports = {},
      contentParts = {};

    pod.invoke('simple', channel, imports, sysImports, contentParts, function(err, exports) {
      should(err).not.ok
      exports.str_out.should.equal('echo');
      exports.value_out.should.equal(123);
      done();
    });
  });


  it('can provide a (pre-disposed) description including auth', function() {
    var oldSchema = pod.getSchema(),
      newSchema = JSON.parse(JSON.stringify(oldSchema));

    newSchema.auth.properties = {
      "access_token" : {
        "type" : "string"
      },
      "secret" : {
        "type" : "string"
      }
    };

    newSchema.auth.disposition = [ "access_token", "secret" ];

    pod.setSchema(newSchema);

    var descriptions = pod.dispositionDescribe('simple'),
      expectedDisposition = [
        "access_token",
        "secret",
        "str_in",
        "value",
        "opt_str_in",
        "in_obj",
        "in_arr",
        "in_mixed",
        "in_bool",
        "config_option"
      ];

    for (var i = 0; i < expectedDisposition.length; i++) {
      descriptions[i].name.should.equal(expectedDisposition[i]);
    }
  });
/*
  it('can derive config and imports from a (pre-disposed) payload', function() {
    var oldSchema = pod.getSchema(),
      newSchema = JSON.parse(JSON.stringify(oldSchema));

    newSchema.auth.properties = {
      "access_token" : {
        "type" : "string"
      },
      "secret" : {
        "type" : "string"
      }
    };

    newSchema.auth.disposition = [ "access_token", "secret" ];

    pod.setSchema(newSchema);

    var payload = {
        'auth.access_token' :'ACCESS_TOKEN',
        'auth.secret' :'SECRET',
        'imports.str_in' : 'pl_str_in',
        'imports.value' :'pl_value',
        'imports.opt_str_in' : 'pl_opt_str_in',
        'imports.in_obj' : 'pl_in_obj',
        'imports.in_arr' : 'pl_in_arr',
        'imports.in_mixed' : 'pl_in_mixed',
        'config.config_option' : false
      },
      unpacked = pod.dispositionUnpack('simple', _.uniq(_.values(payload), true));

    // test all set
    unpacked.imports.should.be.an.Object;
    unpacked.imports.should.have.ownProperty('value');
    unpacked.imports.should.have.ownProperty('str_in');
    unpacked.imports.should.have.ownProperty('opt_str_in');
    unpacked.imports.should.have.ownProperty('config_option');

    unpacked.auth.should.be.an.Object;
    unpacked.auth.should.have.ownProperty('access_token');
    unpacked.auth.should.have.ownProperty('secret');

    _.each(unpacked, function(values, key) {
      _.each(values, function(pVal, pKey) {
        payload[key + '.' + pKey].should.equal(pVal)
      })
    });
  });
*/
  it('can appropriately cast (strings)', function(done) {
    var channel = {
        config : {}
      },
      sysImports = {},
      contentParts = {},
    // string types
      payload = {
        str_in : 123,
        value : "123",
        in_obj : "{\"key\":\"value\"}",
        in_arr : "[\"key1\", \"key2\"]",
        in_mixed : "{\"key\":\"value\"}",
        in_bool : "1"
      };

    pod.invoke('simple', channel, payload, sysImports, contentParts, function(err, exports) {
      should(err).not.ok;
      exports.str_out.should.equal(123);
      exports.value_out.should.equal(123);

      exports.in_obj_out.should.be.an.Object;
      exports.in_obj_out.should.have.ownProperty('key');
      exports.in_obj_out.key.should.equal('value');

      exports.in_arr_out.should.be.an.Array;
      exports.in_arr_out.should.have.lengthOf(2);

      exports.in_mixed_out.should.be.an.Object;
      exports.in_mixed_out.should.have.ownProperty('key');
      exports.in_mixed_out.key.should.equal('value');

      exports.in_bool_out.should.equal(true);

      done();
    });
  });

it('can appropriately cast (explicit types)', function(done) {
    var channel = {
        config : {}
      },
      sysImports = {},
      contentParts = {},
      payload = {
        str_in : "123",
        value : 123,
        in_obj : {"key":"value"},
        in_arr : ["key1", "key2"],
        in_mixed : "{\"key\":\"value\"}",
        in_bool : true
      };

    pod.invoke('simple', channel, payload, sysImports, contentParts, function(err, exports) {
      should(err).not.ok;
      exports.str_out.should.equal('123');
      exports.value_out.should.equal(123);

      exports.in_obj_out.should.be.an.Object;
      exports.in_obj_out.should.have.ownProperty('key');
      exports.in_obj_out.key.should.equal('value');

      exports.in_arr_out.should.be.an.Array;
      exports.in_arr_out.should.have.lengthOf(2);

      exports.in_mixed_out.should.be.an.Object;
      exports.in_mixed_out.should.have.ownProperty('key');
      exports.in_mixed_out.key.should.equal('value');

      exports.in_bool_out.should.equal(true);

      done();
    });
  });

  it('can rate limit requests', function(done) {
    var expected = [],
      resolved = [],
      iter = 10,
      rateLimit = 5,
      reqSec = 1000 / rateLimit; // 5/sec

    this.timeout(1000 * ( iter / rateLimit + 1) );

    var then = (new Date()).getTime();

    for (var i = 1; i <= iter; i++) {
      expected.push(i);

      (function(i) {
        pod.limitRate(
          {
            'owner_id' : 'abc'
          },
          (function(resolved) {
            return function() {
              resolved.push(i);
              if (i === iter) {
                now = (new Date()).getTime();

                ((now - then) / 1000).should.be.above(iter / rateLimit);

                 _.difference(expected, resolved).should.be.empty
                resolved.should.not.be.empty;
                done();
              }
            }
          })(resolved),
          rateLimit);
      })(i);
    }
  });

});










































