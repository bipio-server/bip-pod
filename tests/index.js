var assert = require('assert'),
    should = require('should');

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
        "config_option"
      ];

    for (var i = 0; i < expectedDisposition.length; i++) {
      descriptions[i].name.should.equal(expectedDisposition[i]);
    }
  });

  it('can derive config and imports from a (pre-disposed) payload', function() {
    var payload = {
        'imports.value' :'pl_value',
        'config.str_in' : 'pl_str_in',
        'imports.str_in' : 'pl_str_in',
        'imports.opt_str_in' : 'pl_opt_str_in',
        'config.opt_str_in' : 'pl_opt_str_in',
        'config.config_option' : false
      },
      unpacked = pod.dispositionUnpack('simple', _.uniq(_.values(payload), true));

    // test all set
    unpacked.imports.should.be.an.Object;
    unpacked.imports.should.have.ownProperty('value');
    unpacked.imports.should.have.ownProperty('str_in');
    unpacked.imports.should.have.ownProperty('opt_str_in');
    unpacked.imports.should.not.have.ownProperty('config_option');

    unpacked.config.should.be.an.Object;
    unpacked.config.should.have.ownProperty('str_in');
    unpacked.config.should.have.ownProperty('opt_str_in');
    unpacked.config.should.have.ownProperty('config_option');
    unpacked.config.should.not.have.ownProperty('value');

    _.each(unpacked, function(values, key) {
      _.each(values, function(pVal, pKey) {
        payload[key + '.' + pKey].should.equal(pVal)
      })
    });
  });

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
        value : '_req_value'
      },
      sysImports = {},
      contentParts = {};

    pod.invoke('simple', channel, imports, sysImports, contentParts, function(err, exports) {
      should(err).not.ok
      exports.str_out.should.equal('echo_req_value');
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
        "value",
        "str_in",
        "opt_str_in",
        "config_option"
      ];

    for (var i = 0; i < expectedDisposition.length; i++) {
      descriptions[i].name.should.equal(expectedDisposition[i]);
    }
  });

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
        'imports.value' :'pl_value',
        'config.str_in' : 'pl_str_in',
        'imports.str_in' : 'pl_str_in',
        'imports.opt_str_in' : 'pl_opt_str_in',
        'config.opt_str_in' : 'pl_opt_str_in',
        'config.config_option' : false
      },
      unpacked = pod.dispositionUnpack('simple', _.uniq(_.values(payload), true));

    // test all set
    unpacked.imports.should.be.an.Object;
    unpacked.imports.should.have.ownProperty('value');
    unpacked.imports.should.have.ownProperty('str_in');
    unpacked.imports.should.have.ownProperty('opt_str_in');
    unpacked.imports.should.not.have.ownProperty('config_option');

    unpacked.config.should.be.an.Object;
    unpacked.config.should.have.ownProperty('str_in');
    unpacked.config.should.have.ownProperty('opt_str_in');
    unpacked.config.should.have.ownProperty('config_option');
    unpacked.config.should.not.have.ownProperty('value');

    unpacked.auth.should.be.an.Object;
    unpacked.auth.should.have.ownProperty('access_token');
    unpacked.auth.should.have.ownProperty('secret');

    _.each(unpacked, function(values, key) {
      _.each(values, function(pVal, pKey) {
        payload[key + '.' + pKey].should.equal(pVal)
      })
    });
  });

});










































