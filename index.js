/**
 *
 * The Bipio Pod Bridge.  Provides basic system resources, auth helpers,
 * setup, invoke and data sources for actions within the pod.
 *
 * @author Michael Pearson <github@m.bip.io>
 * Copyright (c) 2010-2013 Michael Pearson https://github.com/mjpearson
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * A Bipio Commercial OEM License may be obtained via support@beta.bip.io
 */
var passport = require('passport'),
request = require('request'),
moment = require('moment'),
util = require('util'),
fs = require('fs'),
extend = require('extend');
uuid = require('node-uuid'),
mime = require('mime'),
cron = require('cron');

var requiredMeta = [
  'name',
//  'title',
  'description'
];

// constructor
function Pod(metadata, init) {

  for (var i = 0; i < requiredMeta.length; i++) {
    if (!metadata[requiredMeta[i]]) {
      throw new Error('Pod is missing required "' + requiredMeta[i] + '" metadata');
    }
  }

  this._name = metadata.name;
  this._title = (metadata.title || metadata.description);
  this._description = (metadata.description || metadata.description_long);
  this._authType = metadata.authType || 'none';
  this._authMap = metadata.authMap || null;
  this._config = metadata.config || null;
  this._dataSources = metadata.dataSources || [];
  this._renderers = metadata.renderers || {};
  this._oAuth = null;
  this._podInit = init;

  if (metadata.oAuthRefresh) {
    this._oAuthRefresh = metadata.oAuthRefresh;
  }

  this._oAuthRegistered = false;
  this._passportStrategy = metadata.passportStrategy;
  this._sysImports = null;
  this._schemas = {}; // import configs and schema; keyed to channel action
  this._importContainer = {};

  this._dao = null;
  this._sysConfig = {};
  this._actionProtos = [];

  this.actions = {};
  this.models = {};
  this.$resource = {};
  this.crons = {};
}

Pod.prototype = {
  getDataSourceName : function(dsName) {
    return 'pod_' + this._name + '_' + dsName;
  },

  /**
     * make system resources available to the pod. Invoked by the Pod registrar
     * in the Channels model when bootstrapping.
     *
     * @param dao {Object} DAO.
     * @param config {Object} Pod Config
     * @param sysConfig {Object} System Config
     *
     */
  init : function(dao, config, sysConfig) {
    var dsi = this._dataSources.length,
    self = this, dataSource, model;

    if (!this._dao) {
      this._dao = dao;
    }

    if (this._renderers) {
      for (var k in this._renderers) {
        if (this._renderers.hasOwnProperty(k)) {
          this._renderers[k]._href = this._dao.getBaseUrl() + '/rpc/pod/' + self._name + '/render/' + k;
        }
      }
    }

    // register generic tracker
    var tracker = require('./models/channel_pod_tracking');
    extend(true, tracker, Object.create(dao.getModelPrototype()));
    this._dao.registerModel(tracker);

    // register pod data sources
    for (var i = 0; i < dsi; i++) {
      dataSource = this._dataSources[i];
      // namespace the model
      dataSource.entityName = this.getDataSourceName(dataSource.entityName);

      extend(true, dataSource, Object.create(dao.getModelPrototype()));
      this._dao.registerModel(dataSource);
    }

    if (config) {
      this.setConfig(config);
    }

    this._sysConfig = sysConfig;

    // register the oauth strategy
    if (this._authType === 'oauth') {
      this._oAuthRegisterStrategy(
        this._passportStrategy,
        self._config.oauth
        );
    }

    // create resources for Actions
    this.$resource.dao = dao;
    this.$resource.moment = moment;
    this.$resource.mime = mime;
    this.$resource.uuid = uuid;
    this.$resource.sanitize = app.helper.sanitize;
    this.$resource.htmlNormalize = function() {
      return app.helper.naturalize.apply(app.helper, arguments);
    };
    this.$resource.log = this.log;
    this.$resource.getDataSourceName = function(dsName) {
      return 'pod_' + self._name + '_' + dsName;
    };

    this.$resource.getDataDir = this.getDataDir;
    this.$resource.getCDNDir = this.getCDNDir;
    this.$resource.expireCDNDir = this.expireCDNDir;
    this.$resource._httpGet = this._httpGet;
    this.$resource._httpPost = this._httpPost;
    this.$resource._httpPut = this._httpPut;
    this.$resource._httpStreamToFile = this._httpStreamToFile;
    this.$resource._isVisibleHost = this._isVisibleHost;

    // give the pod a scheduler
    if (app.isMaster) {
      this.$resource.cron = cron;
    }

    // bind actions
    var action;
    for (i = 0; i < this._actionProtos.length; i++) {
      action = new this._actionProtos[i](this._config, this);
      action.$resource = this.$resource;
      action.pod = this;
      this.actions[action.name] = action;
      this._schemas[action.name] = this.buildSchema(action);
    }

    if (this._podInit) {
      this._podInit.apply(this);
    }
  },

  // provide a scheduler service
  registerCron : function(id, period, callback) {
    var self = this;

    if (this.$resource.cron) {
      if (!this.crons[id]) {
        app.logmessage('POD:Registering Cron:' + self._name + ':' + id);
          self.crons[id] = new self.$resource.cron.CronJob(
            period,
            callback,
            null,
            true,
            GLOBAL.CFG.timezone
          );

      }
    }
  },

  // normalizes the schema for an action
  buildSchema : function(action) {
    var actionSchema = action.getSchema(),
      schema = {
        'title' : (action.title || action.description),
        'description' : (action.description || action.description_long),
        'auth_required' : action.auth_required,
        'trigger' : action.trigger,
        'singleton' : action.singleton,
        'auto' : action.auto,
        'config' : actionSchema.config || {
          properties : {},
          definitions : {}
        },
        'renderers' : actionSchema.renderers || {},
        'defaults' : actionSchema.defaults || {},
        'exports' : actionSchema.exports || {
          properties : {}
        },
        'imports' : actionSchema.imports || {
          properties : {}
        }
      };

    schema.config['$schema'] =
    schema.imports['$schema'] =
    schema.exports['$schema'] = "http://json-schema.org/draft-04/schema#";

    return schema;

  },

  /**
     * Sets the configuration for this pod
     *
     * @param config {Object} configuration structure for this Pod
     */
  setConfig: function(config) {
    this._config = config;
  },

  getConfig : function() {
    return this._config;
  },

  /**
     * Logs a message
     */
  log : function(message, channel, level) {
    if (app.helper.isObject(message)) {
      app.logmessage(
        channel.action
        + ':'
        + channel.owner_id,
        level);
      app.logmessage(message, level);
    } else {
      app.logmessage(
        channel.action
        + ':'
        + channel.owner_id
        + ':'
        + message,
        level);
    }
  },


  // ------------------------------ 3RD PARTY AUTHENTICATION HELPERS


  testCredentials : function(struct, next) {
    next(false);
  },

  issuerTokenRPC : function(podName, method, req, res) {
    var ok = false, accountId = req.remoteUser.user.id;
    res.contentType(DEFS.CONTENTTYPE_JSON);

    if (this._authType == 'issuer_token') {
      if (method == 'set') {
        app.logmessage('[' + accountId + '] ISSUER_TOKEN ' + this._name + ' SET' );

        var self = this;

        // upsert oAuth document
        var filter = {
          owner_id : accountId,
          type : this._authType,
          auth_provider : podName
        };

        var struct = {
          owner_id : accountId,
          username : req.query.username,
          key : req.query.key,
          password : req.query.password,
          type : this._authType,
          auth_provider : podName
        };

        self.testCredentials(struct, function(err, status) {
          if (err) {
            res.jsonp(status || 401, { "message" : err.toString() });

          } else {
            var model = self._dao.modelFactory('account_auth', struct);

            // @todo upserts don't work with mongoose middleware
            // create a dao helper for filter -> model upsert.
            self._dao.find('account_auth', filter, function(err, result) {
              if (err) {
                app.logmessage(err, 'error');
                res.send(500);
              } else {
                // update
                if (result) {
                  self._dao.update('account_auth', result.id, struct, function(err, result) {
                    if (err) {
                      app.logmessage(err, 'error');
                      res.jsonp(500, {});
                    } else {
                      res.jsonp(200, {});
                    }
                  }, req.remoteUser);
                } else {
                  // create
                  self._dao.create(model, function(err, result) {
                    if (err) {
                      app.logmessage(err, 'error');
                      res.jsonp(500, {});
                    } else {
                      self.autoInstall(req.remoteUser);
                      res.jsonp(200, {});
                    }
                  }, req.remoteUser);
                }
              }
            });

          }
        });

        ok = true;
      } else if (method == 'deauth') {
        var filter = {
          owner_id : accountId,
          type : 'issuer_token',
          auth_provider : podName
        }

        this._dao.removeFilter('account_auth', filter, function(err) {
          if (!err) {
            res.jsonp(200, {});
          } else {
            app.logmessage(err, 'error');
            res.jsonp(500, {});
          }
        });
        ok = true;
      }
    }
    return ok;
  },

  /**
     * @param string podName pod name == strategy name
     * @param string method auth rpc method name
     * @param object req request
     * @param object res response
     */
  oAuthRPC: function(podName, method, req, res) {
    var ok = false,
    authMethod = (this._oAuthMethod) ? this._oAuthMethod : 'authorize',
    self = this,
    accountInfo = req.remoteUser,
    accountId = accountInfo.getId(),
    emitterHost = CFG.site_emitter || CFG.website_public;

    if (false !== this._oAuthRegistered) {
      // invoke the passport oauth handler
      if (method == 'auth') {
        app.logmessage('[' + accountId + '] OAUTH ' + podName + ' AUTH REQUEST' );
        passport[authMethod](podName, this._oAuthConfig)(req, res);
        ok = true;

      } else if (method == 'cb') {
        app.logmessage('[' + accountId + '] OAUTH ' + podName + ' AUTH CALLBACK ' + authMethod );
        passport[authMethod](podName, function(err, user) {

          // @todo - decouple from site.
          if (err) {
            app.logmessage(err, 'error');
            res.redirect(emitterHost + '/emitter/oauthcb?status=denied&provider=' + podName);

          } else if (!user && req.query.error_reason && req.query.error_reason == 'user_denied') {
            app.logmessage('[' + accountId + '] OAUTH ' + podName + ' CANCELLED' );
            res.redirect(emitterHost + '/emitter/oauthcb?status=denied&provider=' + podName);

          } else if (!user) {
            app.logmessage('[' + accountId + '] OAUTH ' + podName + ' UNKNOWN ERROR' );
            res.redirect(emitterHost + '/emitter/oauthcb?status=denied&provider=' + podName);

          } else {
            app.logmessage('[' + accountId + '] OAUTH ' + podName + ' AUTHORIZED' );
            // install singletons
            self.autoInstall(accountInfo);
            res.redirect(emitterHost + '/emitter/oauthcb?status=accepted&provider=' + podName);
          }
        })(req, res, function(err) {
          res.send(500);
          app.logmessage(err, 'error');
        });
        ok = true;
      } else if (method == 'deauth') {
        this.oAuthUnbind(podName, accountId, function(err) {
          if (!err) {
            res.send(200);
          } else {
            app.logmessage(err, 'error');
            res.send(500);
          }
        });
        ok = true;

      // returns 200 OK or 401 Not Authorized
      } else if (method == 'authstat') {
        ok = true;
      } else if (method == 'denied') {
        res.send(401);
      }
    }

    return ok;
  },

  authStatus : function(owner_id, podName, next) {
    if (this.isOAuth()) {
      this.oAuthStatus(owner_id, podName, next);
    } else {
      this._getPassword(owner_id, podName, next);
    }
  },

  getAuthType : function() {
    return this._authType;
  },

  isOAuth : function() {
    return this._authType == 'oauth';
  },

  _getPassword : function(ownerId, podName, next) {
    var self = this;
    var filter = {
      owner_id : ownerId,
      type : this._authType,
      auth_provider : podName
    };

    this._dao.find('account_auth', filter, function(err, result) {
      if (!result || err) {
        if (err) {
          app.logmessage(err, 'error');
          next(true, podName, self._authType, result );
        } else {
          next(false, podName, self._authType, result );
        }
      } else {
        next(false, podName,  self._authType, self._dao.modelFactory('account_auth', result));
      }
    });

  },

  /**
     * passes oAuth result set if one exists
     */
  oAuthStatus : function(owner_id, podName, next) {
    var self = this,
    filter = {
      owner_id : owner_id,
      type : this._authType,
      oauth_provider : this._name
    };
    this._dao.find('account_auth', filter, function(err, result) {
      next(err, podName, self._authType, result);
    });
  },

  /**
     *
     * Registers an oAuth strategy for this pod
     *
     */
  _oAuthRegisterStrategy : function(strategy, config) {
    var localConfig = {
      callbackURL : CFG.proto_public + CFG.domain_public + '/rpc/oauth/' + this._name + '/cb',
      failureRedirect : CFG.proto_public + CFG.domain_public + '/rpc/oauth/' + this._name + '/denied',
      passReqToCallback: true
    }, self = this;

    for (key in config) {
      localConfig[key] = config[key];
    }

    this._oAuthConfig = {
      scope : config.scopes
    };

    if (config.extras) {
      app.helper.copyProperties(config.extras, this._oAuthConfig);
    }

    this._oAuthRegistered = true;
    passport.use(new strategy(
      localConfig,
      function(req, accessToken, refreshToken, params, profile, done) {
        // maintain scope
        self.oAuthBinder(req, accessToken, refreshToken, params, profile, done);
      }));
  },

  /**
     *
     */
  oAuthUnbind : function(podName, ownerid, next) {
    var filter = {
      owner_id : ownerid,
      type : 'oauth',
      oauth_provider : podName
    }

    this._dao.removeFilter('account_auth', filter, next);
    this._dao.updateColumn(
      'channel',
      {
        owner_id : ownerid,
        action : {
          $regex : podName + '\.*'
        }
      },
      {
        _available : false
      }
    );
  },

  oAuthBinder: function(req, accessToken, refreshToken, params, profile, done) {
    var self = this,
    modelName = 'account_auth',
    accountInfo = req.remoteUser,
    accountId = accountInfo.getId();

    // upsert oAuth document
    var filter = {
      owner_id : accountId,
      type : 'oauth',
      oauth_provider : this._name
    };

    var struct = {
      owner_id : accountId,
      password : accessToken,
      type : 'oauth',
      oauth_provider : this._name,
      oauth_refresh : refreshToken || '',
      oauth_profile : profile._json ? profile._json : profile
    };

    if (params.expires_in) {
      struct.oauth_token_expire = params.expires_in;
    }

    var model = this._dao.modelFactory(modelName, struct);

    // @todo upserts don't work with mongoose middleware
    // create a dao helper for filter -> model upsert.
    this._dao.find(modelName, filter, function(err, result) {
      var next = done;
      if (err) {
        done( err, req.remoteUser );
      } else {
        if (result) {

          self._dao.updateProperties(
            modelName,
            result.id,
            struct,
            function(err) {
              next( err, accountInfo );
            }
          );
        } else {
          self._dao.create(model, function(err, result) {
            next( err, accountInfo );
          });
        }
      }
    });
  },

  /**
     * Given an owner id and provider, retrieves the oauth token
     */
  oAuthGetToken : function(owner_id, provider, next) {
    var self = this;
    this._dao.find(
      'account_auth',
      {
        'owner_id' : owner_id,
        'oauth_provider' : provider
      },
      function(err, result) {
        var authRecord;
        if (!err && result) {
          authRecord = self._dao.modelFactory('account_auth', result);
          next(
            false,
            authRecord.getPassword(),
            authRecord.getOAuthRefresh(),
            authRecord.getOauthProfile()
            );
        } else {
          if (err) {
            app.logmessage(err, 'error');
          }
          next(err, result);
        }
      }
      );
  },

  oAuthRefresh : function(authModel) {
    var refreshToken = authModel.getOAuthRefresh(),
    self = this;

    this._oAuthRefresh(refreshToken, function(err, refreshStruct) {
      if (!err) {
        self._dao.updateProperties(
          'account_auth',
          authModel.id,
          {
            password : refreshStruct.access_token,
            oauth_token_expire : refreshStruct.expires_in
          },
          function(err) {
            if (!err) {
              app.logmessage(self._name + ':OAuthRefresh:' + authModel.owner_id);
            } else {
              app.logmessage(err, 'error');
            }
          }
          );
      }
    });
  },

  authGetIssuerToken : function(owner_id, provider, next) {
    var self = this;

    this._dao.find(
      'account_auth',
      {
        'owner_id' : owner_id,
        'auth_provider' : provider
      },
      function(err, result) {
        var authRecord;
        if (!err && result) {
          authRecord = self._dao.modelFactory('account_auth', result);
          next(false, authRecord.getUsername(), authRecord.getPassword(), authRecord.getKey());
        } else {
          if (err) {
            app.logmessage(err, 'error');
          } else if (!result) {
            app.logmessage('no result for owner_id:' + owner_id + ' provider:' + provider, 'error');
          }
          next(err, result);
        }
      }
      );
  },

  importGetConfig: function(action) {
    return this._schemas[action].config;
  },

  _testConfig : function(channel, attr, testForVal) {
    return (channel.config[attr] && channel.config[attr] == testForVal );
  },

  importGetDefaults : function(action) {
    return this._schemas[action].defaults;
  },

  // @todo
  _getRendererUrl: function(action, accountInfo) {
    var ret;
    if (accountInfo) {
      ret = accountInfo.getDomain(true);
    }

    ret += '/rpc/pod/' + this._name + '/' + action + '/render';
  },

  // invoker for this action can generate its own content (periodically)
  canTrigger: function(action) {
    return this._schemas[action].trigger;
  },

  // action can render its own stored content
  canRender: function(action) {
    return (this._renderers && this._renderers[action]);
  },

  // tests whether renderer is available for an action
  isRenderer : function(action, renderer) {
    return (this._renderers
      && this._renderers[action]
      && this._renderers[action][renderer]
      );
  },

  // description of the action
  getActionDescription : function(action) {
    if (action && this._schemas[action]) {
      return this._schemas[action].description
    } else {
      return this.repr();
    }
  },

  getName : function() {
    return this._name;
  },

  getSchema : function(action) {
    var schema;
    if (action) {
      if (this._schemas[action]) {
        schema = this._schemas[action];
      }
    } else {
      schema = this._schemas;
    }
    return schema;
  },

  getActionSchemas : function() {
    return this._schemas;
  },

  isTrigger : function(action) {
    return (this._schemas[action].trigger ?
      this._schemas[action].trigger :
      false
      );
  },

  getExports : function(action) {
    return this._schemas[action].exports;
  },

  testImport : function(action, importName) {
    return (Object.keys(this._schemas[action].imports).length == 0 ||
      undefined != this._schemas[action].imports.properties[importName]
      );
  },

  setDao: function(dao) {
    this._dao = dao;
  },

  getDao: function() {
    return this._dao;
  },

  // -------------------------------------------------- STREAMING AND POD DATA

  _isVisibleHost : function(host, next, channel, whitelist) {
    var self = this;
    app.helper.hostBlacklisted(host, whitelist, function(err, blacklisted, resolved) {
      if (err) {
        if (channel) {
          self.log(err, channel, 'error');
        } else {
          app.logmessage(err, 'error');
        }
      } else {
        next(err, blacklisted, resolved);
      }
    });
  },

  _httpGet: function(url, cb, headers) {
    var headerStruct = {
      'User-Agent': 'request'
    };

    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          headerStruct[k] = headers[k];
        }
      }
    }

    request(
    {
      url : url,
      method : 'GET',
      headers: headerStruct
    },
    function(error, res, body) {
      if (404 === res.statusCode) {
        cb('Not Found', body, res.headers, res.statusCode);
      } else {
        if (!error && -1 !== res.headers['content-type'].indexOf('json')) {
          try {
            body = JSON.parse(body);
          } catch (e) {
            error = e.message;
          }
        }
        cb(error, body, res ? res.headers : null, res ? res.statusCode : null);
      }
    }
    );
  },

  _httpPost: function(url, postData, next, headers) {
    var headerStruct = {
      'User-Agent': 'request'
    };

    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          headerStruct[k] = headers[k];
        }
      }
    }

    request({
      url : url,
      method : 'POST',
      json : postData,
      headers: headerStruct
    },
    function(error, res, body) {
      next(error, body, res ? res.headers : null);
    }
    );
  },

  _httpPut: function(url, putData, next, headers) {
    var headerStruct = {
      'User-Agent': 'request'
    },
    params = {
      url : url,
      method : 'PUT'
    };

    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          headerStruct[k] = headers[k];
        }
      }
    }

    params.headers = headerStruct;

    if (putData) {
      params.json = putData;
    }

    request(params, function(error, res, body) {
      next(error, body, res ? res.headers : null);
    });
  },

  /**
     * Downloads file from url.  If the file exists, then stats the existing
     * file
     */
  _httpStreamToFile : function(url, outFile, cb, exports, fileStruct) {
    var self = this,
    outLock = outFile + '.lock';

    fs.exists(outLock, function(exists) {
      if (exists) {
        app.logmessage( self._name + ' LOCKED, skipping [' + outFile + ']');

      } else {
        app.logmessage( self._name + ' writing to [' + outFile + ']');
        fs.exists(outFile, function(exists) {
          if (exists) {
            fs.stat(outFile, function(err, stats) {
              if (err) {
                app.logmessage(err, 'error');
                next(true);
              } else {
                app.logmessage( self._name + ' CACHED, skipping [' + outFile + ']');
                fileStruct.size = stats.size;
                cb(false, exports, fileStruct);
              }
            });
          } else {
            fs.open(outLock, 'w', function() {
              app.logmessage( self._name + ' FETCH [' + url + '] > [' + outFile + ']');
              request.get(
                url,
                function(exports, fileStruct) {
                  return function(error, res, body) {
                    fs.unlink(outLock);
                    if (!error && res.statusCode == 200) {
                      fs.stat(outFile, function(err, stats) {
                        if (err) {
                          app.logmessage(self._name + ' ' + err, 'error');
                          next(true);
                        } else {
                          app.logmessage( self._name + ' done [' + outFile + ']');
                          fileStruct.size = stats.size;
                          cb(false, exports, fileStruct);
                        }
                      });
                    }
                  }
                }(exports, fileStruct)
                ).pipe(fs.createWriteStream(outFile));
            });
          }
        });
      }
    });
  },

  _createChannelDir : function(pfx, channel, action, next) {
    var self = this,
      dDir = pfx + '/channels/';

    if (undefined != channel.owner_id) {
      dDir += channel.owner_id + '/';
    }
    dDir += this._name + '/' + action + '/' + channel.id + '/';

    app.helper.mkdir_p(dDir, 0777 , function(err, path) {
      if (err) {
        self.log(err.message, channel, 'error');
      }
      if (next) {
        next(err, path);
      }
    });


    return dDir;
  },

  _rmChannelDir : function(pfx, channel, action, next) {
    var self = this,
      files, file, dDir = pfx + '/channels/';

    if (undefined != channel.owner_id) {
      dDir += channel.owner_id + '/';
    }
    dDir += this._name + '/' + action + '/' + channel.id + '/';

    app.helper.rmdir(dDir, function(err) {
      if (err) {
        self.log(err.message, channel, 'error');
      }
      if (next) {
        next(err);
      }
    });
  },

  _expireChannelDir : function(pfx, channel, action, ageDays) {
    var self = this,
      dDir = pfx + '/channels/';
      maxTime = (new Date()).getTime() - (ageDays * 24 * 60 * 60 * 1000);

    if (undefined != channel.owner_id) {
      dDir += channel.owner_id + '/';
    }
    dDir += this._name + '/' + action + '/' + channel.id + '/';

    fs.readdir(dDir, function(err, files) {
      if (err) {
        self.log(err, channel, 'error');
      } else {
        for (var f = 0; f < files.length; f++) {
          (function(fileName) {
            fs.stat(fileName, function(err, stat) {
              if (err) {
                self.log(err, channel, 'error');
              } else {
                if (stat.mtime.getTime() < maxTime) {
                  fs.unlink(fileName, function(err) {
                    if (err) {
                      self.log(err, channel, 'error');
                    }
                  });

                }
              }
            });
          })(dDir + files[f]);
        }
      }
    });
  },

  // -------- Data Directory interfaces

  // returns the file based data dir for this pod
  getDataDir: function(channel, action, next) {
    return this._createChannelDir(DATA_DIR, channel, action, next);
  },

  // remove datadir and all of its contents
  rmDataDir : function(channel, action, next) {
    return this._rmChannelDir(DATA_DIR, channel, action, next);
  },

  // -------- CDN Directory interfaces

  // gets public cdn
  getCDNDir : function(channel, action, next) {
    return this._createChannelDir(CDN_DIR, channel, action, next);
  },

  // removes cdn dir and all of its contents
  rmCDNDir : function(channel, action, next) {
    return this._rmChannelDir(CDN_DIR, channel, action, next);
  },

  // removes cdn data by age
  expireCDNDir : function(channel, action, ageDays) {
    return this._expireChannelDir(CDN_DIR, channel, action, ageDays);
  },

  // -------------------------------------------------------------------------

  getImports: function(action) {
    var ret;
    if (action) {
      ret = {};
      for (var prop in this._schemas[action].imports.properties) {
        ret[prop] = '';
      }

    } else {
      ret = this._importContainer;
    }
    return ret;

  },

  // ----------------------------------------------- CHANNEL BRIDGE INTERFACE

  /**
     * Adds an Action to this Pod, attaches $resource to the action and
     * unpacks metadata for capabilities
     *
     * @param ActionProto {Object} Action Object
     */
  add : function(ActionProto) {
    this._actionProtos.push(ActionProto);
  },

  /*
     * Runs the setup function for the pod action, if one exists
     *
     * @todo separate setup scope for pod and channel action.  A pod setup for example
     * might install some default channels into the account for immediate use (such as
     * autoInstall does)
     *
     * @param action {String} Configured pod Action
     * @param channel {Channel} initialized channel
     * @param accountInfo {Object} AccountInfo Structure for Authenticated Account
     * @paran next {Function} callback
     */
  setup : function(action, channel, accountInfo, auth, next) {
    if (!next && 'function' === typeof auth) {
      next = auth;
    } else {
      accountInfo._setupAuth = auth;
    }

    if (this.actions[action] && this.actions[action].setup) {
      this.actions[action].setup(channel, accountInfo, next);
    } else {
      //next(200);
      next(false, 'channel', channel, 200);
    }
  },

  /**
     * Runs the teardown for a pod action if one exists
     *
     *
     *
     */
  teardown : function(action, channel, accountInfo, next) {
    if (this.actions[action] && this.actions[action].teardown) {
      this.actions[action].teardown(channel, accountInfo, next);
    } else {
      next(false, 'channel', channel);
    }
  },

  /**
     * Invokes the action
     *
     * @param action {String} action name
     * @param channel {Object} Channel model
     * @param imports {Object} Imports Map
     * @param sysImports {Object} System Imports and Account Info
     * @param contentParts
     * @paran next {Function} callback
     */
  invoke: function(action, channel, imports, sysImports, contentParts, next) {
    var self = this;

    if (!contentParts) {
      contentParts = {
        _files : []
      }
    }

    this.actions[action].invoke(imports, channel, sysImports, contentParts, function(err, exports) {
      if (err) {
        self.log(err, channel, 'error');
      }
      next.apply(self, arguments);
    });
  },

  /**
  * RPC's are direct calls into a pod, so its up to the pod
  * to properly authenticate data etc.
  */
  rpc : function(action, method, sysImports, options, channel, req, res) {
    var self = this;

    if (this.actions[action] && (this.actions[action].rpc || 'invoke' === method)) {
      if ('invoke' === method) {
        var imports = app.helper.pasteurize((req.method === 'GET') ? req.query : req.body);

        // @todo add files support
        this.actions[action].invoke(imports, channel, sysImports, [], function(err, exports) {
          if (err) {
            self.log(err, channel, 'error');
          }

          res.contentType(DEFS.CONTENTTYPE_JSON);
          if (err) {
            res.send(err, 500);
          } else {
            res.send(exports);
          }
        });
      } else {
        this.actions[action].rpc(method, sysImports, options, channel, req, res);
      }
    } else {
      res.send(404);
    }
  },

  /**
     * Gets an Actions description
     */
  repr : function(action) {
    return this.getActionDescription(action);
  },

  /**
     * Creates a trigger tracking record
     */
  trackingStart : function(channel, accountInfo, fromNow, next) {
    var nowTime = app.helper.nowUTCSeconds(),
    trackingStruct = {
      owner_id : channel.owner_id,
      created : nowTime,
      last_poll : fromNow ? nowTime : 0,
      channel_id : channel.id
    };

    var model = this._dao.modelFactory('channel_pod_tracking', trackingStruct, accountInfo);
    this._dao.create(model, next, accountInfo);
  },

  // get last poll time for tracker
  trackingGet : function(channel, next) {
    var filter = {
      channel_id : channel.id,
      owner_id : channel.owner_id
    };

    this._dao.findFilter('channel_pod_tracking', filter, function(err, result) {
      next(err || !result, result && result.length > 0 ? result[0].last_poll : null);
    });
  },

  // set last poll time
  trackingUpdate : function(channel, next) {
    var filter = {
      channel_id : channel.id,
      owner_id : channel.owner_id
    },
    props = {
      last_poll : app.helper.nowUTCSeconds()
    }

    this._dao.updateColumn(
      'channel_pod_tracking',
      filter,
      props,
      function(err) {
        if (err) {
          app.log(err, 'error');
        }
        next(err, props.last_poll);
      }
      );
  },

  trackingRemove : function(channel, accountInfo, next) {
    var filter = {
      channel_id : channel.id,
      owner_id : channel.owner_id
    };

    this._dao.removeFilter('channel_pod_tracking', filter, next);
  },

  /**
     * Renders self
     * @todo - stub
     */
  render: function(action, channel, accountInfo, cb) {
    if (this.canRender(action)) {

    } else {
      cb(true, undefined, {}, 404);
    }

  },

  _installSingleton : function(template, accountInfo, next) {
    var installedKeys = [];
    // don't care about catching duplicates right now
    var model = dao.modelFactory('channel', channelTemplate, {
      user : accountInfo
    } );
    dao.create(model, function(err, result) {
      i++;
      if (err) {
        app.logmessage(err, 'error');
        errors = true;
      } else {
        installedKeys.push(channelTemplate.action);
      }

      if (i === keyLen && next) {
        // errors are already be logged
        next(errors, (errors ? 'There were errors' : installedKeys.toString()) );
      }

    }, {
      user : accountInfo
    });
  },

  /**
     * Auto installs singletons for the supplied user
     */
  autoInstall : function(accountInfo, next) {
    var dao = this._dao,
    channelTemplate,
    s,
    i = 0,
    keyLen = 0,
    errors = false,
    installedKeys = [],
    singles = false;

    // check any singles exist
    for (key in this._schemas) {
      if (this._schemas[key].singleton || this._schemas[key].auto) {
        singles = true;
        keyLen++;
      }
    }

    if (keyLen && singles) {
      for (key in this._schemas) {
        s = this._schemas[key];
        if (s.singleton || s.auto) {
          channelTemplate = {
            name : s.title,
            action : this._name + '.' + key,
            config : {}, // singletons don't have config
            note : s.description
          };

          // don't care about catching duplicates right now
          model = dao.modelFactory('channel', channelTemplate, accountInfo );
          dao.create(model, function(err, modelName, result) {
            i++;
            if (err) {
              app.logmessage(err, 'error');
              errors = true;
            } else {
              installedKeys.push(result.action);
            }

            if (i === keyLen && next) {
              // errors are already be logged
              next(errors, (errors ? 'There were errors' : installedKeys.toString()), result.owner_id );
            }

          }, accountInfo );
        }
      }
    } else if (next) {
      next(true, 'No Singletons to Install');
    }
  },

  describe : function(accountInfo) {
    var self = this,
    schema = {
      'name' : this._name,
      'title' : this._title,
      'description' : this._description,
      'icon' : CFG.cdn_public + '/pods/' + this._name + '.png',
      'auth' : {
        type : this._authType,
        status : this._authType  == 'none' ? 'accepted' : 'required'
      },
      'renderers' : this._renderers,
      'actions' : {}
    };

    // attach auth binders
    if (this._authType == 'oauth') {
      schema.auth.scopes = this._config.oauth.scopes || [];
      schema.auth._href = this._dao.getBaseUrl() + '/rpc/oauth/' +  this._name + '/auth';
      schema.auth.authKeys = [];

      for (var k in this._config.oauth) {
        if (this._config.oauth.hasOwnProperty(k) && /^client/.test(k)) {
          schema.auth.authKeys.push(k);
        }
      }

    } else if (this._authType == 'issuer_token') {
      schema.auth._href = this._dao.getBaseUrl() + '/rpc/issuer_token/' +  this._name + '/set';
      if (this._authMap) {
        schema.auth.authMap = this._authMap;
      }
    }

    for (action in this._schemas) {
      if (!this._schemas[action].admin) {
        schema.actions[action] = this._schemas[action];
        if (this.canRender(action)) {
          schema.actions[action]['_href'] = this._getRendererUrl();
        }
      }
    }

    return schema;
  },

  _testAndSet : function(key, srcObj, dstObj) {
    if (undefined !== srcObj[key] && '' !== srcObj[key]) {
      dstObj[key] = srcObj[key];
    }
  }
}

module.exports = Pod;
