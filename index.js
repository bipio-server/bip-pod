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
  JSONPath = require('JSONPath'),
  extend = require('extend');
  uuid = require('node-uuid'),
  mime = require('mime'),
  cron = require('cron'),
  _ = require('underscore'),
  tldtools = require('tldtools'),
  ipaddr = require('ipaddr.js'),
  dns = require('dns'),
  validator = require('validator');

// utility resources
var helper = {
  isObject : function(obj) {
    return Object.prototype.toString.call(obj) == "[object Object]";
  },

  toUTC: function(date) {
    return new Date(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds());
  },

  now: function() {
    return new Date();
  },

  nowUTC: function() {
    return helper.toUTC(this.now());
  },

  nowUTCSeconds: function() {
    var d = helper.toUTC(helper.now());

    // @todo looks like a bug in datejs, no seconds for getTime?
    seconds = d.getSeconds() + (d.getMinutes() * 60) + (d.getHours() * 60 * 60);
    return (d.getTime() + seconds);
  },

    // Returns all ipv4/6 A records for a host
  resolveHost : function(host, next) {
    var tokens = tldtools.extract(host),
      resolvingHost;
    if (ipaddr.IPv4.isValid(host) || ipaddr.IPv6.isValid(host) ) {
      next(false, [ host ], host);
    } else {
      resolvingHost = tokens.inspect.getDomain() || tokens.domain;
      dns.resolve(resolvingHost, function(err, aRecords) {
        next(err, aRecords, resolvingHost );
      });
    }
  },

  JSONPath : function(obj, path) {
    return JSONPath.eval(obj, path);
  },

  streamToHash : function(readStream, next) {
    var hash = crypto.createHash('sha1');
    hash.setEncoding('hex');

    readStream.on('end', function() {
        hash.end();
        next(false, hash.read());
    });

    readStream.on('error', function(err) {
      next(err);
    });

    readStream.pipe(hash);
  },

  streamToBuffer : function(readStream, next) {
    var buffers = [];
    readStream.on('data', function(chunk) {
        buffers.push(chunk);
    });

    readStream.on('error', function(err) {
        next(err);
    });

    readStream.on('end', function() {
      next(false, Buffer.concat(buffers));

    });
  }
}

// pod required fields
var requiredMeta = [
  'name',
  'title',
  'description'
];

// constructor
function Pod(metadata, init) {

  metadata = metadata || {};

  // oauth provider token refresh method
  // @todo deprecate for an implementation of oAuthRefresh in pod
  if (metadata.oAuthRefresh) {
    this._oAuthRefresh = metadata.oAuthRefresh;
  }

  // post-constructor
  this._podInit = init;

  // Bip Pod Manifest
  this._bpm = {};

  // pod resources bridge
  this.$resource = {};

  // DAO
  this._dao = null;

  // logger
  this._logger = null;

  // action prototypes
  this._actionProtos = [];

  // action instances
  this.actions = {};

  // crons
  this.crons = {};

  // options
  this.options = {
    baseURL : '',
    blacklist : [],
    timezone : 'UTC',
    cdnPublicBaseURL : '',
    emitterBaseURL : '',
    config : {}
  };

  this._oAuthRegistered = false;
}

Pod.prototype = {
  getPodBase : function(podName, literal) {
    return __dirname + (literal ? '/' : '/../bip-pod-') + podName;
  },
  /**
     * make system resources available to the pod. Invoked by the Pod registrar
     * in the Channels model when bootstrapping.
     *
     * @param dao {Object} DAO.
     * @param config {Object} Pod Config
     * @param options {Object} system options
     *
     */
  init : function(podName, dao, cdn, logger, options) {
    var reqBase = this.getPodBase(podName, options.reqLiteral),
      self = this;

    this._bpm = require(reqBase + '/manifest.json');

    // check required meta's
    for (var i = 0; i < requiredMeta.length; i++) {
      if (!this.getBPMAttr(requiredMeta[i])) {
        throw new Error(podName + ' Pod is missing required "' + requiredMeta[i] + '" metadata');
      }
    }

    var dataSources = this.getDataSources(),
      self = this,
      dataSource,
      model;

    // set stored config
    if (options.config) {
      this.setConfig(options.config);
    }

    // merge options
    _.each(options, function(value, key) {
      if ('config' !== key) {
        self.options[key] = value;
      }
    });

    if (dao) {
      this._dao = dao;
    }

    if (logger) {
      this._logger = logger;
    }

    // register generic tracker
    var tracker = require('./models/channel_pod_tracking');
    this._dao.registerModel(tracker);

    // create pod tracking container for duplicate entities
    if (this._trackDuplicates) {
      var podDupTracker = _.clone(require('./models/dup'));

      podDupTracker.entityName = this.getDataSourceName(podDupTracker.entityName);

      this._dao.registerModel(podDupTracker);

//      this.$resource.dupFilter = this.dupFilter;
    }

    // register pod data sources
    for (var dsName in dataSources) {
      if (dataSources.hasOwnProperty(dsName)) {
        dataSource = _.clone(dataSources[dsName]);

        // namespace the model + create an internal representation
        dataSource.entityName = this.getDataSourceName(dsName);
        dataSource.entitySchema = dataSource.properties;
        dataSource.compoundKeyConstraints  = _.object(
          _.map(
            dataSource.keys,
            function(x) {
              return [x, 1]
            }
          )
        );

        this._dao.registerModel(dataSource);
      }
    }

    // register the oauth strategy
    if (this.getAuthType() === 'oauth') {
      var auth = self.getAuth(),
        pProvider = (auth.passport && auth.passport.provider)
          ? auth.passport.provider
          : this.getName(),
        pStrategy = (auth.passport && auth.passport.strategy)
          ? auth.passport.strategy
          : 'Strategy',
        passport = require(reqBase + '/node_modules/passport-' + pProvider);

      this._oAuthRegisterStrategy(
        passport[pStrategy],
        self.getConfig().oauth
      );

      // cleanup
      delete auth.passport;
    }

    // bind pod renderers
    var rpcs = this.getRPCs();
    _.each(rpcs, function(rpc, key) {
      rpc._href = self.options.baseUrl + '/rpc/pod/' + self.getName() + '/render/' + key;

      if (!rpc.method) {
        rpc.method = 'GET';
      }

      if (!rpc.name) {
        rpc.name = key;
      }
    });

    //
    // --- CREATE RESOURCES
    //

    // create resources for Actions
    this.$resource.dao = dao;
    this.$resource.moment = moment;
    this.$resource.mime = mime;
    this.$resource.uuid = uuid;
    this.$resource.sanitize = validator.sanitize;

    this.$resource.accumulateFilter = this.accumulateFilter;

    this.$resource.log = (function(scope) {
      return function() {
        scope.log.apply(scope, arguments);
      }
    })(this);

    this.$resource.getDataSourceName = function(dsName) {
      return 'pod_' + self.getName().replace(/-/g, '_') + '_' + dsName;
    };

    this.$resource.getDataDir = this.getDataDir;
    this.$resource.getCDNDir = this.getCDNDir;
    this.$resource.expireCDNDir = this.expireCDNDir;

    this.$resource._httpGet = this._httpGet;
    this.$resource._httpPost = this._httpPost;
    this.$resource._httpPut = this._httpPut;
    this.$resource._httpStreamToFile = this._httpStreamToFile;

    this.$resource.stream = {
      toHash : helper.streamToHash,
      toBuffer : helper.streamToBuffer
    }

    // temporary file management bridge
    this.$resource.file = cdn;

    this.$resource._isVisibleHost = this._isVisibleHost;

    // give the pod a scheduler
    if (options.isMaster) {
      this.$resource.cron = cron;
    }

    // --------- BIND ACTIONS

    // bind actions
    var action;
    _.each(this.getActionSchemas(), function(schema, actionName) {
      if (!schema.disabled) {
        var reqBase = self.getPodBase(podName, options.reqLiteral),
          actionProto = require(reqBase + '/' + actionName + '.js');

        action = new actionProto(self.getConfig(), self);
        action.$resource = self.$resource;

        // bind meta info
        action.name = actionName;
        action.schema = schema;
        action.pod = self;

        // add to action collection
        self.actions[actionName] = action;
      }
    });

    if (this._podInit) {
      this._podInit.apply(this);
    }
  },

  // tests whether host is in blacklist
  hostBlacklisted : function(host, whitelist, next) {
    var blacklist = this.options.blacklist;

    helper.resolveHost(host, function(err, aRecords, resolvedHost) {
      var inBlacklist = false;
      if (!err) {
        if (whitelist) {
          if (_.intersection(aRecords, whitelist).length ) {
            next(err, [], aRecords);
            return;
          } else {
            for (var i = 0; i < whitelist.length; i++) {
              if (resolvedHost === whitelist[i]) {
                next(err, [], aRecords);
                return;
              }
            }
          }
        }

        inBlacklist = _.intersection(aRecords, blacklist)
      }
      next(err, inBlacklist, aRecords);
    });
  },

  /**
   * Retrieves matching elements from the manfiest with a JSON Path
   * When no element found, returns null
   *
   * @param string path JSONPath
   * @returns mixed result or null
   */
  _attrCache : {},
  getBPMAttr : function (path) {
    var val;
    if (true || !this._attrCache[path]) {
      var result = helper.JSONPath(this._bpm, path);
      if (result.length === 1) {
        val = result[0];
      } else if (result.length) {
        val = result;
      } else {
        val = null;
      }
      this._attrCache[path] = val;
    }

    return this._attrCache[path];
  },

  getSchema : function(action) {
    return this._bpm;
  },

  // --------------------------- BPM path accessors
  getName : function() {
    return this.getBPMAttr('name');
  },

  getTitle : function() {
    return this.getBPMAttr('title');
  },

  getDescription : function() {
    return this.getBPMAttr('description');
  },

  getIcon : function() {
    return this.options.cdnPublicBaseURL + this.getName() + '.png';
  },

  getRPCs : function() {
    return this.getBPMAttr('rpcs') || {};
  },

  // AUTH

  getAuthType : function() {
    return this.getBPMAttr('auth.strategy') || 'none';
  },

  getAuthMap : function() {
    return this.getBPMAttr('auth.authMap') || {};
  },

  getAuth : function() {
    var auth = this.getBPMAttr('auth');
    auth.status = 'none' === auth.strategy ? 'accepted' : 'required'
    return auth;
  },

  // POD CONFIG

  getConfig : function() {
    return this.getBPMAttr('config') || {};
  },

  setConfig: function(config) {
    this._bpm.config = config;
  },

  // DATASOURCES

  getDataSources : function() {
    return this.getBPMAttr('dataSources') || {};
  },

  getDataSourceName : function(dsName) {
    return 'pod_' + this.getName().replace(/-/g, '_') + '_' + dsName;
  },

  // DAO

  setDao: function(dao) {
    this._dao = dao;
  },

  getDao: function() {
    return this._dao;
  },

  // --------------------------- BPM ACTION Path Accessors

  getTriggerType : function(action) {
    return this.getBPMAttr('actions.' + action + '.trigger');
  },

  getActionSchemas : function() {
    return this.getBPMAttr('actions');
  },

  getAction : function(action) {
    return this.getBPMAttr('actions.' + action);
  },

  getActionConfig : function(action) {
    return this.getBPMAttr('actions.' + action + '.config');
  },

  getActionExports : function(action) {
    return this.getBPMAttr('actions.' + action + '.exports');
  },

  getActionImports : function(action) {
    return this.getBPMAttr('actions.' + action + '.imports');
  },

  getActionConfigDefaults : function(action) {
    var defaults = {},
      config = this.getActionConfig(action);

    _.each(config.properties, function(attr, key) {
      if (attr['default']) {
        defaults[key] = attr['default'];
      }
    });

    return defaults;
  },

  getActionImportDefaults : function(action) {
    var defaults = {},
      imports = this.getActionImports(action);

    _.each(imports.properties, function(attr, key) {
      if (attr['default']) {
        defaults[key] = attr['default'];
      }
    });

    return defaults;
  },

  getActionRPC : function(action, rpc) {
    return this.getBPMAttr('actions.' + action + '.rpcs.' + rpc);
  },

  // description of the action
  getActionDescription : function(action) {
    return this.getAction(action).description;
  },

  // alias for getActionDescription
  repr : function() {
    return this.getActionDescription.apply(this, arguments);
  },

  // --------------------------- Compound tests and helpers

  // invoker for this action can generate its own content (periodically)
  isTrigger: function(action) {
    var tt = this.getTriggerType(action);
    return ('poll' === tt || 'realtime' === tt);
  },

  isRealtime : function(action) {
    var tt = this.getTriggerType(action);
    return ('realtime' === tt);
  },

  // action can render its own stored content
  canRender: function(action) {
    return this.getBPMAttr('actions.' + action + '.rpcs') !== null;
  },

  // tests whether renderer is available for an action
  isRenderer : function(action, renderer) {
    return this.getBPMAttr('actions.' + action + '.rpcs.' + renderer) !== null;
  },

  testImport : function(action, importName) {
    return this.getBPMAttr('actions.' + action + '.imports.' + importName)
  },

  listActions : function() {
    return _.where(this.getActionSchemas(), { trigger : 'invoke'} );
  },

  listEmitters : function() {
//    return this.getBPMAttr('.actions[?(@.trigger!="invoke")]');
    return _.filter(this.getActionSchemas(), function(action, key) {
      return (action.trigger !== 'invoke');
    });
  },

  // provide a scheduler service
  registerCron : function(id, period, callback) {
    var self = this;

    if (this.$resource.cron) {
      if (!this.crons[id]) {
        self._logger.call(self, 'POD:Registering Cron:' + self.getName() + ':' + id);
          self.crons[id] = new self.$resource.cron.CronJob(
            period,
            callback,
            null,
            true,
            self.options.timezone
          );
      }
    }
  },

  /**
     * Logs a message
     */
  log : function(message, channel, level) {
    if (helper.isObject(message)) {
      this._logger.call(this,
        channel.action
        + ':'
        + (channel.owner_id ? channel.owner_id : 'system'),
        level);
      this._logger.call(this, message, level);
    } else {
      this._logger.call(this,
        channel.action
        + ':'
        + (channel.owner_id ? channel.owner_id : 'system'),
        + ':'
        + message,
        level);
    }
  },

  _isVisibleHost : function(host, next, channel, whitelist) {
    var self = this;
    self.hostBlacklisted(host, whitelist, function(err, blacklisted, resolved) {
      if (err) {
        if (channel) {
          self.log(err, channel, 'error');
        } else {
          self._logger.call(self, err, 'error');
        }
      } else {
        next(err, blacklisted, resolved);
      }
    });
  },

  // ------------------------------ 3RD PARTY AUTHENTICATION HELPERS

  testCredentials : function(struct, next) {
    next(false);
  },

  issuerTokenRPC : function(method, req, res) {
    var ok = false,
      accountId = req.remoteUser.user.id;
      self = this;

    res.contentType(DEFS.CONTENTTYPE_JSON);

    if (this.getAuthType() == 'issuer_token') {
      if (method == 'set') {
        self._logger.call(self, '[' + accountId + '] ISSUER_TOKEN ' + this.getName() + ' SET' );

        // upsert oAuth document
        var filter = {
          owner_id : accountId,
          type : this.getAuthType(),
          auth_provider : this.getName()
        };

        var struct = {
          owner_id : accountId,
          username : req.query.username,
          key : req.query.key,
          password : req.query.password,
          type : this.getAuthType(),
          auth_provider : this.getName()
        };

        self.testCredentials(struct, function(err, status) {
          if (err) {
            res.status(status || 401).jsonp({ "message" : err.toString() });

          } else {

            // @todo upserts don't work with mongoose middleware
            // create a dao helper for filter -> model upsert.
            self._dao.find('account_auth', filter, function(err, result) {
              if (err) {
                self._logger.call(self, err, 'error');
                res.send(500);
              } else {
                // update
                if (result) {
                  self._dao.update('account_auth', result.id, struct, function(err, result) {
                    if (err) {
                      self._logger.call(self, err, 'error');
                      res.status(500).jsonp({});
                    } else {
                      res.status(200).jsonp({});
                    }
                  }, req.remoteUser);
                } else {
                  // create
                  var model = self._dao.modelFactory('account_auth', struct);
                  self._dao.create(model, function(err, result) {
                    if (err) {
                      self._logger.call(self, err, 'error');
                      res.status(500).jsonp({});
                    } else {
                      res.status(200).jsonp({});
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
          auth_provider : this.getName()
        }

        this._dao.removeFilter('account_auth', filter, function(err) {
          if (!err) {
            res.status(200).jsonp({});
          } else {
            self._logger.call(self, err, 'error');
            res.status(500).jsonp({});
          }
        });
        ok = true;
      }
    }
    return ok;
  },

  /**
     * @param string method auth rpc method name
     * @param object req request
     * @param object res response
     */
  oAuthRPC: function(method, req, res) {
    var ok = false,
    authMethod = (this._oAuthMethod) ? this._oAuthMethod : 'authorize',
    self = this,
    podName = this.getName(),
    accountInfo = req.remoteUser,
    accountId = accountInfo.getId(),
    emitterHost = this.options.emitterBaseURL;

    if (false !== this._oAuthRegistered) {
      // invoke the passport oauth handler
      if (method == 'auth') {
        self._logger.call(self, '[' + accountId + '] OAUTH ' + podName + ' AUTH REQUEST' );

        passport[authMethod](this.getName(), this._oAuthConfig)(req, res);
        ok = true;

      } else if (method == 'cb') {
        self._logger.call(self, '[' + accountId + '] OAUTH ' + podName + ' AUTH CALLBACK ' + authMethod );
        passport[authMethod](this.getName(), function(err, user) {
          // @todo - decouple from site.
          if (err) {
            self._logger.call(self, err, 'error');
            res.redirect(emitterHost + '/oauthcb?status=denied&provider=' + podName);

          } else if (!user && req.query.error_reason && req.query.error_reason == 'user_denied') {
            self._logger.call(self, '[' + accountId + '] OAUTH ' + podName + ' CANCELLED' );
            res.redirect(emitterHost + '/oauthcb?status=denied&provider=' + podName);

          } else if (!user) {
            self._logger.call(self, '[' + accountId + '] OAUTH ' + podName + ' UNKNOWN ERROR' );
            res.redirect(emitterHost + '/oauthcb?status=denied&provider=' + podName);

          } else {
            self._logger.call(self, '[' + accountId + '] OAUTH ' + podName + ' AUTHORIZED' );
            // install singletons
//            self.autoInstall(accountInfo);
            res.redirect(emitterHost + '/oauthcb?status=accepted&provider=' + podName);
          }
        })(req, res, function(err) {
          res.send(500);
          self._logger.call(self, err, 'error');
        });
        ok = true;
      } else if (method == 'deauth') {
        this.oAuthUnbind(accountId, function(err) {
          if (!err) {
            res.send(200);
          } else {
            self._logger.call(self, err, 'error');
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

  authStatus : function(owner_id, next) {
    if (this.isOAuth()) {
      this.oAuthStatus(owner_id, next);
    } else {
      this._getPassword(owner_id, next);
    }
  },

  isOAuth : function() {
    return 'oauth' === this.getAuthType();
  },

  isIssuerAuth : function() {
    return 'issuer_token' === this.getAuthType();
  },

  _getPassword : function(ownerId, next) {
    var self = this,
      podName = this.getName(),
      filter = {
        owner_id : ownerId,
        type : this.getAuthType(),
        auth_provider : podName
      };

    this._dao.find('account_auth', filter, function(err, result) {
      if (!result || err) {
        if (err) {
          self._logger.call(self, err, 'error');
          next(true, podName, self.getAuthType(), result );
        } else {
          next(false, podName, self.getAuthType(), result );
        }
      } else {
        next(false, podName,  self.getAuthType(), result);
      }
    });

  },

  /**
     * passes oAuth result set if one exists
     */
  oAuthStatus : function(owner_id, next) {
    var self = this,
    podName = this.getName(),
    filter = {
      owner_id : owner_id,
      type : this.getAuthType(),
      oauth_provider : this.getName()
    };
    this._dao.find('account_auth', filter, function(err, result) {
      next(err, podName, filter.type, result);
    });
  },

  /**
     *
     * Registers an oAuth strategy for this pod
     *
     */
  _oAuthRegisterStrategy : function(strategy, config) {

    var self = this,
      localConfig = {
        callbackURL : self.options.baseUrl  + '/rpc/oauth/' + this.getName() + '/cb',
        failureRedirect : self.options.baseUrl  + '/rpc/oauth/' + this.getName() + '/denied',
        passReqToCallback: true
      },
      passportStrategy;

    for (key in config) {
      localConfig[key] = config[key];
    }

    self._oAuthConfig = {
      scope : config.scopes
    };

    if (config.extras) {
      _.each(config.extras, function(val, key) {
        self._oAuthConfig[key] = val;
      });
    }

    this._oAuthRegistered = true;

    passportStrategy = new strategy(
      localConfig,
      function(req, accessToken, refreshToken, params, profile, done) {
        // maintain scope
        self.oAuthBinder(req, accessToken, refreshToken, params, profile, done);
      });

    // set strategy name as the pod name
    // this is for authing separate applications/pods
    // with the same strategy
    passportStrategy.name = this.getName();

    passport.use(passportStrategy);
  },

  /**
     *
     */
  oAuthUnbind : function(ownerid, next) {
    var filter = {
      owner_id : ownerid,
      type : 'oauth',
      oauth_provider : this.getName()
    }

    this._dao.removeFilter('account_auth', filter, next);
    this._dao.updateColumn(
      'channel',
      {
        owner_id : ownerid,
        action : {
          $regex : this.getName() + '\.*'
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
      oauth_provider : this.getName()
    };

    var struct = {
      owner_id : accountId,
      password : accessToken,
      type : 'oauth',
      oauth_provider : this.getName(),
      oauth_refresh : refreshToken || '',
      oauth_profile : profile._json ? profile._json : profile
    };

    if (params.expires_in) {
      struct.oauth_token_expire = params.expires_in;
    }

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
          var model = self._dao.modelFactory(modelName, struct);
          self._dao.create(model, function(err, result) {
            next( err, accountInfo );
          });
        }
      }
    });
  },

  oAuthRefresh : function(authModel) {
    var refreshToken = authModel.getOAuthRefresh(),
    self = this;

    this._oAuthRefresh(refreshToken, function(err, refreshStruct) {
      if (!err && refreshStruct) {
        self._dao.updateProperties(
          'account_auth',
          authModel.id,
          {
            password : refreshStruct.access_token,
            oauth_token_expire : refreshStruct.expires_in
          },
          function(err) {
            if (!err) {
              self._logger.call(self, self.getName() + ':OAuthRefresh:' + authModel.owner_id);
            } else {
              self._logger.call(self, err, 'error');
            }
          }
          );
      }
    });
  },


  // -------------------------------------------------- STREAMING AND POD DATA

  _httpGet: function(url, cb, headers, options) {
    var headerStruct = {
      'User-Agent': 'request'
    };

    var params = {
      url : url,
      method : 'GET'
    };

    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          headerStruct[k] = headers[k];
        }
      }
    }

    params.headers = headerStruct;

    if (options) {
      for (var k in options) {
        if (options.hasOwnProperty(k)) {
          params[k] = options[k];
        }
      }
    }

    request(params, function(error, res, body) {
        if (-1 !== res.headers['content-type'].indexOf('json')) {
          try {
            body = JSON.parse(body);
          } catch (e) {
            error = e.message;
          }
        }

        if (404 === res.statusCode) {
          cb('Not Found', body, res.headers, res.statusCode);
        } else {
          cb(error, body, res ? res.headers : null, res ? res.statusCode : null);
        }
      }
    );
  },

  _httpPost: function(url, postData, next, headers, options) {
    var headerStruct = {
      'User-Agent': 'request'
    };

    var params = {
      url : url,
      method : 'POST',
      json : postData
    }

    if (headers) {
      for (var k in headers) {
        if (headers.hasOwnProperty(k)) {
          headerStruct[k] = headers[k];
        }
      }
    }

    params.headers = headerStruct;

    if (options) {
      for (var k in options) {
        if (options.hasOwnProperty(k)) {
          params[k] = options[k];
        }
      }
    }

    request(params, function(error, res, body) {
      next(error, body, res ? res.headers : null);
    });
  },

  _httpPut: function(url, putData, next, headers, options) {
    var headerStruct = {
      'User-Agent': 'request'
    },
    params = {
      url : url,
      method : 'PUT'
    };

    if (options) {
      for (var k in options) {
        if (options.hasOwnProperty(k)) {
          params[k] = options[k];
        }
      }
    }

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

  // -------------------------------------------------- CDN HELPERS

  _cdnFileSave : function(readableStream, filename, options, next) {
    if ('function' === typeof persist) {
      next = options;
      options = {};
    }
  },

  /**
   * Returns a readable file stream
   */
  _cdnFileGet : function(fileStruct, next) {
    next(false, fileStruct, fs.createReadStream(path.join(fileStruct.localpath)));
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
        self._logger.call(self,  self.getName() + ' LOCKED, skipping [' + outFile + ']');

      } else {
        self._logger.call(self,  self.getName() + ' writing to [' + outFile + ']');
        fs.exists(outFile, function(exists) {
          if (exists) {
            fs.stat(outFile, function(err, stats) {
              if (err) {
                self._logger.call(self, err, 'error');
                next(true);
              } else {
                self._logger.call(self,  self.getName() + ' CACHED, skipping [' + outFile + ']');
                fileStruct.size = stats.size;
                cb(false, exports, fileStruct);
              }
            });
          } else {
            fs.open(outLock, 'w', function() {
              self._logger.call(self,  self.getName() + ' FETCH [' + url + '] > [' + outFile + ']');
              request.get(
                url,
                function(exports, fileStruct) {
                  return function(error, res, body) {
                    fs.unlink(outLock);
                    if (!error && res.statusCode == 200) {
                      fs.stat(outFile, function(err, stats) {
                        if (err) {
                          self._logger.call(self, self.getName() + ' ' + err, 'error');
                          next(true);
                        } else {
                          self._logger.call(self,  self.getName() + ' done [' + outFile + ']');
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
    dDir += this.getName() + '/' + action + '/' + channel.id + '/';

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
    dDir += this.getName() + '/' + action + '/' + channel.id + '/';

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
    dDir += this.getName() + '/' + action + '/' + channel.id + '/';

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


  // ----------------------------------------------- CHANNEL BRIDGE INTERFACE

  /**
     * Adds an Action to this Pod, attaches $resource to the action and
     * unpacks metadata for capabilities
     *
     * @param ActionProto {Object} Action Object
     */
/*
  add : function(ActionProto) {
    this._actionProtos.push(ActionProto);
  },
  */

  // DUMMY - DEPRECATED
  add : function() {

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

  // tries to drop any duplicates from db
  _dupTeardown : function(channel, next) {
    var filter = {
        channel_id : channel.id
      },
      modelName = this.getDataSourceName('dup');

    this._dao.removeFilter(modelName, filter, next);
  },

  /**
    * Runs the teardown for a pod action if one exists
    */
  teardown : function(action, channel, accountInfo, next) {
    var self = this;
    if (this.actions[action] && this.actions[action].teardown) {
      if (this._trackDuplicates) {
        // confirm teardown and drop any dup tracking from database
        this.actions[action].teardown(channel, accountInfo, function(err, modelName, result) {
          next(err, modelName, result);
          self._dupTeardown(channel);
        });
      } else {
        this.actions[action].teardown(channel, accountInfo, next);
      }
    } else {
      if (this._trackDuplicates) {
        self._dupTeardown(channel);
      }
      next(false, 'channel', channel);
    }
  },

  /**
    *
    *
    *
    */
  bindUserAuth : function(sysImports, ownerId, next) {
    var self = this;

    if (!sysImports.auth) {
      sysImports.auth = {};
    }

    if ( (self.isOAuth() && !sysImports.auth.oauth) || (self.isIssuerAuth() && !sysImports.auth.issuer_token) )  {
      self._dao.getPodAuthTokens(ownerId, this, function(err, tokenStruct) {
        if (err) {
          next(err);
        } else {
          sysImports.auth = {};

          if (self.isOAuth()) {
            sysImports.auth.oauth = tokenStruct;
          } else if (self.isIssuerAuth()) {
            sysImports.auth.issuer_token = tokenStruct;
          }

          next(false, sysImports);
        }
      });
    } else {
      next(false, sysImports);
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

    if (this.actions[action].invoke) {

      if (!contentParts) {
        contentParts = {
          _files : []
        }
      }

     try {

        // apply channel config defaults into imports, if required
        // fields don't already exist
        var actionSchema = this.getAction(action),
          haveRequiredFields = true,
          missingFields = [],
          errStr;

        // apply config defaults
        var configDefaults = this.getActionConfigDefaults(action);
        _.each(configDefaults, function(value, key) {
          if (!channel.config[key]) {
            channel.config[key] = value;
          }
        });

        // transpose from config to imports (no need to reference channel.config in pods)
        _.each(channel.config, function(value, key) {
          if (!imports[key]) {
            imports[key] = channel.config[key];
          }
        });

        // derive import defaults
        var importDefaults = this.getActionImportDefaults(action);
        _.each(importDefaults, function(value, key) {
          if (!imports[key]) {
            imports[key] = value;
          }
        });

        // trim empty imports
        for (var k in imports) {
          if (imports.hasOwnProperty(k) && '' === imports[k]) {
            delete imports[k];
          }
        }

        if (actionSchema.imports
          && actionSchema.imports.required
          && actionSchema.imports.required.length) {

          for (var i = 0; i < actionSchema.imports.required.length; i++) {
            if (!imports[actionSchema.imports.required[i]]) {
              haveRequiredFields = false;
              missingFields.push(actionSchema.imports.required[i]);
            }
          }
        }

        if (haveRequiredFields) {
          //
          this.actions[action].invoke(imports, channel, sysImports, contentParts, function(err, exports) {
            if (err) {
              self.log(err, channel, 'error');
            }
            next.apply(self, arguments);
          });

        } else {
          errStr = 'Missing Required Field(s):' + missingFields.join();
        }

      } catch (e) {
        errStr = 'EXCEPT ' + e.toString();
      }

      if (errStr) {

       self.log(errStr, channel, 'error');
       next.call(self, errStr);
      }
    }
  },

  /**
  * RPC's are direct calls into a pod, so its up to the pod
  * to properly authenticate data etc.
  */
  rpc : function(action, method, sysImports, options, channel, req, res) {
    var self = this;

    if (this.actions[action] && (this.actions[action].rpc || 'invoke' === method)) {
      if ('invoke' === method) {
        var imports = (req.method === 'GET' ? req.query : req.body);

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
   * Creates a json-schema-ish 'public' view of this Pod
   */
  describe : function() {
    var self = this,
      rpcs = this.getRPCs(),
      schema = {
        'name' : this.getName(),
        'title' : this.getTitle(),
        'description' : this.getDescription(),
        'icon' : this.getIcon(),
        'auth' : this.getAuth(),
        'rpcs' : this.getRPCs(),
        'url' : this.getBPMAttr('url'),
        'actions' : this.getBPMAttr('actions')
      },
      authType = this.getAuth().strategy;

    // attach auth binders
    if (authType == 'oauth') {
      schema.auth.scopes = this.getConfig().oauth.scopes || [];
      schema.auth._href = self.options.baseUrl + '/rpc/oauth/' + this.getName() + '/auth';
      schema.auth.authKeys = [];

      for (var k in this.getConfig().oauth) {
        if (this.getConfig().oauth.hasOwnProperty(k) && /^client/.test(k)) {
          schema.auth.authKeys.push(k);
        }
      }

    } else if (authType == 'issuer_token') {
      schema.auth._href = self.options.baseUrl + '/rpc/issuer_token/' +  this.getName() + '/set';
      schema.auth.authMap = this.getAuthMap();
    }

    return schema;
  },

  /**
   * Returns array of config/imports in merged disposition order
   *
   */
  dispositionDescribe : function(action) {
    var self = this,
      imports = this.getActionImports(action),
      config = this.getActionConfig(action),
      descriptions = [];

     _.each(
      _.uniq(
        _.union(imports.required, config.required).concat(
          imports.disposition,
          config.disposition
        )
      ),
      function(attr) {
        var prop;

        if (imports.properties.hasOwnProperty(attr)) {
          prop = _.clone(imports.properties[attr]);
        } else if (config.properties.hasOwnProperty(attr)) {
          prop = _.clone(config.properties[attr]);
        }

        if (prop) {
          prop.name = attr;
          descriptions.push(prop);
        } else {
          self._logger('required field "' + attr + '" not in imports or config', 'warn');
        }
      }
    );

     return descriptions;
  },

  /*
   * Unpacks given arguments by their schema disposition
   *
   * @return object keyed by config, imports, auth
   */
  dispositionUnpack : function(action, args) {
    var self = this,
      imports = this.getActionImports(action),
      config = this.getActionConfig(action),
      unpacked = {
        config : {},
        imports : {}
      },
      disposition = this.dispositionDescribe(action),
      ptr;

    _.each(args, function(value, idx) {
      ptr = disposition[idx];

      if (imports.properties.hasOwnProperty(ptr.name)) {
        unpacked.imports[ptr.name] = value;
      }

      if (config.properties.hasOwnProperty(ptr.name)) {
        unpacked.config[ptr.name] = value;
      }
    });

    return unpacked;
  },

  // @todo deprecate
  _testAndSet : function(key, srcObj, dstObj) {
    if (undefined !== srcObj[key] && '' !== srcObj[key]) {
      dstObj[key] = srcObj[key];
    }
  },

  //
  // --------------------------- DATA SERVICE HELPERS
  //

  /**
    * Creates a trigger tracking record
    */
  trackingStart : function(channel, accountInfo, fromNow, next) {
    var nowTime = helper.nowUTCSeconds(),
    trackingStruct = {
      owner_id : channel.owner_id,
      created : nowTime,
      last_poll : fromNow ? nowTime : 0,
      channel_id : channel.id
    };

    var model = self._dao.modelFactory('channel_pod_tracking', trackingStruct);
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
    self = this,
    props = {
      last_poll : helper.nowUTCSeconds()
    }

    this._dao.updateColumn(
      'channel_pod_tracking',
      filter,
      props,
      function(err) {
        if (err) {
          self.log(err, 'error');
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

  // duplicate filter (type coerced)
  // *** NOTE : Requires a 'dup' model for Pod
  // scoped to $resource (please fix)
  dupFilter : function(obj, key, channel, sysImports, next) {
    var self = this,
      modelName = this.getDataSourceName('dup'),
      objVal = helper.JSONPath(obj, key),
      filter = {
        owner_id : channel.owner_id,
        channel_id : channel.id,
        bip_id : sysImports.bip.id,
        value : objVal
      },
      props = {
        last_update : helper.nowUTCSeconds(),
        owner_id : channel.owner_id,
        channel_id : channel.id,
        bip_id : sysImports.bip.id,
        value : objVal
      };

    self.dao.find(modelName, filter, function(err, result) {
      if (err) {
        next(err);
      } else {
        if (!result || (result && result.value != objVal)) {
          self.dao.upsert(modelName, filter, props, function(err, result) {
            next(err, obj);
          });
        }
      }
    });
  },

  /**
   *
   *
   *
   */
  accumulateFilter : function(modelName, filter, setter, incBy, next) {
    var self = this,
      modelName = this.getDataSourceName(modelName),
      dao = self.dao;

    dao.accumulateFilter(modelName, filter, 'count', setter, function(err) {
      if (err) {
        next(err);
      } else {
        // check if it was an upsert and give it an id if none present (yuck)
        dao.find(modelName, filter, function(err, result) {
          if (err) {
            next(err);
          } else {
            // pretty gross, is there a better way?
            if (!result.id) {
              dao.updateColumn(
                modelName,
                filter,
                {
                  id : app.helper.uuid().v4(),
                  created : app.helper.nowUTCSeconds()
                },
                function(err) {
                  if (err) {
                    next(err);
                  } else {
                    next(false, result.count);
                  }
                }
              );
            } else {
              next(false, result.count);
            }
          }
        });
      }
    }, incBy);
  },
}

module.exports = Pod;
