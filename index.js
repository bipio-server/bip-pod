/**
 * 
 * The Bipio Pod Bridge.  Provides basic system resources, auth helpers,
 * setup, invoke and data sources for actions within the pod.
 * 
 * @author Michael Pearson <michael@cloudspark.com.au>
 * Copyright (c) 2010-2013 CloudSpark pty ltd http://www.cloudspark.com.au
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
 * A Bipio Commercial OEM License may be obtained via enquiries@cloudspark.com.au
 */
var passport = require('passport'),
    request = require('request'),
    util = require('util'),
    fs = require('fs');

// constructor
function Pod(metadata) {
    this._name = metadata.name || 'Anonymous Pod';
    this._description = metadata.description;
    this._description_long = metadata.description_long;
    this._authType = metadata.authType || 'none';    
    this._config = metadata.config || null;
    this._dataSources = metadata.dataSources || [];
}

function Action() {   
}

Action.prototype.invoke = function(imports, channel, sysImports, contentParts, next) {
    throw new Error('Actions Must Implement invoke(imports, channel, sysImports, contentParts, next)');
}

Pod.prototype = {
    _oAuth : null,
    _sysImports: null,

    _schemas: [], // import configs and schema, keyed to channel action
    _importContainer: {},

    _dataSources : [],
    _dao : null,
    _config : null,
    _sysConfig : {},
    
    actions : {},
    models : {},

    $resource : {},

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
            self = this;

        if (!this._dao) {
            this._dao = dao;
        }

        for (var i = 0; i < dsi; i++) {
            
             //require('../channel_pod_email_verify').EmailVerify
            
            this._dao.registerModel('../models/' + this._dataSources[i]);
        }

        // create an imports container
        for (var action in this._schemas) {
            this._importContainer[this._schemas[action]] = {};
            for ( var attribute in this._schemas[action]) {
                this._importContainer[this._schemas[action]][attribute] = ''
            }
        }
        
        if (config) {
            this.setConfig(config);
        }

        this._sysConfig = sysConfig;

        // register the oauth strategy
        if (this._authType === 'oAuth') {
            var passportStrategy = 'passport-' + this._name;
            this._oAuthRegisterStrategy(
                require(passportStrategy).Strategy, 
                self._config.oauth.auth,
                // oAuth permission list
                self._config.oauth.scopes || []
            );
        }
        
        
        // create resources for Actions
        this.$resource.dao = dao;
        this.$resource.log = this.log;        
    },

    /**
     * Sets the configuration for this pod
     * 
     * @param config {Object} configuration structure for this Pod
     */
    setConfig: function(config) {
        this._config = config;
    },

    /**
     * Logs a message
     */
    log : function(message, channel, sysImports, level) {
        app.logmessage(
            this._name 
                + '.' 
                + channel.action 
                + ':' 
                + sysImports.owner_id 
                + ':' 
                + message, 
            level);
    },

    // ------------------------------ 3RD PARTY AUTHENTICATION HELPERS

    // @todo oAuthScope should direclty key into which actions are available
    // for the pod so that we have a clean upgrade path for users. ie: they
    // reauthenticate and we upgrade the perms + install new channels
    _oAuthScope : [],

    _oAuthRegistered : false,

    issuerTokenRPC : function(podName, method, req, res) {
        var ok = false;

        if (this._authType == 'issuer_token') {
            if (method == 'set') {
                app.logmessage('[' + req.remoteUser.id + '] ISSUER_TOKEN ' + podName + ' SET' );
                var setTo = req.query.to;

                var self = this;

                // upsert oAuth document
                var filter = {
                    owner_id : req.remoteUser.id,
                    type : this._authType
                };

                var struct = {
                    owner_id : req.remoteUser.id,
                    password : setTo,
                    type : this._authType
                };

                var model = this._dao.modelFactory('account_auth', struct);

                // @todo upserts don't work with mongoose middleware
                // create a dao helper for filter -> model upsert.
                this._dao.find('account_auth', filter, function(err, result) {
                    if (err) {
                        app.logmessage(err, 'error');
                        done( err, req.remoteUser );
                    } else {
                        // update
                        if (result) {
                            self._dao.update('account_auth', result.id, struct, function(err, result) {
                                if (!err) {
                                    res.send(200);
                                }
                            }, {
                                user : req.remoteUser
                            } );
                        // create
                        } else {
                            self._dao.create(model, function(err, result) {
                                if (err) {
                                    app.logmessage(err, 'error');
                                    res.send(500);
                                } else {
                                    res.send(200);
                                }
                            });
                        }
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
            self = this;

        if (false !== this._oAuthRegistered) {
            // invoke the passport oauth handler
            if (method == 'auth') {
                app.logmessage('[' + req.user.id + '] OAUTH ' + podName + ' AUTH REQUEST' );
                passport[authMethod](podName, {
                    scope : this._oAuthScope
                })(req, res);
                ok = true;

            } else if (method == 'cb') {
                app.logmessage('[' + req.user.id + '] OAUTH ' + podName + ' AUTH CALLBACK ' + authMethod );
                passport[authMethod](podName, function(err, user) {
                    // @todo - decouple from site.
                    if (err) {
                        app.logmessage(err, 'error');                        
                        res.redirect(CFG.website_public + '/emitter/oauthcb?status=denied&provider=' + podName);

                    } else if (!user && req.query.error_reason && req.query.error_reason == 'user_denied') {
                        app.logmessage('[' + req.user.id + '] OAUTH ' + podName + ' CANCELLED' );
                        res.redirect(CFG.website_public + '/emitter/oauthcb?status=denied&provider=' + podName);

                    } else {
                        app.logmessage('[' + req.user.id + '] OAUTH ' + podName + ' AUTHORIZED' );
                        // install singletons
                        self.autoInstall(req.user);
                        res.redirect(CFG.website_public + '/emitter/oauthcb?status=accepted&provider=' + podName);
                    }
                })(req, res, function(err) {
                    res.send(500);
                    app.logmessage(err, 'error');
                });
                ok = true;
            } else if (method == 'deauth') {
                this.oAuthUnbind(podName, req.user.id, function(err) {
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
            type : this._authType
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
    _oAuthRegisterStrategy : function(strategy, config, scope) {
        var localConfig = {
            callbackURL : CFG.proto_public + CFG.domain_public + '/rpc/oauth/' + this._name + '/cb',
            failureRedirect : CFG.proto_public + CFG.domain_public + '/rpc/oauth/' + this._name + '/denied',
            passReqToCallback: true
        }, self = this;

        for (key in config) {
            localConfig[key] = config[key];
        }

        this._oAuthScope = scope;
        this._oAuthRegistered = true;
        passport.use(new strategy(
            localConfig,
            function(req, accessToken, refreshToken, profile, done) {
                self.oAuthBinder(req, accessToken, refreshToken, profile, done);
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
    },

    oAuthBinder: function(req, accessToken, refreshToken, profile, done) {
        var self = this;

        // upsert oAuth document
        var filter = {
            owner_id : req.remoteUser.id,
            oauth_provider : this._name
        };

        var struct = {
            owner_id : req.remoteUser.id,
            password : accessToken,
            type : 'oauth',
            oauth_provider : this._name,
            oauth_refresh : refreshToken,
            oauth_profile : profile._json
        };

        var model = this._dao.modelFactory('account_auth', struct);

        // @todo upserts don't work with mongoose middleware
        // create a dao helper for filter -> model upsert.
        this._dao.find('account_auth', filter, function(err, result) {
            var next = done;
            if (err) {
                done( err, req.remoteUser );
            } else {
                self._dao.create(model, function(err, result) {
                    next( err, req.remoteUser );
                });
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
                    next(false, authRecord.getPassword(), authRecord.getOAuthRefresh(), authRecord.getOauthProfile());
                } else {
                    if (err) {
                        app.logmessage(err, 'error');
                    }
                    next(true, err);
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

    // description of the action
    getActionDescription : function(action) {
        if (action) {
            return this._schemas[action].description
        } else {
            return this.repr();
        }
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
    _httpGet: function(url, cb) {
        request(url, function(error, res, body) {
            if (!error && res.headers['content-type'].indexOf('json')) {
                body = JSON.parse(body);
            }
            cb(error, body);
        });
    },

    /**
     * Downloads file from url.  If the file exists, then stats the existing
     * file
     */
    _httpStreamToFile : function(url, outFile, cb, exports, fileStruct) {
        var self = this;
        app.logmessage( this._name + ' writing to [' + outFile + ']');

        fs.exists(outFile, function(exists) {
            if (exists) {
                fs.stat(outFile, function(err, stats) {
                    if (err) {
                        app.logmessage(err, 'error');
                        next(true);
                    } else {
                        app.logmessage( self._name + ' cached, skipping [' + outFile + ']');
                        fileStruct.size = stats.size;
                        cb(false, exports, fileStruct);
                    }
                });
            } else {
                app.logmessage( self._name + ' fetching [' + url + '] > [' + outFile + ']');
                request.get(
                    url,
                    function(exports, fileStruct) {
                        return function(error, res, body) {
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
            }
        });
    },

    // returns the file based data dir for this pod
    getDataDir: function(channel, action) {
        var dDir = DEFS.DATA_DIR + '/channels/';

        if (undefined != channel.owner_id) {
            dDir += channel.owner_id + '/';
        }

        dDir += this._name + '/' + action.name + '/' + channel.id;

        return dDir;
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
        util.inherits(ActionProto, Action);
        var action = new ActionProto(this._config);
            
        action.$resource = this.$resource;
        this.actions[action.name] = action;
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
    setup : function(action, channel, accountInfo, next) {
        if (this.actions[action] && this.actions[action].setup) {
            this.actions[action].setup(channel, accountInfo, next);
        } else {
            next();
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
        this.actions[action](imports, channel, sysImports, contentParts, next);
    },

    /**
     * RPC's are direct calls into a pod, so its up to the pod
     * to properly authenticate data etc.
     */
    rpc : function(action, method, options, req, res, channel) {
        if (undefined != this.rpc[action]) {
            this.rpc[action](method, options, req, res, channel);
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
    trackingStart : function(channel, accountInfo) {
        var trackingStruct = {
            owner_id : channel.owner_id,
            created : app.helper.nowUTCSeconds(),
            last_poll : 0,
            last_update_remote : 0,
            channel_id : channel.id,
            active : true
        }

        model = this._dao.modelFactory('channel_pod_tracking', trackingStruct, accountInfo);

        this._dao.create(model, function(err, result) {
            if (err) {
                console.log(err);
            }
        }, accountInfo);
    },

    /**
     * Updates tracking times for the trigger
     */
    trackingUpdate : function(channel, last_update_remote) {
        var last_poll = app.helper.nowUTCSeconds();

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

    /**
     * Auto installs singletons for the supplied user
     */
    autoInstall : function(accountInfo, next) {
        var dao = this._dao,
            channelTemplate,
            s,
            i = 0,
            keyLen = Object.keys(this._schemas).length, errors = false

        for (key in this._schemas) {
            i++;
            s = this._schemas[key];
            if (s.singleton) {
                channelTemplate = {
                    name : s.description,
                    action : this._name + '.' + key,
                    config : {}, // singletons don't have config
                    note : s.description_long + ' (Automatically Installed)'
                };

                // don't care about catching duplicates right now
                model = dao.modelFactory('channel', channelTemplate, { user : accountInfo } );
                dao.create(model, function(err, result) {
                    if (err) {
                        app.logmessage(err, 'error');
                        errors = true;
                    }

                    if (i === keyLen && next) {
                        // errors are already be logged
                        next(errors, (errors ? 'There were errors' : '') );
                    }

                }, { user : accountInfo });


            }
        }
    },

    describe : function(accountInfo) {
        var self = this,
        schema = {
            'name' : this._name,
            'description' : this._description,
            'description_long' : this._description_long,
            'auth' : {
                type : this._authType,
                status : this._authType  == 'none' ? 'accepted' : 'required'
            },
            'actions' : {}
        };

        // attach auth binders
        if (this._authType == 'oauth') {
            schema.auth._href = this._dao.getBaseUrl() + '/rpc/oauth/' +  this._name + '/auth';
        } else if (this._authType == 'issuer_token') {
            schema.auth._href = this._dao.getBaseUrl() + '/rpc/issuer_token/' +  this._name + '/set?to=';
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
    }
}

module.exports = Pod;