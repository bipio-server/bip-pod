/**
 *
 * The Bipio Simple Pod.  boilerplate sample action definition
 * ---------------------------------------------------------------
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
 */

function Simple(podConfig) {
  this.name = 'simple';
  this.description = 'short description',
  this.description_long = 'the long description',
  this.trigger = false; // this action can trigger
  this.singleton = false; // only 1 instance per account (can auto install)
  this.auto = false; // no config, not a singleton but can auto-install anyhow
  this.podConfig = podConfig; // general system level config for this pod (transports etc)
}

Simple.prototype = {};

Simple.prototype.getSchema = function() {
  return {
    "config": {
      "properties" : {
        "instring_override" : {
          "type" :  "string",
          "description" : "String goes in"
        }
      }
    },
    "imports": {
      "properties" : {
        "instring" : {
          "type" :  "string",
          "description" : "String goes in"
        }
      }
    },
    "exports": {
      "properties" : {
        "outstring" : {
          "type" : "string",
          "description" : "String goes out"
        }
      }
    },
    'renderers' : {
      'hello' : {
        description : 'Hello World',
        description_long : 'Hello World',
        contentType : DEFS.CONTENTTYPE_XML
      }     
    }
  }
}

Simple.prototype.rpc = function(method, sysImports, options, channel, req, res) {
  if (method === 'hello') {
    res.contentType(this.getSchema().renderers[method].contentType);
    res.send('world');
  } else {
    res.send(404);
  }
}

Simple.prototype.setup = function(channel, accountInfo, next) {
  next(false, 'channel', channel);
}

Simple.prototype.teardown = function(channel, accountInfo, next) {
  next(false, 'channel', channel);
}

Simple.prototype.invoke = function(imports, channel, sysImports, contentParts, next) {
  next(
    false,
    {
      "outstring" : channel.config.instring_override || imports.instring
    }
    );
}

// -----------------------------------------------------------------------------
module.exports = Simple;