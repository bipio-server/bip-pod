/**
 *
 * The Bipio Sample Pod.  boilerplate sample action definition
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

function Sample(podConfig) {
    this.name = 'sample';
    this.description = 'short description',
    this.description_long = 'the loooooooooooong description',
    this.trigger = false; // this action can trigger
    this.singleton = false; // only 1 instance per account (can auto install)
    this.auto = false; // no config, not a singleton but can auto-install anyhow
    this.podConfig = podConfig; // general system level config for this pod (transports etc)
}

Sample.prototype = {};

Sample.prototype.getSchema = function() {
    return {
        "imports": {
            "properties" : {
                "instring" : {
                    "type" : String,
                    "description" : "String goes in"
                }
            }
        },
        "exports": {
            "properties" : {
                "outstring" : {
                    "type" : String,
                    "description" : "String goes out"
                }
            }
        }
    }
}

/**
 * Invokes (runs) the action.
 */
Sample.prototype.invoke = function(imports, channel, sysImports, contentParts, next) {
    // whatever comes in, we push straight back out
    next(
        false,
        {
            "outstring" : imports.instring
        }
    );
}

// -----------------------------------------------------------------------------
module.exports = Sample;