/**
 *
 * The Bipio Simple Pod.  boilerplate sample action definition
 * ---------------------------------------------------------------
 *
 *
 * Copyright (c) 2017 InterDigital, Inc. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

function Simple(podConfig) {
  this.podConfig = podConfig; // general system level config for this pod (transports etc)
}

Simple.prototype = {};

// RPC/Renderer accessor - /rpc/render/channel/{channel id}/hello
Simple.prototype.rpc = function(method, sysImports, options, channel, req, res) {
  var self = this;
  if (method === 'echo') {
    res.contentType(self.pod.getActionRPC(self.name, method).contentType);
    res.send(req.query.message);
  } else {
    res.send(404);
  }
}

/**
 * Action Invoker - the primary function of a channel
 *
 * @param Object imports transformed key/value input pairs
 * @param Channel channel invoking channel model
 * @param Object sysImports
 * @param Array contentParts array of File Objects, key/value objects
 * with attributes txId (transaction ID), size (bytes size), localpath (local tmp file path)
 * name (file name), type (content-type), encoding ('binary')
 *
 * @param Function next callback(error, exports, contentParts, transferredBytes)
 *
 */
Simple.prototype.invoke = function(imports, channel, sysImports, contentParts, next) {
  next(
    false,
    {
      "str_out" :  imports.str_in,
      "value_out" : imports.value,
      "in_obj_out" : imports.in_obj,
      "in_arr_out" : imports.in_arr,
      "in_mixed_out" : imports.in_mixed,
      "in_bool_out" : imports.in_bool
    }
  );
}

// -----------------------------------------------------------------------------
module.exports = Simple;