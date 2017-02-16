![Boilerplate](boilerplate.png) bip-pod-boilerplate
=======

<a href="http://en.wikipedia.org/wiki/Boilerplate_code">boilerplate</a> pod for [bipio](https://bip.io).  

## Installation

From bipio server root directory

    npm install bip-pod-boilerplate
    ./tools/pod-install.js -a boilerplate [-u optional account-wide channel auto install]

The pod-install script is a server script which will register the pod with the bipio server and add sparse
configuration to your NODE_ENV environment config ('default.json', staging or production)
keyed to 'boilerplate', based on the default config in the pod constructor.  It will also move the
pod icon into the server cdn

Manually restart the bipio server at your convenience.

[Bipio Docs](https://bip.io/docs/pods/boilerplate)

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Copyright (c) 2017 InterDigital, Inc. All Rights Reserved
