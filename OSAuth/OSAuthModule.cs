// Copyright 2019 Robert Adams
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
//     Unless required by applicable law or agreed to in writing, software
//     distributed under the License is distributed on an "AS IS" BASIS,
//     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//     See the License for the specific language governing permissions and
//     limitations under the License.

using System;
using System.Reflection;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Mono.Addins;

using OpenSim.Framework;
using OpenSim.Region.Framework.Interfaces;
using OpenSim.Region.Framework.Scenes;

using org.herbal3d.cs.CommonEntitiesUtil;

using log4net;
using Nini.Config;

namespace org.herbal3d.OSAuth {

    // Encapsulization of auth to be passed around
    public class OSAuthToken {

        public string ServiceName;
        public string Token;
        public DateTime Expiration;

        public OSAuthToken(string pServiceName) {
            ServiceName = pServiceName;
            Token = Guid.NewGuid().ToString();
            Expiration = DateTime.UtcNow + TimeSpan.FromHours(4.0);
        }

        public string ToJSON() {
            return ToJSON(null);
        }
        public string ToJSON(Dictionary<string,string> pKeysToAdd) {
            StringBuilder buff = new StringBuilder();
            buff.Append(" { ");
            buff.Append("'Name': '" + ServiceName + "'");
            if (pKeysToAdd != null) {
                foreach (var kvp in pKeysToAdd) {
                    buff.Append(", ");
                    buff.Append("'" + kvp.Key + "': '" + kvp.Value + "'");
                }
            }
            buff.Append(", ");
            buff.Append("'Auth': '" + Token + "'");
            buff.Append(", ");
            buff.Append("'AuthExpiration': '" 
                    + ExpirationString()
                    + "'");
            buff.Append(" } ");
            return buff.ToString();
        }

        public string ExpirationString() {
            return Expiration.ToString("yyyy-MM-dd'T'HH:mm:ssK", DateTimeFormatInfo.InvariantInfo);
        }
    }

    [Extension(Path = "/OpenSim/RegionModules", NodeName = "RegionModule", Id = "OSAuth")]
    public class OSAuthModule : INonSharedRegionModule {
        private static readonly ILog _log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly String _logHeader = "[OSAuth]";

        private Scene _scene;

        private bool _enabled = false;
        private IConfig _params;

        private string _regionAuthSecret;

        private Dictionary<string, OSAuthToken> _tokensForServices;

        // IRegionModuleBase.Name
        public string Name { get { return "OSAuthModule"; } }

        // IRegionModuleBase.ReplaceableInterface
        // This module has nothing to do with replaceable interfaces.
        public Type ReplaceableInterface { get { return null; } }

        // IRegionModuleBase.Initialize
        public void Initialise(IConfigSource pConfig) {
            _params = pConfig.Configs["OSAuth"];
            if (_params != null) {
                _enabled = _params.GetBoolean("Enabled", false);
                if (_enabled) {
                    _log.InfoFormat("{0} Enabled", _logHeader);
                }
            }
            _regionAuthSecret = CreateASecret();
            _tokensForServices = new Dictionary<string, OSAuthToken>();
        }
        //
        // IRegionModuleBase.Close
        public void Close() {
        }

        // IRegionModuleBase.AddRegion
        // Called once for the region we're managing.
        public void AddRegion(Scene pScene) {
            // Remember all the loaded scenes
            _scene = pScene;

            // Add to region a handle to this module
            _scene.RegisterModuleInterface<OSAuthModule>(this);
        }

        // IRegionModuleBase.RemoveRegion
        public void RemoveRegion(Scene pScene) {
            if (_scene != null) {
                Close();
                _scene = null;
            }
        }

        // IRegionModuleBase.RegionLoaded
        // Called once for each region loaded after all other regions have been loaded.
        public void RegionLoaded(Scene scene) {
            if (_enabled) {
            }
        }

        // Create an Auth token for the specified service.
        // Throws exception of the service name already has a token
        public OSAuthToken CreateAuthForService(string pServiceName) {
            if (_tokensForServices.ContainsKey(pServiceName)) {
                throw new Exception("Duplicate service name");
            }
            OSAuthToken token = new OSAuthToken(pServiceName);
            _tokensForServices.Add(pServiceName, token);
            return token;
            
        }

        // Get the auth token for the service.
        // Return 'null' if there is no token for this service
        public OSAuthToken GetServiceAuth(string pServiceName) {
            OSAuthToken ret = null;
            _tokensForServices.TryGetValue(pServiceName, out ret);
            return ret;
        }

        // Remove the token for the named service.
        // Returns 'true' if token removed, 'false' if there was no such token.
        public bool RemoveServiceAuth(string pServiceName) {
            bool ret = false;
            if (_tokensForServices.TryGetValue(pServiceName, out OSAuthToken theToken)) {
                ret = true;
                _tokensForServices.Remove(pServiceName);
            }
            return ret;
        }

        // Validate the passed authorization string.
        // The string is presumed to be a JWT string so check the signature and expiration of same.
        public bool Validate(string pAuthString) {
            _log.DebugFormat("{0} Validate: {1}", _logHeader, pAuthString);
            return true;
        }

        public bool Validate(OSAuthToken pToken) {
            return true;
        }

        // Create the secret used for JWT tokens.
        // TODO: Research and make a better secret
        private string CreateASecret() {
            return Guid.NewGuid().ToString();
        }
    }
}
