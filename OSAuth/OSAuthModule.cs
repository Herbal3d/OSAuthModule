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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using log4net;
using Nini.Config;

namespace org.herbal3d.OSAuth {

    // Encapsulization of auth to be passed around.
    // Create the OSAuthToken from scratch
    //     or serialized from an existing token (OSAuthToken.FromString).
    // A sendable token is fetched with the Token() method.
    //
    // This is envisioned to be a JWT token that can be verified (by signatures)
    //    and to carry information about the user, permissions, etc.
    // For the moment, it is just a Base64 encoded JSON string with that data
    // During this transition period, there are two forms: 1) a JWT'ish type
    //    which is a Base64 encoded JSON string and 2) a random string. The
    //    latter is formatted when _randomString is not NULL or Empty.
    public class OSAuthToken {

        public string Srv {
            get { return GetProperty("Srv"); }
            set { AddProperty("Srv", value); _modified = true; }
        }

        public string Sid {
            get { return GetProperty("Sid"); }
            set { AddProperty("Sid", value); _modified = true; }
        }

        public DateTime Exp {
            get { return ExpirationValue(GetProperty("Exp")); }
            set { AddProperty("Exp", ExpirationString(value)); _modified = true; }
        }

        // A secret that makes this token unique
        private string Secret {
            get { return GetProperty("Secret"); }
            set { AddProperty("Secret", value); _modified = true; }
        }

        // THe token is made up of key/value pairs
        private Dictionary<string, string> _authProperties;

        public void AddProperty(string key, string val) {
            if (_authProperties.ContainsKey(key)) {
                _authProperties[key] = val;
            }
            else {
                _authProperties.Add(key, val);
            }
            _modified = true;
        }
        public bool HasProperty(string key) {
            return _authProperties.ContainsKey(key);
        }
        // Get the value of a property. Returns 'null' if not found.
        public string GetProperty(string key) {
            string ret = null;
            if (_authProperties.ContainsKey(key)) {
                ret = _authProperties[key];
            }
            return ret;
        }

        public void ForEachProperty(Action<KeyValuePair<string, string>> pAction) {
            foreach (KeyValuePair<string, string> pair in _authProperties) {
                pAction(pair);
            }
        }

        private string _token;
        public string Token {
            get {
                lock (_locker) {
                    if (_modified) {
                        BuildToken();
                        _modified = false;
                    }
                    return _token;
                }
            }
            private set { _token = value; _modified = false; }
        }
        // The Token is a Base64 encoding of a JSON string. THis is the underlying JSON
        private string _tokenJSON;
        public string TokenJSON {
            get {
                _ = this.Token;
                return _tokenJSON;
            }
        }

        // Alternate form of the token which is just a random string.
        // If is is null or empty, then token is built from the above info.
        private string _randomString;

        // 'true' if any of the underlying values have changed and Token needs
        //    to be rebuilt.
        private bool _modified = true;

        // Used for locking this to try and keep updating parameters and computed token in sync
        private Object _locker = new Object();

        // Authentication/Authorization Token
        // TODO: Make into JWT
        // For the moment, the token is just a 
        public OSAuthToken() {
            _authProperties = new Dictionary<string, string>() {
                { "Srv", "" },
                { "Exp", ExpirationString(DateTime.UtcNow + TimeSpan.FromHours(4.0)) },
                { "Sid", "" },
                { "Secret", org.herbal3d.cs.CommonEntitiesUtil.Util.RandomString(10) },
            };
            _modified = true;
            _randomString = null;
        }

        // Build the token based on the current values
        private void BuildToken() {
            lock (_locker) {
                if (String.IsNullOrEmpty(_randomString)) {
                    // Not a random string. Create token from properties
                    JObject jObj = new JObject();
                    foreach (KeyValuePair<string, string> vals in _authProperties) {
                        jObj.Add(vals.Key, vals.Value);
                    }
                    _tokenJSON = jObj.ToString();
                    _token = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(_tokenJSON));
                }
                else {
                    // Token is just a random string.
                    _token = _randomString;
                    _tokenJSON = _randomString;
                }
            }
        }

        // From a Base64 encoded string, extract the values for a token
        public static OSAuthToken FromString(string pTokenString) {
            OSAuthToken token = null;
            try {
                string jToken =  Encoding.UTF8.GetString(System.Convert.FromBase64String(pTokenString));
                token = new OSAuthToken();
                if (jToken.TrimStart().StartsWith("{")) {
                    JObject jObj = JObject.Parse(jToken);
                    foreach (KeyValuePair<string, JToken> val in jObj) {
                        token.AddProperty(val.Key, (string)val.Value);
                    }
                }
                else {
                    // The token doesn't look like JSON so assume it's a random string
                    token = new OSAuthToken {
                        _randomString = pTokenString
                    };
                }
            }
            catch {
                // Most likely here because the parsing of the token failed.
                // This means the string was just a token by itself
                token = new OSAuthToken {
                    _randomString = pTokenString
                };
            }
            return token;
        }

        public override string ToString() {
            return this.Token;
        }

        // Routines for the conversion of the expiration time to and from string representation
        public string ExpirationString() {
            return Exp.ToString("yyyy-MM-dd'T'HH:mm:ssK", DateTimeFormatInfo.InvariantInfo);
        }
        public string ExpirationString(DateTime pExp) {
            return pExp.ToString("yyyy-MM-dd'T'HH:mm:ssK", DateTimeFormatInfo.InvariantInfo);
        }
        // Parse the date time from a string. Return 'forever' if not parseable
        public DateTime ExpirationValue(string pExpStr) {
            DateTime ret;
            if (!String.IsNullOrEmpty(pExpStr)) {
                if (DateTime.TryParse(pExpStr, out ret)) {
                    return ret;
                }
            }
            return new DateTime(2199, 12, 31);
        }

        // Check that the significant pieces of this token matches the passed token
        public bool Matches(OSAuthToken pOther) {
            bool ret = false;
            return (this.Sid == pOther.Sid) && (this.Secret == pOther.Secret);
        }
    }

    // OSAuthModule: Center for logic for Herbal3d authorization logic.
    // Provides a central store for OSAuthTokens because expiration has to be managed.
    [Extension(Path = "/OpenSim/RegionModules", NodeName = "RegionModule", Id = "OSAuth")]
    public class OSAuthModule : INonSharedRegionModule {
        private static readonly ILog _log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly String _logHeader = "[OSAuth]";

        private Scene _scene;

        private bool _enabled = false;
        private IConfig _params;

        private string _regionAuthSecret;

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

            // TODO: start timer for scanning and removing expired tokens
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

        // Validate the passed authorization string.
        // The string is presumed to be a JWT string so check the signature and expiration of same.
        public bool Validate(string pAuthString, OSAuthToken pToken) {
            bool ret = false;
            if (pToken == null) {
                // If there is no connection client token yet, verify that the
                //      auth string is a legal JWT
                // TODO:
                ret = true;
            }
            else {
                ret = (pAuthString == pToken.Token);
            }
            _log.DebugFormat("{0} Validate: {1}. Auth={2}", _logHeader, pAuthString, ret);
            return ret;
        }

        public bool Validate(OSAuthToken pToken) {
            _log.DebugFormat("{0} Validate just token. Auth={1}", _logHeader, true);
            return true;
        }

        // Create the secret used for JWT tokens.
        // TODO: Research and make a better secret
        private string CreateASecret() {
            return Guid.NewGuid().ToString();
        }

    }
}
