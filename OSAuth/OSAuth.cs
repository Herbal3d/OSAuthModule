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
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text;

using Newtonsoft;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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
    //
    // Note: one problem with this form of token is that rebuilding might
    //    not create the same token string. That is, taking a token and
    //    disassembling it and then reassembling it might not code  the
    //    same token. This is because JSON syntax is flexible and the
    //    same data can be formatted differently in different JSON renderings.
    //    (See discussions in JWT on creating canonical JSON strings.)
    //    This routine "solves" this problem by no rebuilding the
    //    token string unless the underlying data is changed.
    public class OSAuthToken {

        // Service: usually who created this or service it is for
        public string Srv {
            get { return GetProperty("Srv"); }
            set { AddProperty("Srv", value); _modified = true; }
        }

        // StreamID: the stream the token is associated with
        public string Sid {
            get { return GetProperty("Sid"); }
            set { AddProperty("Sid", value); _modified = true; }
        }

        // Expiration time
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
        private readonly Dictionary<string, string> _authProperties;

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
        private readonly Object _locker = new Object();

        // Authentication/Authorization Token
        // TODO: Make into JWT
        // For the moment, the token is just a 
        public OSAuthToken() {
            _authProperties = new Dictionary<string, string>() {
                { "Srv", "" },
                { "Exp", ExpirationString(DateTime.UtcNow + TimeSpan.FromHours(4.0)) },
                { "Sid", "" },
                { "Secret", Guid.NewGuid().ToString() }
            };
            _modified = true;
            _randomString = null;
        }

        // Build and return a token that is a unique random string
        public static OSAuthToken SimpleToken() {
            return OSAuthToken.FromString(Guid.NewGuid().ToString());
        }

        // Build the token based on the current values
        private void BuildToken() {
            lock (_locker) {
                if (String.IsNullOrEmpty(_randomString)) {
                    // Not a random string. Create token from properties
                    JObject jObj = new JObject();
                    foreach (KeyValuePair<string, string> vals in _authProperties) {
                        if (!String.IsNullOrEmpty(vals.Value)) {
                            jObj.Add(vals.Key, vals.Value);
                        }
                    }
                    _tokenJSON = jObj.ToString(Formatting.None);
                    _token = System.Convert.ToBase64String(Encoding.UTF8.GetBytes(_tokenJSON));
                }
                else {
                    // Token is just a random string.
                    _token = _randomString;
                    _tokenJSON = "{ \"" + _randomString + "\" }";
                }
            }
        }

        // From a Base64 encoded string, extract the values for a token
        //    or, if not a Base64 JSON string, just use the passed string
        public static OSAuthToken FromString(string pTokenString) {
            OSAuthToken token;
            try {
                string jToken =  Encoding.UTF8.GetString(System.Convert.FromBase64String(pTokenString));
                if (jToken.TrimStart().StartsWith("{")) {
                    // The token seems to be JSON so take it apart
                    token = new OSAuthToken() {
                        _token = pTokenString,
                        _tokenJSON = jToken,
                    };
                    JObject jObj = JObject.Parse(jToken);
                    foreach (KeyValuePair<string, JToken> val in jObj) {
                        token.AddProperty(val.Key, (string)val.Value);
                    }
                    token._modified = false;
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
            if (!String.IsNullOrEmpty(pExpStr)) {
                if (DateTime.TryParse(pExpStr, out DateTime ret)) {
                    return ret;
                }
            }
            return new DateTime(2199, 12, 31);
        }

        /*
        // Check that the significant pieces of this token matches the passed token
        public bool Matches(OSAuthToken pOther) {
            return (this.Sid == pOther.Sid) && (this.Secret == pOther.Secret);
        }
        public bool Matches(string pOther) {
            OSAuthToken otherT = OSAuthToken.FromString(pOther);
            return Matches(otherT);
        }
        */
        // Test to see if two OSAuthTokens have the same value
        public override bool Equals(object obj) {
            bool ret = false;
            OSAuthToken other = obj as OSAuthToken;
            if (other != null) {
                ret = this.Token == other.Token;
            }
            return ret;
        }
        // For those that need a hash, the hash of the Token is this one
        public override int GetHashCode() {
            return this.Token.GetHashCode();
        }

        public string Dump() {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Token: " + this.Token);
            sb.AppendLine(", TokenJSON: " + this.TokenJSON);
            sb.AppendLine(", RandomString: " + this._randomString);
            sb.AppendLine(", Modified: " + this._modified);
            sb.AppendLine(", Expiration: " + this.ExpirationString());
            sb.AppendLine(", Properties:");
            foreach (KeyValuePair<string, string> pair in _authProperties) {
                sb.AppendLine("  " + pair.Key + ": " + pair.Value);
            }
            return sb.ToString();
        }
    }
}

