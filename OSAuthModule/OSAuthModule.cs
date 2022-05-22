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

using OpenSim.Region.Framework.Interfaces;
using OpenSim.Region.Framework.Scenes;

using log4net;
using Nini.Config;

namespace org.herbal3d.OSAuth {
    //
    // OSAuthModule: Center for logic for Herbal3d authorization logic.
    // Provides a central store for OSAuthTokens because expiration has to be managed.
    [Extension(Path = "/OpenSim/RegionModules", NodeName = "RegionModule", Id = "OSAuth")]
    public class OSAuthModule : INonSharedRegionModule {
        private static readonly ILog _log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly String _logHeader = "[OSAuth]";

        private Scene _scene;

        private bool _enabled = false;
        private IConfig _params;


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
    }
}
