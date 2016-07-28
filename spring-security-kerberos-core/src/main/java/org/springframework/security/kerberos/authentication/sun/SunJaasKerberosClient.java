/*
 * Copyright 2009-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kerberos.authentication.sun;

import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.kerberos.authentication.KerberosClient;

/**
 * Implementation of {@link KerberosClient} which uses the SUN JAAS
 * login module, which is included in the SUN JRE, it will not work with an IBM JRE.
 * The whole configuration is done in this class, no additional JAAS configuration
 * is needed.
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class SunJaasKerberosClient implements KerberosClient {

    private boolean debug = false;

    private static final Log LOG = LogFactory.getLog(SunJaasKerberosClient.class);

    @Override
    public String login(String username, String password) {
        LOG.debug("Trying to authenticate " + username + " with Kerberos");
        String validatedUsername;

        try {
            LoginContext loginContext = new LoginContext("", null, new KerberosUserCallbackHandler(username, password),
                    new LoginConfig(this.debug));
            loginContext.login();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Kerberos authenticated user: "+loginContext.getSubject());
            }
            validatedUsername = loginContext.getSubject().getPrincipals().iterator().next().toString();
            loginContext.logout();
        } catch (LoginException e) {
            throw new BadCredentialsException("Kerberos authentication failed", e);
        }
        return validatedUsername;

    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    private static class LoginConfig extends Configuration {
        private boolean debug;

        public LoginConfig(boolean debug) {
            super();
            this.debug = debug;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            HashMap<String, String> options = new HashMap<String, String>();
            options.put("storeKey", "true");
            if (debug) {
                options.put("debug", "true");
            }

            return new AppConfigurationEntry[] { new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options), };
        }
    }
}
