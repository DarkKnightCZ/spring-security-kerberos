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

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * Implementation of JAAS CallbackHandler to handle Sun's Kerberos username / password requests.
 * Used in {@link SunJaasKerberosClient} and {@link SunJaasKerberosTicketValidator} when not using keytab.
 *
 * @author Mike Wiesner
 * @since 1.0
 */
public class KerberosUserCallbackHandler implements CallbackHandler {
    private String username;
    private String password;

    public KerberosUserCallbackHandler(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback ncb = (NameCallback) callback;
                ncb.setName(username);
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback pwcb = (PasswordCallback) callback;
                pwcb.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callback, "We got a " + callback.getClass().getCanonicalName()
                        + ", but only NameCallback and PasswordCallback is supported");
            }
        }

    }
}