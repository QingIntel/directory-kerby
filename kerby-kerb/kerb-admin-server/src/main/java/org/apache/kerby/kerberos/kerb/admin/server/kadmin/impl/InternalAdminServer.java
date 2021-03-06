/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *
 */
package org.apache.kerby.kerberos.kerb.admin.server.kadmin.impl;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.server.kadmin.AdminServerSetting;
import org.apache.kerby.kerberos.kerb.identity.backend.IdentityBackend;

/**
 * An internal KDC admin interface.
 */
public interface InternalAdminServer {

    /**
     * Initialize.
     * @throws KrbException e
     */
    void init() throws KrbException;

    /**
     * Start the KDC admin.
     * @throws KrbException e
     */
    void start() throws KrbException;

    /**
     * Stop the KDC admin.
     * @throws KrbException e
     */
    void stop() throws KrbException;

    /**
     * Get admin admin setting.
     * @return setting
     */
    AdminServerSetting getSetting();

    /**
     * Get identity backend.
     * @return IdentityBackend
     */
    IdentityBackend getIdentityBackend();
}
