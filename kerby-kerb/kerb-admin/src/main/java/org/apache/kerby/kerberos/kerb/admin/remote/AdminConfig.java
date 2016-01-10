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
package org.apache.kerby.kerberos.kerb.admin.remote;

import org.apache.kerby.kerberos.kerb.common.Krb5Conf;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;

import java.util.Arrays;
import java.util.List;

/**
 * Kerb client side configuration API.
 */
public class AdminConfig extends Krb5Conf {
    private static final String LIBDEFAULT = "libdefaults";

    public boolean enableDebug() {
        return getBoolean(AdminConfigKey.KRB_DEBUG, true, LIBDEFAULT);
    }

    /**
     * Get KDC host name
     *
     * @return The kdc host
     */
    public String getKdcHost() {
        return getString(
            AdminConfigKey.KDC_HOST, true, LIBDEFAULT);
    }

    /**
     * Get KDC port, as both TCP and UDP ports
     *
     * @return The kdc host
     */
    public int getKdcPort() {
        Integer kdcPort = getInt(AdminConfigKey.KDC_PORT, true, LIBDEFAULT);
        if (kdcPort != null) {
            return kdcPort.intValue();
        }
        return -1;
    }

    /**
     * Get KDC TCP port
     *
     * @return The kdc tcp port
     */
    public int getKdcTcpPort() {
        Integer kdcPort = getInt(AdminConfigKey.KDC_TCP_PORT, true, LIBDEFAULT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return getKdcPort();
    }

    /**
     * Is to allow UDP for KDC
     *
     * @return true to allow UDP, false otherwise
     */
    public boolean allowUdp() {
        return getBoolean(AdminConfigKey.KDC_ALLOW_UDP, true, LIBDEFAULT)
                || getInt(AdminConfigKey.KDC_UDP_PORT, true, LIBDEFAULT) != null
            || getInt(AdminConfigKey.KDC_PORT, false, LIBDEFAULT) != null;
    }

    /**
     * Is to allow TCP for KDC
     *
     * @return true to allow TCP, false otherwise
     */
    public boolean allowTcp() {
        return getBoolean(AdminConfigKey.KDC_ALLOW_TCP, true, LIBDEFAULT)
                || getInt(AdminConfigKey.KDC_TCP_PORT, true, LIBDEFAULT) != null
            || getInt(AdminConfigKey.KDC_PORT, false, LIBDEFAULT) != null;
    }

    /**
     * Get KDC UDP port
     *
     * @return The kdc udp port
     */
    public int getKdcUdpPort() {
        Integer kdcPort = getInt(AdminConfigKey.KDC_UDP_PORT, true, LIBDEFAULT);
        if (kdcPort != null && kdcPort > 0) {
            return kdcPort.intValue();
        }
        return getKdcPort();
    }

    /**
     * Get KDC realm.
     * @return The kdc realm
     */
    public String getKdcRealm() {
        String realm = getString(AdminConfigKey.KDC_REALM, false, LIBDEFAULT);
        if (realm == null) {
            realm = getString(AdminConfigKey.DEFAULT_REALM, false, LIBDEFAULT);
            if (realm == null) {
                realm = (String) AdminConfigKey.KDC_REALM.getDefaultValue();
            }
        }

        return realm;
    }

    /**
     * Get whether preatuh is required.
     * @return true if preauth required
     */
    public boolean isPreauthRequired() {
        return getBoolean(AdminConfigKey.PREAUTH_REQUIRED, true, LIBDEFAULT);
    }

    /**
     * Get tgs principal.
     * @return The tgs principal
     */
    public String getTgsPrincipal() {
        return getString(AdminConfigKey.TGS_PRINCIPAL, true, LIBDEFAULT);
    }

    /**
     * Get allowable clock skew.
     * @return The allowable clock skew
     */
    public long getAllowableClockSkew() {
        return getLong(AdminConfigKey.CLOCKSKEW, true, LIBDEFAULT);
    }

    /**
     * Get whether empty addresses allowed.
     * @return true if empty address is allowed
     */
    public boolean isEmptyAddressesAllowed() {
        return getBoolean(AdminConfigKey.EMPTY_ADDRESSES_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get whether forward is allowed.
     * @return true if forward is allowed
     */
    public boolean isForwardableAllowed() {
        return getBoolean(AdminConfigKey.FORWARDABLE, true, LIBDEFAULT);
    }

    /**
     * Get whether post dated is allowed.
     * @return true if post dated is allowed
     */
    public boolean isPostdatedAllowed() {
        return getBoolean(AdminConfigKey.POSTDATED_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get whether proxy is allowed.
     * @return true if proxy is allowed
     */
    public boolean isProxiableAllowed() {
        return getBoolean(AdminConfigKey.PROXIABLE, true, LIBDEFAULT);
    }

    /**
     * Get whether renew is allowed.
     * @return true if renew is allowed
     */
    public boolean isRenewableAllowed() {
        return getBoolean(AdminConfigKey.RENEWABLE_ALLOWED, true, LIBDEFAULT);
    }

    /**
     * Get maximum renewable life time.
     * @return The maximum renewable life time
     */
    public long getMaximumRenewableLifetime() {
        return getLong(AdminConfigKey.MAXIMUM_RENEWABLE_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get maximum ticket life time.
     * @return The maximum ticket life time
     */
    public long getMaximumTicketLifetime() {
        return getLong(AdminConfigKey.MAXIMUM_TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get minimum ticket life time.
     * @return The minimum ticket life time
     */
    public long getMinimumTicketLifetime() {
        return getLong(AdminConfigKey.MINIMUM_TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get encryption types.
     * @return encryption type list
     */
    public List<EncryptionType> getEncryptionTypes() {
        return getEncTypes(AdminConfigKey.PERMITTED_ENCTYPES, true, LIBDEFAULT);
    }

    /**
     * Get whether pa encrypt timestamp required.
     * @return true if pa encrypt time required
     */
    public boolean isPaEncTimestampRequired() {
        return getBoolean(AdminConfigKey.PA_ENC_TIMESTAMP_REQUIRED, true, LIBDEFAULT);
    }

    /**
     * Get whether body checksum verified.
     * @return true if body checksum verified
     */
    public boolean isBodyChecksumVerified() {
        return getBoolean(AdminConfigKey.VERIFY_BODY_CHECKSUM, true, LIBDEFAULT);
    }

    /**
     * Get default realm.
     * @return The default realm
     */
    public String getDefaultRealm() {
        return getString(AdminConfigKey.DEFAULT_REALM, true, LIBDEFAULT);
    }

    /**
     * Get whether dns look up kdc.
     * @return true if dnc look up kdc
     */
    public boolean getDnsLookUpKdc() {
        return getBoolean(AdminConfigKey.DNS_LOOKUP_KDC, true, LIBDEFAULT);
    }

    /**
     * Get whether dns look up realm.
     * @return true if dns look up realm
     */
    public boolean getDnsLookUpRealm() {
        return getBoolean(AdminConfigKey.DNS_LOOKUP_REALM, true, LIBDEFAULT);
    }

    /**
     * Get whether allow weak crypto.
     * @return true if allow weak crypto
     */
    public boolean getAllowWeakCrypto() {
        return getBoolean(AdminConfigKey.ALLOW_WEAK_CRYPTO, true, LIBDEFAULT);
    }

    /**
     * Get ticket life time.
     * @return The ticket life time
     */
    public long getTicketLifetime() {
        return getLong(AdminConfigKey.TICKET_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get renew life time.
     * @return The renew life time
     */
    public long getRenewLifetime() {
        return getLong(AdminConfigKey.RENEW_LIFETIME, true, LIBDEFAULT);
    }

    /**
     * Get default tgs encryption types.
     * @return The tgs encryption type list
     */
    public List<EncryptionType> getDefaultTgsEnctypes() {
        return getEncTypes(AdminConfigKey.DEFAULT_TGS_ENCTYPES, true, LIBDEFAULT);
    }

    /**
     * Get default ticket encryption types.
     * @return The encryption type list
     */
    public List<EncryptionType> getDefaultTktEnctypes() {
        return getEncTypes(AdminConfigKey.DEFAULT_TKT_ENCTYPES, true, LIBDEFAULT);
    }

    public List<String> getPkinitAnchors() {
        return Arrays.asList(getStringArray(
                AdminConfigKey.PKINIT_ANCHORS, true, LIBDEFAULT));
    }

    public List<String> getPkinitIdentities() {
        return Arrays.asList(getStringArray(
                AdminConfigKey.PKINIT_IDENTITIES, true, LIBDEFAULT));
    }

    public String getPkinitKdcHostName() {
        return getString(
                AdminConfigKey.PKINIT_KDC_HOSTNAME, true, LIBDEFAULT);
    }
}