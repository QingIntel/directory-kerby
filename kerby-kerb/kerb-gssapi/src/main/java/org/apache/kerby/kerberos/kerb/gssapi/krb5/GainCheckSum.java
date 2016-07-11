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
package org.apache.kerby.kerberos.kerb.gssapi.krb5;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSToken;

import javax.security.auth.kerberos.DelegationPermission;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GainCheckSum {

    public static CheckSum getCheckSum (KerbyContext context, TgtTicket tgtTicket, SgtTicket sgtTicket) {
        byte[] CkSumBytes = null;
        try {
            CkSumBytes = getCkSumBytes(context, tgtTicket, sgtTicket);
        } catch (GSSException e) {
            e.printStackTrace();
        }
        return new CheckSum(CheckSumType.RSA_MD5_DES, CkSumBytes);
    }

    private static byte[] getCkSumBytes (KerbyContext kerbyContext, TgtTicket tgt, SgtTicket sgt) throws GSSException {
        byte[] resultByte = null;
        byte[] kCMessage = null;
        byte pByte = 0;
        int totalSize = 4 + 16 + 4;
        int kerbyFlag = 0;

        if(!tgt.getEncKdcRepPart().getFlags().isFlagSet(TicketFlag.FORWARDABLE)) {
            kerbyContext.setCredDelegState(false);
            kerbyContext.setDelegPolicyState(false);
        } else if(kerbyContext.getCredDelegState()) {
            if(kerbyContext.getDelegPolicyState() && !sgt.getTicket().getEncPart().getFlags().isFlagSet(TicketFlag.OK_AS_DELEGATE)) {
                kerbyContext.setDelegPolicyState(false);
            }
        } else if(kerbyContext.getDelegPolicyState()) {
            if(sgt.getTicket().getEncPart().getFlags().isFlagSet(TicketFlag.OK_AS_DELEGATE)) {
                kerbyContext.setCredDelegState(true);
            } else {
                kerbyContext.setDelegPolicyState(false);
            }
        }

        if(kerbyContext.getCredDelegState()) {
            EncryptionKey key = sgt.getSessionKey();
            EncryptedData data = tgt.getTicket().getEncryptedEncPart();
            try {
                kCMessage = EncryptionHandler.decrypt(data, key, KeyUsage.AS_REP_ENCPART);
            } catch (KrbException e) {
                e.printStackTrace();
            }

            totalSize += 2 + 2 + kCMessage.length;
        }

        resultByte = new byte[totalSize];

        resultByte[pByte++] = (byte)16;
        resultByte[pByte++] = (byte)0;
        resultByte[pByte++] = (byte)0;
        resultByte[pByte++] = (byte)0;

        ChannelBinding localBindings = kerbyContext.getChannelBinding();
        byte[] localBindingsBytes;
        if(localBindings != null) {
            localBindingsBytes = getChBi(kerbyContext.getChannelBinding());
            System.arraycopy(localBindingsBytes, 0, resultByte, pByte, localBindingsBytes.length);
        }

        pByte += 16;
        if(kerbyContext.getCredDelegState()) {
            kerbyFlag |= 1;
        }

        if(kerbyContext.getMutualAuthState()) {
            kerbyFlag |= 2;
        }

        if(kerbyContext.getReplayDetState()) {
            kerbyFlag |= 4;
        }

        if(kerbyContext.getSequenceDetState()) {
            kerbyFlag |= 8;
        }

        if(kerbyContext.getIntegState()) {
            kerbyFlag |= 32;
        }

        if(kerbyContext.getConfState()) {
            kerbyFlag |= 16;
        }

        byte[] temp = new byte[4];
        GSSToken.writeLittleEndian(kerbyFlag, temp);
        resultByte[pByte++] = temp[0];
        resultByte[pByte++] = temp[1];
        resultByte[pByte++] = temp[2];
        resultByte[pByte++] = temp[3];

        if(kerbyContext.getCredDelegState()) {
            PrincipalName prcName = sgt.getTicket().getSname();
            StringBuffer sb = new StringBuffer("\"");
            sb.append(prcName.getName()).append('\"');
            String realm = prcName.getRealm();
            sb.append(" \"krbtgt/").append(realm).append('@');
            sb.append(realm).append('\"');
            SecurityManager securityManager = System.getSecurityManager();
            if(securityManager != null) {
                DelegationPermission delegationPermission = new DelegationPermission(sb.toString());
                securityManager.checkPermission(delegationPermission);
            }

            resultByte[pByte++] = 1;
            resultByte[pByte++] = 0;
            if(kCMessage.length > 0x0000ffff) {
                throw new GSSException(11, -1, "Incorrect message length");
            }

            GSSToken.writeLittleEndian(kCMessage.length, temp);
            resultByte[pByte++] = temp[0];
            resultByte[pByte++] = temp[1];
            System.arraycopy(kCMessage, 0, resultByte, pByte, kCMessage.length);
        }
        return resultByte;
    }

    private static byte[] getChBi(ChannelBinding channelBinding) {
        InetAddress initiatorAddress = channelBinding.getInitiatorAddress();
        InetAddress acceptorAddress = channelBinding.getAcceptorAddress();
        int totalSize = 20;

        int initiatorAddressType = gainAType(initiatorAddress);
        int acceptorAddressType = gainAType(acceptorAddress);

        byte[] initiatorAddressBytes = null;
        if(initiatorAddress != null) {
            try {
                initiatorAddressBytes = gainABytes(initiatorAddress);
            } catch (GSSException e) {
                e.printStackTrace();
            }
            totalSize += initiatorAddressBytes.length;
        }

        byte[] acceptorAddressBytes = null;
        if(acceptorAddress != null) {
            try {
                acceptorAddressBytes = gainABytes(acceptorAddress);
            } catch (GSSException e) {
                e.printStackTrace();
            }
            totalSize += acceptorAddressBytes.length;
        }

        byte[] appDataBytes = channelBinding.getApplicationData();
        if(appDataBytes != null) {
            totalSize += appDataBytes.length;
        }

        byte[] data = new byte[totalSize];
        byte pByte = 0;

        GSSToken.writeLittleEndian(initiatorAddressType, data, pByte);
        pByte += 4;
        if(initiatorAddressBytes != null) {
            GSSToken.writeLittleEndian(initiatorAddressBytes.length, data, pByte);
            pByte += 4;
            System.arraycopy(initiatorAddressBytes, 0, data, pByte, initiatorAddressBytes.length);
            pByte += initiatorAddressBytes.length;
        } else {
            pByte += 4;
        }

        GSSToken.writeLittleEndian(acceptorAddressType, data, pByte);
        pByte += 4;
        if(acceptorAddressBytes != null) {
            GSSToken.writeLittleEndian(acceptorAddressBytes.length, data, pByte);
            pByte += 4;
            System.arraycopy(acceptorAddressBytes, 0, data, pByte, acceptorAddressBytes.length);
            pByte += acceptorAddressBytes.length;
        } else {
            pByte += 4;
        }

        if(appDataBytes != null) {
            GSSToken.writeLittleEndian(appDataBytes.length, data, pByte);
            pByte += 4;
            System.arraycopy(appDataBytes, 0, data, pByte, appDataBytes.length);
        }
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(data);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static int gainAType(InetAddress IAddress) {
        short sb = 255;
        if(IAddress instanceof Inet4Address) {
            sb = 2;
        } else if(IAddress instanceof Inet6Address) {
            sb = 24;
        }
        return sb;
    }

    private static byte[] gainABytes(InetAddress inetAddress) throws GSSException {
        int aType = gainAType(inetAddress);
        byte[] resultByte = inetAddress.getAddress();
        if(resultByte != null) {
            if(aType == 2) {
                if(resultByte.length != 4) {
                    System.out.println("Incorrect AF-INET address length in ChannelBinding.");
                } else {
                    return resultByte;
                }
            } else if(aType == 24) {
                if(resultByte.length != 16) {
                    System.out.println("Incorrect AF-INET6 address length in ChannelBinding.");
                } else {
                    return resultByte;
                }
            } else {
                System.out.println("Cannot handle non AF-INET addresses in ChannelBinding.");
                return null;
            }
        }

        return null;
    }


}
