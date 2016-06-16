package org.apache.kerby.kerberos.kerb.gssapi.krb5;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TicketFlag;
import org.apache.kerby.kerberos.kerb.type.base.EncryptedData;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.KeyUsage;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.ietf.jgss.ChannelBinding;
import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSToken;
import javax.security.auth.kerberos.DelegationPermission;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class InitialToken {
    private final byte[] CHECKSUM_FIRST_BYTES = new byte[]{(byte)16, (byte)0, (byte)0, (byte)0};

    private static final int CHECKSUM_LENGTH_SIZE     = 4;
    private static final int CHECKSUM_BINDINGS_SIZE   = 16;
    private static final int CHECKSUM_FLAGS_SIZE      = 4;
    private static final int CHECKSUM_DELEG_OPT_SIZE  = 2;
    private static final int CHECKSUM_DELEG_LGTH_SIZE = 2;

    private static final int CHECKSUM_DELEG_FLAG    = 1;
    private static final int CHECKSUM_MUTUAL_FLAG   = 2;
    private static final int CHECKSUM_REPLAY_FLAG   = 4;
    private static final int CHECKSUM_SEQUENCE_FLAG = 8;
    private static final int CHECKSUM_CONF_FLAG     = 16;
    private static final int CHECKSUM_INTEG_FLAG    = 32;

    public InitialToken() {
    }

    public class OverloadedChecksum {
        private static final int CHECKSUM_TYPE = 0x8003;
        private byte[] checksumBytes = null;
        private int flags = 0;

        public OverloadedChecksum(KerbyContext context, TgtTicket tgt, SgtTicket sgt) throws KrbException, IOException, GSSException {
            byte[] krbCredMessage = null;
            byte pos = 0;
            int size = CHECKSUM_LENGTH_SIZE + CHECKSUM_BINDINGS_SIZE +
                    CHECKSUM_FLAGS_SIZE;

            if(!tgt.getEncKdcRepPart().getFlags().isFlagSet(TicketFlag.FORWARDABLE)) {
                context.setCredDelegState(false);
                context.setDelegPolicyState(false);
            } else if(context.getCredDelegState()) {
                if(context.getDelegPolicyState() && !sgt.getTicket().getEncPart().getFlags().isFlagSet(TicketFlag.OK_AS_DELEGATE)) {
                    context.setDelegPolicyState(false);
                }
            } else if(context.getDelegPolicyState()) {
                if(sgt.getTicket().getEncPart().getFlags().isFlagSet(TicketFlag.OK_AS_DELEGATE)) {
                    context.setCredDelegState(true);
                } else {
                    context.setDelegPolicyState(false);
                }
            }

            if(context.getCredDelegState()) {
                EncryptionKey tmpKey = sgt.getSessionKey();
                if (tmpKey == null) {
                    throw new KrbException("Client key isn't availalbe");
                }
                EncryptedData data = tgt.getTicket().getEncryptedEncPart();
                krbCredMessage = EncryptionHandler.decrypt(data, tmpKey, KeyUsage.AS_REP_ENCPART);
                size += CHECKSUM_DELEG_OPT_SIZE + CHECKSUM_DELEG_LGTH_SIZE + krbCredMessage.length;
            }

            this.checksumBytes = new byte[size];

            this.checksumBytes[pos++] = InitialToken.this.CHECKSUM_FIRST_BYTES[0];
            this.checksumBytes[pos++] = InitialToken.this.CHECKSUM_FIRST_BYTES[1];
            this.checksumBytes[pos++] = InitialToken.this.CHECKSUM_FIRST_BYTES[2];
            this.checksumBytes[pos++] = InitialToken.this.CHECKSUM_FIRST_BYTES[3];
            ChannelBinding localBindings = context.getChannelBinding();
            byte[] localBindingsBytes;
            if(localBindings != null) {
                localBindingsBytes = InitialToken.this.computeChannelBinding(context.getChannelBinding());
                System.arraycopy(localBindingsBytes, 0, this.checksumBytes, pos, localBindingsBytes.length);

            }

            pos += CHECKSUM_BINDINGS_SIZE;
            if(context.getCredDelegState()) {
                this.flags |= CHECKSUM_DELEG_FLAG;
            }

            if(context.getMutualAuthState()) {
                this.flags |= CHECKSUM_MUTUAL_FLAG;
            }

            if(context.getReplayDetState()) {
                this.flags |= CHECKSUM_REPLAY_FLAG;
            }

            if(context.getSequenceDetState()) {
                this.flags |= CHECKSUM_SEQUENCE_FLAG;
            }

            if(context.getIntegState()) {
                this.flags |= CHECKSUM_INTEG_FLAG;
            }

            if(context.getConfState()) {
                this.flags |= CHECKSUM_CONF_FLAG;
            }

            byte[] temp = new byte[4];
            GSSToken.writeLittleEndian(this.flags, temp);
            this.checksumBytes[pos++] = temp[0];
            this.checksumBytes[pos++] = temp[1];
            this.checksumBytes[pos++] = temp[2];
            this.checksumBytes[pos++] = temp[3];
            if(context.getCredDelegState()) {
                PrincipalName prcName = sgt.getTicket().getSname();
                StringBuffer var11 = new StringBuffer("\"");
                var11.append(prcName.getName()).append('\"');
                //String var12 = var10.getRealmAsString();
                String realm = prcName.getRealm();
                var11.append(" \"krbtgt/").append(realm).append('@');
                var11.append(realm).append('\"');
                SecurityManager securityManager = System.getSecurityManager();
                if(securityManager != null) {
                    DelegationPermission delegationPermission = new DelegationPermission(var11.toString());
                    securityManager.checkPermission(delegationPermission);
                }

                this.checksumBytes[pos++] = 1;
                this.checksumBytes[pos++] = 0;
                if(krbCredMessage.length > 0x0000ffff) {
                    throw new GSSException(11, -1, "Incorrect message length");
                }

                GSSToken.writeLittleEndian(krbCredMessage.length, temp);
                this.checksumBytes[pos++] = temp[0];
                this.checksumBytes[pos++] = temp[1];
                System.arraycopy(krbCredMessage, 0, this.checksumBytes, pos, krbCredMessage.length);
            }
        }

        public CheckSum getChecksum() throws KrbException {
            return new CheckSum(CHECKSUM_TYPE, this.checksumBytes);
        }

    }

    private byte[] computeChannelBinding(ChannelBinding channelBinding) throws GSSException {
        InetAddress initiatorAddress = channelBinding.getInitiatorAddress();
        InetAddress acceptorAddress = channelBinding.getAcceptorAddress();
        int size = 20;

        int initiatorAddressType = this.getAddrType(initiatorAddress);
        int acceptorAddressType = this.getAddrType(acceptorAddress);

        byte[] initiatorAddressBytes = null;
        if(initiatorAddress != null) {
            initiatorAddressBytes = this.getAddrBytes(initiatorAddress);
            size += initiatorAddressBytes.length;
        }

        byte[] acceptorAddressBytes = null;
        if(acceptorAddress != null) {
            acceptorAddressBytes = this.getAddrBytes(acceptorAddress);
            size += acceptorAddressBytes.length;
        }

        byte[] appDataBytes = channelBinding.getApplicationData();
        if(appDataBytes != null) {
            size += appDataBytes.length;
        }

        byte[] data = new byte[size];
        byte pos = 0;

        GSSToken.writeLittleEndian(initiatorAddressType, data, pos);
        pos += 4;
        if(initiatorAddressBytes != null) {
            GSSToken.writeLittleEndian(initiatorAddressBytes.length, data, pos);
            pos += 4;
            System.arraycopy(initiatorAddressBytes, 0, data, pos, initiatorAddressBytes.length);
            pos += initiatorAddressBytes.length;
        } else {
            pos += 4;
        }

        GSSToken.writeLittleEndian(acceptorAddressType, data, pos);
        pos += 4;
        if(acceptorAddressBytes != null) {
            GSSToken.writeLittleEndian(acceptorAddressBytes.length, data, pos);
            pos += 4;
            System.arraycopy(acceptorAddressBytes, 0, data, pos, acceptorAddressBytes.length);
            pos += acceptorAddressBytes.length;
        } else {
            pos += 4;
        }

        if(appDataBytes != null) {
            GSSToken.writeLittleEndian(appDataBytes.length, data, pos);
            pos += 4;
            System.arraycopy(appDataBytes, 0, data, pos, appDataBytes.length);
            pos += appDataBytes.length;
        } else {
            pos += 4;
        }

        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(data);
        } catch (NoSuchAlgorithmException var13) {
            throw new GSSException(11, -1, "Could not get MD5 Message Digest - " + var13.getMessage());
        }
    }

    private int getAddrType(InetAddress var1) {
        short var2 = 255;
        if(var1 instanceof Inet4Address) {
            var2 = 2;
        } else if(var1 instanceof Inet6Address) {
            var2 = 24;
        }

        return var2;
    }

    private byte[] getAddrBytes(InetAddress inetAddress) throws GSSException {
        int addrType = this.getAddrType(inetAddress);
        byte[] result = inetAddress.getAddress();
        if(result != null) {
            switch(addrType) {
                case 2:
                    if(result.length != 4) {
                        throw new GSSException(11, -1, "Incorrect AF-INET address length in ChannelBinding.");
                    }

                    return result;
                case 24:
                    if(result.length != 16) {
                        throw new GSSException(11, -1, "Incorrect AF-INET6 address length in ChannelBinding.");
                    }

                    return result;
                default:
                    throw new GSSException(11, -1, "Cannot handle non AF-INET addresses in ChannelBinding.");
            }
        } else {
            return null;
        }
    }

}
