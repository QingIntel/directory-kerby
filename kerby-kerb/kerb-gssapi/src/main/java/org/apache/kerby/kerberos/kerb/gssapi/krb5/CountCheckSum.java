package org.apache.kerby.kerberos.kerb.gssapi.krb5;

import org.apache.kerby.kerberos.kerb.type.base.CheckSum;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/**
 * It provides computing checksum structure
 */
public class CountCheckSum {

    public static CheckSum getCheckSum (KerbyContext context, TgtTicket tgtTicket, SgtTicket sgtTicket) {
        InitialToken initialToken = new InitialToken();
        try {
            InitialToken.OverloadedChecksum overloadedChecksum =
                    initialToken.new OverloadedChecksum(context, tgtTicket, sgtTicket);
            CheckSum checksum = overloadedChecksum.getChecksum();
            return checksum;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
