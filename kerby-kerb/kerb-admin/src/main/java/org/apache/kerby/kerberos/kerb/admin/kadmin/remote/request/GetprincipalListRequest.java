package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.request;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageCode;
import org.apache.kerby.kerberos.kerb.admin.message.AdminMessageType;
import org.apache.kerby.kerberos.kerb.admin.message.GetprincipalListReq;
import org.apache.kerby.xdr.XdrDataType;
import org.apache.kerby.xdr.XdrFieldInfo;

import java.io.IOException;
import java.nio.ByteBuffer;

public class GetprincipalListRequest extends AdminRequest {
    public GetprincipalListRequest() {
        super(null);
    }

    @Override
    public void process() throws KrbException {
        //encoding and set adminReq
        GetprincipalListReq getprincipalListReq = new GetprincipalListReq();

        XdrFieldInfo[] xdrFieldInfos = new XdrFieldInfo[3];
        xdrFieldInfos[0] = new XdrFieldInfo(0, XdrDataType.ENUM, AdminMessageType.GET_PRINCIPALLIST_REQ);
        xdrFieldInfos[1] = new XdrFieldInfo(1, XdrDataType.INTEGER, 2);
        xdrFieldInfos[2] = new XdrFieldInfo(2, XdrDataType.STRING, "all");

        AdminMessageCode value = new AdminMessageCode(xdrFieldInfos);
        byte[] encodeBytes;
        try {
            encodeBytes = value.encode();
        } catch (IOException e) {
            throw new KrbException("Xdr encode error when generate get principals request.", e);
        }
        ByteBuffer messageBuffer = ByteBuffer.wrap(encodeBytes);
        getprincipalListReq.setMessageBuffer(messageBuffer);

        setAdminReq(getprincipalListReq);
    }
}
