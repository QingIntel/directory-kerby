package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

public class RemoteUIAddPrincipalCommand extends RemoteCommand {

    public RemoteUIAddPrincipalCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("&");
        if (items.length != 2) {
            System.out.println("need available input");
            return;
        }
        String adminRealm = adminClient.getAdminConfig().getAdminRealm();
        String clientPrincipal = items[0] + "@" + adminRealm;
        String password = items[1];
        adminClient.requestAddPrincipal(clientPrincipal, password);
    }

}
