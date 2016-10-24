package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

public class RemoteUIRenameCommand extends RemoteCommand {

    public RemoteUIRenameCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        System.out.println(input);
        String[] items = input.split("&");
        if (items.length != 2) {
            System.out.println("need available input");
            return;
        }
        String adminRealm = adminClient.getAdminConfig().getAdminRealm();
        String oldPrincipalName = items[0];
        String newPrincipalName = items[1] + "@" + adminRealm;

        adminClient.requestRenamePrincipal(oldPrincipalName, newPrincipalName);
    }
}
