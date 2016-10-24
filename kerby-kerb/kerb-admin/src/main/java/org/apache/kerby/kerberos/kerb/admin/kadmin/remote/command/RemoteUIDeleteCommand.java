package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

public class RemoteUIDeleteCommand extends RemoteCommand {

    public RemoteUIDeleteCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        if (input == null) {
            System.out.println("need available input");
            return;
        }
        adminClient.requestDeletePrincipal(input);
    }
}
