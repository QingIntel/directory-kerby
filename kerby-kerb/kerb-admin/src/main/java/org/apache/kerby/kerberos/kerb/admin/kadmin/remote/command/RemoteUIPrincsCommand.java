package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RemoteUIPrincsCommand extends RemoteCommand {

    private List<Map<String, Object>> principalList = new ArrayList<>();
    public RemoteUIPrincsCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        if (input == null) {
            System.out.println("need available input");
            return;
        }

        List<Map<String, Object>> results = null;
        results = adminClient.requestUIPrincs();
        setPrincipalList(results);
    }

    public List<Map<String, Object>> getPrincipalList() {
        return principalList;
    }

    public void setPrincipalList(List<Map<String, Object>> principalList) {
        this.principalList = principalList;
    }
}
