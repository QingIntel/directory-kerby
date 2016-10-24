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
package org.apache.kerby.kerberos.kerb.admin.webserver;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminConfig;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminUtil;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command.*;
import org.apache.kerby.kerberos.kerb.transport.KrbNetwork;
import org.apache.kerby.kerberos.kerb.transport.TransportPair;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;



/**
 * Command use of remote admin
 */
public class RemoteUIClientTool {
    //private static final Logger LOG = LoggerFactory.getLogger(RemoteAdminClientTool.class);
    //private static final byte[] EMPTY = new byte[0];
    //private static KrbTransport transport;
    private static List<Map<String, Object>> principalList = new ArrayList<>();
    private static String input = null;

    private static void sentCommand(String command) throws Exception {
        AdminClient adminClient;

        if (command == null) {
            System.out.println("need available command");
            System.exit(1);
        }

        String confDirPath = "conf/";
        File confFile = new File(confDirPath, "adminClient.conf");

        final AdminConfig adminConfig = new AdminConfig();
        adminConfig.addKrb5Config(confFile);

        adminClient = new AdminClient(adminConfig);

        String adminRealm = adminConfig.getAdminRealm();

        adminClient.setAdminRealm(adminRealm);
        adminClient.setAllowTcp(true);
        adminClient.setAllowUdp(false);
        adminClient.setAdminTcpPort(adminConfig.getAdminPort());
        adminClient.init();
        System.out.println("admin init successful");


        TransportPair tpair = null;
        try {
            tpair = AdminUtil.getTransportPair(adminClient.getSetting());
        } catch (KrbException e) {
            //LOG.error("Fail to get transport pair. " + e);
            e.printStackTrace();
        }
        KrbNetwork network = new KrbNetwork();
        network.setSocketTimeout(adminClient.getSetting().getTimeout());

        try {
            network.connect(tpair);
        } catch (IOException e) {
            throw new KrbException("Failed to create transport", e);
        }

        /*
        String adminPrincipal = KrbUtil.makeKadminPrincipal(
                adminClient.getSetting().getKdcRealm()).getName();
        Subject subject = null;
        try {
            subject = AuthUtil.loginUsingKeytab(adminPrincipal,
                    new File(adminConfig.getKeyTabFile()));
        } catch (LoginException e) {
            LOG.error("Fail to login using keytab. " + e);
        }
        Subject.doAs(subject, new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                try {

                    Map<String, String> props = new HashMap<String, String>();
                    props.put(Sasl.QOP, "auth-conf");
                    props.put(Sasl.SERVER_AUTH, "true");
                    SaslClient saslClient = null;
                    try {
                        String protocol = adminConfig.getProtocol();
                        String serverName = adminConfig.getServerName();
                        saslClient = Sasl.createSaslClient(new String[]{"GSSAPI"}, null,
                                protocol, serverName, props, null);
                    } catch (SaslException e) {
                        LOG.error("Fail to create sasl client. " + e);
                    }
                    if (saslClient == null) {
                        throw new KrbException("Unable to find client implementation for: GSSAPI");
                    }
                    byte[] response = new byte[0];
                    try {
                        response = saslClient.hasInitialResponse()
                                ? saslClient.evaluateChallenge(EMPTY) : EMPTY;
                    } catch (SaslException e) {
                        LOG.error("Sasl client evaluate challenge failed." + e);
                    }

                    sendMessage(response, saslClient);

                    ByteBuffer message = transport.receiveMessage();

                    while (!saslClient.isComplete()) {
                        int ssComplete = message.getInt();
                        if (ssComplete == 0) {
                            System.out.println("Sasl Server completed");
                        }
                        byte[] arr = new byte[message.remaining()];
                        message.get(arr);
                        byte[] challenge = saslClient.evaluateChallenge(arr);

                        sendMessage(challenge, saslClient);

                        if (!saslClient.isComplete()) {
                            message = transport.receiveMessage();
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return null;
            }
        });
        */

        excute(adminClient, command);
    }

    /*
    private static void sendMessage(byte[] challenge, SaslClient saslClient)
            throws SaslException {

        // 4 is the head to go through network
        ByteBuffer buffer = ByteBuffer.allocate(challenge.length + 8);
        buffer.putInt(challenge.length + 4);
        int scComplete = saslClient.isComplete() ? 0 : 1;

        buffer.putInt(scComplete);
        buffer.put(challenge);
        buffer.flip();

        try {
            transport.sendMessage(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    */

    private static void excute(AdminClient adminClient, String command) throws KrbException {
        //RemoteCommand executor = null;
        System.out.println(command);
        if (command.startsWith("getPrincipalList")) {
            RemoteUIPrincsCommand executor = new RemoteUIPrincsCommand(adminClient);
            executor.execute(command);
            principalList = executor.getPrincipalList();
        } else if (command.startsWith("addPrincipal")) {
            RemoteUIAddPrincipalCommand executor = new RemoteUIAddPrincipalCommand(adminClient);
            executor.execute(input);
        } else if (command.startsWith("renamePrincipal")) {
            RemoteUIRenameCommand executor = new RemoteUIRenameCommand(adminClient);
            executor.execute(input);
        } else if (command.startsWith("deletePrincipal")) {
            RemoteUIDeleteCommand executor = new RemoteUIDeleteCommand(adminClient);
            executor.execute(input);
        } else {
            System.out.println("need available command");
            return;
        }
    }

    public static List<Map<String, Object>> getPrincipalList() {
        try {
            sentCommand("getPrincipalList");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return principalList == null ? null : principalList;
    }

    public static void addPrincipal(String principalName, String password) {
        try {
            RemoteUIClientTool.input = principalName + "&" + password;
            sentCommand("addPrincipal");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void renamePrincipal(String oldPrincipalName, String newPrincipalName) {
        try {
            RemoteUIClientTool.input = oldPrincipalName + "&" + newPrincipalName;
            sentCommand("renamePrincipal");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void deletePrincipal(String principalName) {
        try {
            RemoteUIClientTool.input = principalName;
            sentCommand("deletePrincipal");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
