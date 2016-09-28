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
package org.apache.kerby.kerberos.kerb.admin.kadmin.remote.command;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.admin.kadmin.remote.AdminClient;
import java.util.HashMap;

public class RemoteGetPrincipalCommand extends RemoteCommand {
    private static final String USAGE = "Usage: getprinc principalName\n"
            + "such as, getprinc hello@TEST.COM";

    public RemoteGetPrincipalCommand(AdminClient adminClient) {
        super(adminClient);
    }

    @Override
    public void execute(String input) throws KrbException {
        String[] items = input.split("\\s+");

        if (items.length != 2) {
            System.err.println(USAGE);
            return;
        }

        String princName = items[items.length - 1];
        HashMap<String, String> map = adminClient.getPrincipal(princName);

        if (map == null) {
            System.err.println(princName + " doesn't exist\n");
            System.err.println(USAGE);
            return;
        }

        System.out.println(
                "Principal: " + map.get("principalName") + "\n"
                        + "Expiration data: " + map.get("expireTime") + "\n"
                        + "Created time: "
                        + map.get("createTime") + "\n"
                        + "KDC flags: " + map.get("kdcFlags") + "\n"
        );

    }
}
