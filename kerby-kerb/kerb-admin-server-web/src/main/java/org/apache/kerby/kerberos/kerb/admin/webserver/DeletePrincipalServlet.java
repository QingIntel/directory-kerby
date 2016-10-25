package org.apache.kerby.kerberos.kerb.admin.webserver;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class DeletePrincipalServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String principalName = request.getParameter("principalName");

        RemoteUIClientTool.deletePrincipal(principalName);
    }
}
