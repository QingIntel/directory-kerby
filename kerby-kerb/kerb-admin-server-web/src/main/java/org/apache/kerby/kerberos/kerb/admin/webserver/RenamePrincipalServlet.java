package org.apache.kerby.kerberos.kerb.admin.webserver;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RenamePrincipalServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String oldPrincipalName = request.getParameter("oldPrincipalName");
        String newPrincipalName = request.getParameter("newPrincipalName");

        RemoteUIClientTool.renamePrincipal(oldPrincipalName, newPrincipalName);
    }
}
