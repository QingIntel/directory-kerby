package org.apache.kerby.kerberos.kerb.admin.webserver;

/**
 * Created by ychen36 on 10/16/2016.
 */

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HelloServlet extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    response.setContentType("text/html");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().println("<h1>Hello Servlet</h1>");
    response.getWriter().println("session=" + request.getSession(true).getId());
  }
}

