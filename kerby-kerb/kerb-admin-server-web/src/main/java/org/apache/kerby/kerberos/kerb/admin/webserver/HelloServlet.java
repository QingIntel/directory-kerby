package org.apache.kerby.kerberos.kerb.admin.webserver;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONArray;

public class HelloServlet extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    /*get data from kdc */
    List<Map<String, Object>> dataList = new ArrayList<Map<String, Object>>();
    try {
      dataList = RemoteUIClientTool.getPrincipalList();
    } catch (Exception e) {
      e.printStackTrace();
    }

    JSONArray jsonArray = JSONArray.fromObject(dataList);
    PrintWriter out = response.getWriter();
    out.write(jsonArray.toString());
  }

}

