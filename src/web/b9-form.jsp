<%@ page
   import="org.jivesoftware.openfire.XMPPServer,
           org.mos.openfire.plugin.B9Plugin,
           org.jivesoftware.util.ParamUtils,
           java.util.*,
           java.util.regex.*,
	   java.net.*"
   errorPage="error.jsp"%>

<%@ taglib uri="http://java.sun.com/jstl/core_rt" prefix="c"%>
<%@ taglib uri="http://java.sun.com/jstl/fmt_rt" prefix="fmt"%>

<%
	boolean save = request.getParameter("save") != null;	

	boolean b9SocketEnabled = ParamUtils.getBooleanParameter(request, "b9SocketEnabled", false);
	String b9Port = ParamUtils.getParameter(request, "b9Port");
	String b9IP = ParamUtils.getParameter(request, "b9IP");
	String b9Password = ParamUtils.getParameter(request, "b9Password");

	String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
    
	B9Plugin plugin = (B9Plugin) XMPPServer.getInstance().getPluginManager().getPlugin("b9");

	Map<String, String> errors = new HashMap<String, String>();	

	if (save) {
	  if (b9Port == null || b9Port.equals("0")) {

	     b9Port="4456";
	  }
	  else {
	  	try {
			
			int nPort=Integer.parseInt(b9Port);
		}
		catch (Exception e) {

			b9Port="4456";
		}
	  }
       
	  if (b9IP == null || b9IP.trim().length() < 1) {
	     b9IP="127.0.0.1";
	  }

	  if (b9SocketEnabled) {

          	if (b9Password == null || b9Password.trim().length() < 1) {
		
			errors.put("missingB9Password", "missingB9Password");
		}
	  }
	
	  String validIPs = "Valid IPs: ";
	  Boolean ipFound = false;

	  Enumeration e = NetworkInterface.getNetworkInterfaces();
  	  while(e.hasMoreElements()) {

		NetworkInterface n = (NetworkInterface) e.nextElement();
		Enumeration ee = n.getInetAddresses();
		while (ee.hasMoreElements()) {

			InetAddress i = (InetAddress) ee.nextElement();

			Pattern VALID_IPV4_PATTERN=Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
			Matcher ipv4=VALID_IPV4_PATTERN.matcher(i.getHostAddress());

			if (ipv4.matches()) {

				String localIP=i.getHostAddress();
				validIPs+=localIP+" ";

				if (localIP.equals(b9IP)) {

					ipFound=true;
				}
			}
		}
	  }

	  request.setAttribute("VALIDIPS", validIPs); 

	  if (!ipFound) {

		if (!b9IP.equals("0.0.0.0")) {

                        errors.put("invalidIP", "invalidIP");
                }

	  }

	  if (errors.size() == 0) {
	     plugin.setSocketEnabled(b9SocketEnabled);
	     plugin.setPort(b9Port);
	     plugin.setIP(b9IP);
	     plugin.setPassword(b9Password);
           
	     response.sendRedirect("b9-form.jsp?settingsSaved=true");
	     return;
	  }		
	}
    
	b9SocketEnabled = plugin.isEnabled();
	b9Port = plugin.getPort();
	b9IP = plugin.getIP();
	b9Password = plugin.getPassword();
%>

<html>
	<head>
	  <title><fmt:message key="b9.title" /></title>
	  <meta name="pageID" content="b9-form"/>
	</head>
	<body>

<form action="b9-form.jsp?save" method="post">

<div class="jive-contentBoxHeader"><fmt:message key="b9.options" /></div>
<div class="jive-contentBox">
   
	<% if (ParamUtils.getBooleanParameter(request, "settingsSaved")) { %>
   
	<div class="jive-success">
	<table cellpadding="0" cellspacing="0" border="0">
	<tbody>
	  <tr>
	     <td class="jive-icon"><img src="images/success-16x16.gif" width="16" height="16" border="0"></td>
	     <td class="jive-icon-label"><fmt:message key="b9.saved.success" /></td>
	  </tr>
	</tbody>
	</table>
	</div>
   
	<% } %>
  
        <table cellpadding="3" cellspacing="0" border="0" width="100%">
        <tbody>
          <tr>
             <td width="1%" align="center" nowrap><input type="checkbox" name="b9SocketEnabled" <%=b9SocketEnabled ? "checked" : "" %>></td>
             <td width="99%" align="left"><fmt:message key="b9.socketenabled" /></td>
          </tr>
        </tbody>
        </table>
 
   <br><br>
	<p><fmt:message key="b9.directions" /></p>
   
	<table cellpadding="3" cellspacing="0" border="0" width="100%">
	<tbody>
	  <tr>
	     <td width="5%" valign="top"><fmt:message key="b9.port" />:&nbsp;</td>
	     <td width="95%"><input type="text" name="b9Port" value="<%= b9Port %>"></td>
	  </tr>
	  <tr>
	     <td width="5%" valign="top"><fmt:message key="b9.IP" />:&nbsp;</td>
	     <td width="95%"><input type="text" name="b9IP" value="<%= b9IP %>"></td>
             <% if (errors.containsKey("invalidIP")) { %>
                <span class="jive-error-text"><fmt:message key="b9.message.ipinvalid" /><br>
                <%= request.getAttribute("VALIDIPS") %></span>
             <% } %>
	  </tr>
	  <tr>
	     <td width="5%" valign="top"><fmt:message key="b9.Password" />:&nbsp;</td>
	     <td width="95%"><input type="text" name="b9Password" value="<%= b9Password %>"></td>
             <% if (errors.containsKey("missingB9Password")) { %>
                <span class="jive-error-text"><fmt:message key="b9.message.missingpassword" /><br></span>
             <% } %>
	  </tr>
	
	</tbody>
	</table>
</div>
<input type="submit" value="<fmt:message key="b9.button.save" />"/>
</form>

</body>
</html>
