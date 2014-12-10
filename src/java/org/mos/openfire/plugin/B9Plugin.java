/**
* $RCSfile: B9.java,v $
* $Revision: 1 $
* $Date: 2014-08-14 19:25:00 -0300 (Thu, 14 Aug 2014) $
*
* Copyright (C) 2014 Marcelo Hartmann Terres. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package org.mos.openfire.plugin;

import java.net.*;
import java.io.*;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;


import org.dom4j.Element;
import org.jivesoftware.openfire.admin.AdminManager;
import org.jivesoftware.openfire.SessionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.group.Group;
import org.jivesoftware.openfire.group.GroupManager;
import org.jivesoftware.openfire.handler.IQAuthHandler;
import org.jivesoftware.openfire.muc.MUCRoom;
import org.jivesoftware.openfire.muc.MultiUserChatManager;
import org.jivesoftware.openfire.muc.MultiUserChatService;
import org.jivesoftware.openfire.server.RemoteServerConfiguration;
import org.jivesoftware.openfire.server.RemoteServerManager;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.util.ParamUtils;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.PropertyEventDispatcher;
import org.jivesoftware.util.PropertyEventListener;
import org.jivesoftware.util.Log;
import org.slf4j.LoggerFactory;
import org.xmpp.component.Component;
import org.xmpp.component.ComponentException;
import org.xmpp.component.ComponentManager;
import org.xmpp.component.ComponentManagerFactory;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.xmpp.packet.PacketError;
import org.xmpp.packet.Presence;

/**
* B9plugin. It accepts messages and return the requested
* information or you can get and set admin openfire parameters
* The address <tt>b9@[serviceName].[server]</tt> is reserved for 
* receiving the requests.
*
* @author Marcelo Hartmann Terres
*/
public class B9Plugin implements Plugin, Component, PropertyEventListener {

	private static final String B9SOCKETENABLED_PROP = "plugin.b9.socketenabled";
	private static final String B9PORT_PROP = "plugin.b9.port";
	private static final String B9IP_PROP = "plugin.b9.ip";
	private static final String B9PASSWORD_PROP = "plugin.b9.password";

	private String serviceName;
	private SessionManager sessionManager;
	private ComponentManager componentManager;
	private PluginManager pluginManager;
	private UserManager userManager;
	private AdminManager adminManager = AdminManager.getInstance();

        private Socket socket = null;
        private ServerSocket server = null;
        private DataInputStream streamIn =  null;
        private B9D_Server b9d_srv = new B9D_Server();
        public static Thread ofThread;
        public static Boolean NotExit = true;
        public static String b9Port = JiveGlobals.getProperty(B9PORT_PROP, "4456");
        public static String b9IP = JiveGlobals.getProperty(B9IP_PROP, "127.0.0.1");
	public static Boolean b9SocketEnabled = JiveGlobals.getBooleanProperty(B9SOCKETENABLED_PROP, false);

	/**
	* Constructs a new b9 plugin.
	*/
	public B9Plugin() {

		serviceName = JiveGlobals.getProperty("plugin.b9.serviceName", "adminbot");
	}

	// Plugin Interface

	public void initializePlugin(PluginManager manager, File pluginDirectory) {

		Log.info("B9 - Starting plugin.");
		Log.debug("B9 - Starting plugin.");

		pluginManager = manager;
		sessionManager = SessionManager.getInstance();

		userManager = UserManager.getInstance();

		// Register as a component.
		componentManager = ComponentManagerFactory.getComponentManager();

		try {

			componentManager.addComponent(serviceName, this);
		}
		catch (Exception e) {

			Log.error(e.getMessage(), e);
		}

		PropertyEventDispatcher.addListener(this);

		if (b9SocketEnabled) {
                	Log.info("B9 - Starting bind on port " + b9Port + ".");
                	Log.debug("B9 - Starting bind on port " + b9Port + ".");
                	b9d_srv.startServer();
		}
        }


	public void destroyPlugin() {

		Log.info("B9 - Closing plugin.");
		Log.debug("B9 - Closing plugin.");

		PropertyEventDispatcher.removeListener(this);
		
		// Unregister component.
		if (componentManager != null) {

			try {

				componentManager.removeComponent(serviceName);
			}
			catch (Exception e) {

				Log.error(e.getMessage(), e);
			}
		}

		serviceName = JiveGlobals.getProperty("plugin.b9.serviceName", "");
		componentManager = null;
		userManager = null;
		pluginManager = null;
		sessionManager = null;

		Log.info("B9 - Closing plugin.");
		Log.debug("B9 - Closing plugin.");

		if (b9SocketEnabled) {

                	clientConnect();
                	B9Plugin.NotExit=false;
                	B9Plugin.ofThread.stop();
                	Log.info("B9 - Thread closed.");
                	Log.debug("B9 - Thread closed.");
		}
	}

	public void setSocketEnabled(boolean socketenabled) {
		JiveGlobals.setProperty(B9SOCKETENABLED_PROP, socketenabled ? Boolean.toString(true) : Boolean.toString(false));
	}

	public boolean isEnabled() {
		return JiveGlobals.getBooleanProperty(B9SOCKETENABLED_PROP, false);
	}

	public void setPort(String port) {
      		JiveGlobals.setProperty(B9PORT_PROP, port);
	}

	public String getPort() {
		return JiveGlobals.getProperty(B9PORT_PROP, "4456");
	}

	public void setIP(String IP) {
		JiveGlobals.setProperty(B9IP_PROP, IP);
	}

	public String getIP() {
		 return JiveGlobals.getProperty(B9IP_PROP, "127.0.0.1");
	}
	public void setPassword(String Password) {
		JiveGlobals.setProperty(B9PASSWORD_PROP, Password);
	}

	public String getPassword() {
		 return JiveGlobals.getProperty(B9PASSWORD_PROP, "2mQG7foh");
	}


	public void initialize(JID jid, ComponentManager componentManager) {
	}	

	public void start() {
	}

	public void shutdown() {

 		Log.info("B9 - Shutdown thread.");
 		Log.debug("B9 - Shutdown thread.");

                if (b9SocketEnabled) {

                        clientConnect();
                        B9Plugin.NotExit=false;
                        B9Plugin.ofThread.stop();
                        Log.info("B9 - Thread closed.");
                        Log.debug("B9 - Thread closed.");
                }
	}

        public void clientConnect() {

                try {
                        Log.info("B9 - Making local connection.");
                        Log.debug("B9 - Making local connection no port " + b9Port + ".");
                        Socket clientSocket = new Socket(b9IP,Integer.parseInt(b9Port));
                        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());

                        Log.debug("B9 - Send disconnect commando to local server.");
                        outToServer.writeBytes(".\n");
                        clientSocket.close();
                }
                catch (UnknownHostException e) {

                        Log.error(e.getMessage(), e);
                }
                catch (IOException e) {

                        Log.error(e.getMessage(), e);
                }
        }

	// Component Interface

	public String getName() {

		// Get the name from the plugin.xml file.
		return pluginManager.getName(this);
	}

	public String getDescription() {

		// Get the description from the plugin.xml file.
		return pluginManager.getDescription(this);
	}

	public void processPacket(Packet packet) {

		boolean canProceed = false;
		String toNode = packet.getTo().getNode();
		boolean targetSrv = "b9".equals(toNode);

		if (targetSrv) {

			JID address = new JID(packet.getFrom().toBareJID());
			canProceed = true;
		}

		if (packet instanceof Message) {

			// Respond to incoming messages
			Message message = (Message)packet;
			processMessage(message, targetSrv, canProceed);
		}

		else if (packet instanceof Presence) {

			// Respond to presence subscription request or presence probe
			Presence presence = (Presence) packet;
			processPresence(canProceed, presence);
		}

		else if (packet instanceof IQ) {

			// Handle disco packets
			IQ iq = (IQ) packet;
			// Ignore IQs of type ERROR or RESULT

			if (IQ.Type.error == iq.getType() || IQ.Type.result == iq.getType()) {

				return;
			}

			processIQ(iq, targetSrv, canProceed);
		}
	}


	private void processMessage(Message message, boolean targetSrv,boolean canProceed) {

		if (targetSrv)	{

			String to = message.getFrom().toBareJID();
			String body = message.getBody();
			String xmppdomain = "@" + JiveGlobals.getProperty("xmpp.domain");
			String text="";
			Boolean authUse = false;

			Log.debug("B9 - Message received");
			Log.debug("B9 - Original message from: " + to);
			Log.debug("B9 - Original message body: " + body);

			MyMessage_B9 MyMsg = new MyMessage_B9();

                        Log.debug("B9 - Processing message received.");
                        Log.debug("B9 - Verifying user access.");

			if (!adminManager.isUserAdmin(message.getFrom(),false)) {

				Log.debug("B9 - JID " + message.getFrom() + " is not admin.");
				text="JID " + to + " is not an Openfire Administrator.";
			}
			else {
			
				Log.debug("B9 - JID " + message.getFrom() + " is admin.");
				text = MyMsg.returnMessage(body,"XMPP");
			}

			Message newMessage = new Message();
			newMessage.setTo(to);
			newMessage.setFrom("b9@adminbot."+JiveGlobals.getProperty("xmpp.domain"));
			newMessage.setSubject("Resultado");
			newMessage.setBody(text);

			Log.debug("B9 - Return message to: " + to);
			Log.debug("B9 - Return message from: " + "b9@adminbot."+JiveGlobals.getProperty("xmpp.domain"));
			Log.debug("B9 - Return message body: " + text);

			try {

				componentManager.sendPacket(this, newMessage);
			} 
			catch (Exception e) {

				Log.error(e.getMessage(), e);
			}
		}
	}

	private void processPresence(boolean canProceed, Presence presence) {

		try {

			if (Presence.Type.subscribe == presence.getType()) {

				// Accept all presence requests if user has permissions
				// Reply that the subscription request was approved or rejected
				Presence reply = new Presence();
				reply.setTo(presence.getFrom());
				reply.setFrom(presence.getTo());
				reply.setType(canProceed ? Presence.Type.subscribed : Presence.Type.unsubscribed);
				componentManager.sendPacket(this, reply);
			}

			else if (Presence.Type.unsubscribe == presence.getType()) {

				// Send confirmation of unsubscription
				Presence reply = new Presence();
				reply.setTo(presence.getFrom());
				reply.setFrom(presence.getTo());
				reply.setType(Presence.Type.unsubscribed);
				componentManager.sendPacket(this, reply);
			}

			else if (Presence.Type.probe == presence.getType()) {

				// Send that the service is available
				Presence reply = new Presence();
				reply.setTo(presence.getFrom());
				reply.setFrom(presence.getTo());
				componentManager.sendPacket(this, reply);
			}
		}
		catch (ComponentException e) {

			Log.error(e.getMessage(), e);
		}
	}

	private void processIQ(IQ iq, boolean targetSrv,boolean canProceed) {

		IQ reply = IQ.createResultIQ(iq);
		Element childElement = iq.getChildElement();
		String namespace = childElement.getNamespaceURI();
		Element childElementCopy = iq.getChildElement().createCopy();
		reply.setChildElement(childElementCopy);

		if ("http://jabber.org/protocol/disco#info".equals(namespace)) {

			if (iq.getTo().getNode() == null) {

				// Return service identity and features
				Element identity = childElementCopy.addElement("identity");
				identity.addAttribute("category", "component");
				identity.addAttribute("type", "generic");
				identity.addAttribute("name", "B9 service");
				childElementCopy.addElement("feature")
				.addAttribute("var", "http://jabber.org/protocol/disco#info");
				childElementCopy.addElement("feature")
				.addAttribute("var", "http://jabber.org/protocol/disco#items");
			}

			else {

				if (targetSrv) {

					// Return identity and features of the "all" group
					Element identity = childElementCopy.addElement("identity");
					identity.addAttribute("category", "component");
					identity.addAttribute("type", "generic");
					identity.addAttribute("name", "Openfire Administration Bot");
					childElementCopy.addElement("feature")
					.addAttribute("var", "http://jabber.org/protocol/disco#info");
				}
			}
		}

		try {

			componentManager.sendPacket(this, reply);
		}
		catch (Exception e) {

			Log.error(e.getMessage(), e);
		}
	}

	// Other Methods

	/**
	* Returns the service name of this component, which is "b9" by default.
	*
	* @return the service name of this component.
	*/
	public String getServiceName() {

		return serviceName;
	}

	/**
	* Sets the service name of this component, which is "b9" by default.
	*
	* @param serviceName the service name of this component.
	*/
	public void setServiceName(String serviceName) {

		JiveGlobals.setProperty("plugin.b9.serviceName", serviceName);
	}

	// PropertyEventListener Methods

	public void propertySet(String property, Map<String, Object> params) {

		if (property.equals("plugin.b9.serviceName")) {

			changeServiceName((String)params.get("value"));
		}
	}

	public void propertyDeleted(String property, Map<String, Object> params) {

		if (property.equals("plugin.b9.serviceName")) {

			changeServiceName("adminbot");
		}
	}

	public void xmlPropertySet(String property, Map<String, Object> params) {

		// Ignore.
	}

	public void xmlPropertyDeleted(String property, Map<String, Object> params) {

		// Ignore.
	}

	/**
	* Changes the service name to a new value.
	*
	* @param serviceName the service name.
	*/
	private void changeServiceName(String serviceName) {

		if (serviceName == null) {

			throw new NullPointerException("Service name cannot be null");
		}

		if (this.serviceName.equals(serviceName)) {

			return;
		}

		// Re-register the service.
		try {

			componentManager.removeComponent(this.serviceName);
		}
		catch (Exception e) {

			Log.error(e.getMessage(), e);
		}

		try {

			componentManager.addComponent(serviceName, this);
		}
		catch (Exception e) {

			Log.error(e.getMessage(), e);
		}

		this.serviceName = serviceName;
		}
}

class B9D_Server {

        private static final String B9PORT_PROP = "plugin.b9.port";
        private static final String B9IP_PROP = "plugin.b9.ip";

        public static void main(String[] args) {

                Log.info("B9 - Running startServer.");
                Log.debug("B9 - Running startServer.");

                new B9D_Server().startServer();
        }

        public void startServer() {

                Runnable serverTask = new Runnable() {
                @Override
                public void run() {

                        String b9Port = JiveGlobals.getProperty(B9PORT_PROP, "4456");
                        String b9IP = JiveGlobals.getProperty(B9IP_PROP, "127.0.0.1");
			Boolean authUse = false;

                        try {

                                Log.info("B9 - Opening socket in IP " + b9IP + " port " + b9Port + ".");
                                Log.debug("B9 - Opening socket in IP " + b9IP + " port " + b9Port + ".");
                                ServerSocket serverSocket = new ServerSocket(Integer.parseInt(b9Port),1,InetAddress.getByName(b9IP));
                                Log.info("B9 - Waiting for connection.");
                                Log.debug("B9 - Listen on IP " + b9IP + " port " + b9Port  + ".");
                                Log.debug("Waiting for connection.");

                                while (B9Plugin.NotExit) {

                                        Socket clientSocket = serverSocket.accept();
                                        String input="";
                                        String line;

                                        try {

                                                // Get input from the client
                                                DataInputStream in = new DataInputStream (clientSocket.getInputStream());
                                                PrintStream out = new PrintStream(clientSocket.getOutputStream());

                                                input = "";
						String text="";

                                                while((line = in.readLine()) != null && !line.equals(".")) {

                                                        input=input + line;
                                                        MyMessage_B9 MyMsg = new MyMessage_B9();
                                                        Log.debug("B9 - Receive socket message: " + input);

							if (!authUse) {
				
								
								Integer Result = verifyAuth(input);


								switch (Result) {

									case 0:
										text="You are now identified and can send commands";
										authUse=true;
										break;
									case 1:
										text="First you need to identify yourself using commando: login <secret>";
										break;

									case 2:
										text="You need to inform secret";
										break;

									case 3:
										text="Invalid secret";
										break;

								}
							}

							else {
								
                                                        	text = MyMsg.returnMessage(input,"TELNET");
							}

                                                        out.println(text);
                                                        input = "";

                                                        if (!B9Plugin.NotExit) {

                                                                Log.info("B9 - Receive signal to close thread.");
                                                                Log.debug("B9 - Receive signal to close thread.");
                                                                break;
                                                        }
                                                }

                                                clientSocket.close();
                                        } catch (IOException ioe) {

                                                Log.error("B9 - IOException on socket listen: " + ioe);
                                                ioe.printStackTrace();
                                        }

                                }

                                Log.info("B9 - Thread closing.");
                                Log.debug("B9 - Thread closing.");
                        }
                        catch (IOException e) {

                                Log.error("B9 - Unable to process client request");
                                e.printStackTrace();
                        }
                }
        };

        B9Plugin.ofThread = new Thread(serverTask);
        B9Plugin.ofThread.start();
        Log.info("B9 - Thread Created.");
        Log.debug("B9 - Thread Created.");

        }

	public Integer verifyAuth(String message) {

		String[] param = message.split(" ");
        	String b9Password = JiveGlobals.getProperty("plugin.b9.password", "Sd2E9hAvs9LBLcbDVtHsigoP8sAFx6FS");

		Log.debug("B9 - Processing message received.");
		Log.debug("B9 - Verifying user access.");


		if (param[0].equals("login")) {

			if (param.length < 2) {

				//"You need to inform secret"
				return 2;
			}
			else {

				if (param[1].equals(b9Password)) {

					//"You are now identified and can send commands"
					return 0;	
				}
				else {

					//"Invalid secret"
					return 3;
				}
			}
		}

		else {

			//"First you need to identify yourself using commando: login <secret>"
			return 1;
		}
				
	}

}





class MyMessage_B9 {

	private String msg =  "";
	private int msgTot = 0;

	private String conf_roomname = "";
	private String[] conf_members = new String[] {};
	private String conf_listmembers = "";
	private int conf_members_count = 0;

	private MUCRoom conf_room;
	private String inviteErrors = "";

	private GroupManager groupManager = GroupManager.getInstance();
	private UserManager userManager = UserManager.getInstance();
	private SessionManager sessionManager = SessionManager.getInstance();
	private XMPPServer xmppServer = XMPPServer.getInstance();
	private DecimalFormat mbFormat = new DecimalFormat("#0.00");
	private DecimalFormat mbIntFormat = new DecimalFormat("#0");
	private Collection<Group> groups = groupManager.getGroups();
	private Collection<User> users = userManager.getUsers();

	private MultiUserChatManager multiUserChatManager = xmppServer.getMultiUserChatManager();
	private MultiUserChatService multiUserChatService = multiUserChatManager.getMultiUserChatServices().get(0);

	private String xmppdomain = JiveGlobals.getProperty("xmpp.domain");
	private IQAuthHandler authHandler = XMPPServer.getInstance().getIQAuthHandler();
	private Boolean anonymousLogin = authHandler.isAnonymousAllowed();


	public static boolean isNumeric(String str) {  

		try  {  

			double d = Double.parseDouble(str);  
		}  

		catch(NumberFormatException nfe)  {  

			return false;  
		}  

		return true;  
	}

	public String returnMessage(String message,String TypeMessage) {

		String msg = "";
		String[] param = message.split(" ");
		String linebreak="\r\n";

		if (TypeMessage.equals("XMPP")) {

			linebreak="\r";
		}

		Log.debug("B9 - Processing message received.");

  		msg =  "Invalid command: " + message + ". Try again.";

		Log.debug("B9 - Processing command: " + message + ".");

		if ( message.equals("online users") )  {

			msg = "";
			msgTot = sessionManager.getUserSessionsCount(true);
		}

		else if ( message.equals("help") ) { 

			msg = ProcessCmd_help(linebreak);
		}

		else if ( message.equals("server sessions") ) {

			msg= "";
			msgTot = sessionManager.getIncomingServerSessionsCount(true);
		}

		else if ( message.equals("total users") ) {

			msg= "";
			msgTot = 0;

			for (User u : users) {

				msgTot = msgTot + 1;
			}
		}

		else if ( message.equals("version") ) {

			msg="B9 version 0.3";
		}

		else if ( message.equals("openfire version") ) {

			msg="Openfire version: " + xmppServer.getServerInfo().getVersion().getVersionString();
		}

		else if ( message.equals("openfire host") ) {

			msg="Openfire hostname: " + xmppServer.getServerInfo().getHostname();
		}

		else if ( message.equals("openfire uptime") ) {

			msg="Openfire last started: " + xmppServer.getServerInfo().getLastStarted();
		}

		else if ( message.equals("java version") ) {
		
			msg = "Java " + System.getProperty("java.version") + " " +System.getProperty("java.vendor") + " " + System.getProperty("java.vm.name");
		}

		else if ( message.equals("total memory") ) {

			msg = "Total available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().totalMemory())/1024)/1024)) + "MB";
		}

		else if ( message.equals("free memory") ) {

			msg = "Total free available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().freeMemory())/1024)/1024)) + "MB";
		}

		else if ( message.equals("used memory") ) {

			msg = "Total used memory by the JVM: " + mbFormat.format(((((Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()))/1024)/1024)) + "MB";
		}

		else if ( message.equals("max memory") ) {

			msg = "Total maximum available memory to the JVM: " + mbFormat.format((((Runtime.getRuntime().maxMemory())/1024)/1024)) + "MB";
		}


		else if ( message.startsWith("create conference") ) {

			if (param.length > 2) {

				conf_roomname = param[2];

				if (param.length < 4) {

					conf_members_count=0;
				}
				else {

					conf_listmembers=param[3];

					conf_members=conf_listmembers.split(",");
					conf_members_count=conf_members.length;
				}

				MultiUserChatService multiUserChatService = multiUserChatManager.getMultiUserChatServices().get(0);  

		                Log.info("B9 - Creating conference room " + conf_roomname + ".");

				try {

					conf_room=multiUserChatService.getChatRoom(conf_roomname, xmppServer.createJID(conf_roomname, null));
					conf_room.unlock(conf_room.getRole());  
				}
				catch(Exception e) {

					Log.error(e.getMessage(), e);
					msg="Can't create conference room " + conf_roomname + ".";
				}

				try {

					conf_room.unlock(conf_room.getRole());  
				}
				catch(Exception e) {

					Log.error(e.getMessage(), e);
					msg="Can't unlock conference room " + conf_roomname + ".";
				}


				if (conf_members_count > 0) {

					for(String conf_jid : conf_members) {

						String[] conf_member_jid_items=conf_jid.split("@");
	
						JID conf_member_jid=xmppServer.createJID(conf_member_jid_items[0],null);

		                		Log.info("B9 - Sending invitation to " + conf_jid + " to join conference room " + conf_roomname + ".");

						try {

							conf_room.sendInvitation(conf_member_jid, null, conf_room.getRole(), null);  
						}
						catch(Exception e) {

                                               		Log.error(e.getMessage(), e);
						}
					}
				}

				msg="Conference room " + conf_roomname + " created.";

			}
			else {

				msg="You need to inform at least conference room name.";
			}
		}

		else if ( message.startsWith("invite conference") ) {


			if (param.length == 4 ) {

				conf_roomname = param[2];

				conf_listmembers=param[3];

				conf_members=conf_listmembers.split(",");
				conf_members_count=conf_members.length;

				MultiUserChatService multiUserChatService = multiUserChatManager.getMultiUserChatServices().get(0);  

				try {
					conf_room=multiUserChatService.getChatRoom(conf_roomname);
				}
				catch(Exception e) {

					Log.error(e.getMessage(), e);
					msg="Can't access conference room " + conf_roomname + ".";
				}

				if (conf_room == null) {

					msg="Conference room " + conf_roomname + " does not exists.";
				}

				try {
					
					conf_room.unlock(conf_room.getRole());  
				}
				catch(Exception e) {

					Log.error(e.getMessage(), e);
					msg="Can't unlock conference room " + conf_roomname + ".";
				}

				for(String conf_jid : conf_members) {

					String[] conf_member_jid_items=conf_jid.split("@");

					JID conf_member_jid=xmppServer.createJID(conf_member_jid_items[0],null);

	                		Log.info("B9 - Sending invitation to " + conf_jid + " to join conference room " + conf_roomname + ".");
					try {

						conf_room.sendInvitation(conf_member_jid, null, conf_room.getRole(), null);  
					}
                                       	catch(Exception e) {

                                       		Log.error(e.getMessage(), e);

						if (inviteErrors.equals("")) {

							inviteErrors += conf_jid;
						}
						else {

							inviteErrors += ", " + conf_jid;
						}
					}
				}

				if (inviteErrors.equals("")) {

					msg="Invitations sent.";
				}

				msg="Can't send invitation to " + inviteErrors + ".";
			}
			else {

				msg="You need to inform conference room name and JIDs to be invited.";
			}
		}

		else if ( message.equals("list conferences") ) {

			if ( multiUserChatManager.getMultiUserChatServicesCount() == 0 ) {

				msg = "There is no conference service enabled.";
			}

			else {

				MultiUserChatService multiUserChatService = multiUserChatManager.getMultiUserChatServices().get(0);

				msg = "List of available conference rooms:";
				
				List<MUCRoom> mucRooms = multiUserChatService.getChatRooms();

				for (MUCRoom mucRoom:  mucRooms) {

					msg += linebreak + mucRoom.getName();
				}
			}
		}
	
		else if ( message.equals("list groups") ) {

			String Groups = "";
			msg= "";
			msgTot = 0;

  			for (Group group : groups) {

				msgTot = msgTot + 1;

				if ( Groups != "" ) {

					Groups += linebreak;
				}

				Groups += group.getName();
			}

			msg = Integer.toString(msgTot) + " groups available in " + xmppdomain + linebreak + Groups;
		}

		else if ( message.startsWith("group members") ) {

			String group = "";

			if (param.length > 2) {

				if (param.length == 3) {

					group = param[2];
				}

				else {

					for (int i = 0; i < param.length; i++) {

						if (i >1) {

							if ( group != "" ) {

								group += " ";
							}

							group += param[i];
						}
					}
				}	

				Boolean groupFound = false;
				Group grp = new Group();

			   	for (Group sgroup : groups) {
	
					if ( sgroup.getName().equals(group) ) {
							
						grp = sgroup;
						groupFound = true;
					}
				}

				if ( !groupFound ) {

					msg="Group " + group + " not found.";
				}
					
				String members = "";

				Collection<JID> jids = grp.getMembers();

				for (JID jid : jids) {

					members += jid.toBareJID() + linebreak;
				}

				msg = "Group " + group + " member(s):" + linebreak;
				msg += members;
			}

			else {

				msg="You need to inform group name.";
			}
		}

		else if ( message.startsWith("user info") )  {

			String group = "";

			if (param.length > 2) {

				String user = param[2];

				Boolean userFound = false;
				User usr = new User();

			   	for (User suser : users) {

					msg += suser.getUsername()+"." + linebreak;

					if ( suser.getUsername().equals(user) ) {
							
						usr = suser;
						userFound = true;
					}
				}					

				if ( !userFound ) {

					msg="User " + user + " not found.";
				}
					
				msg = "User " + user + linebreak;
				msg += "Name: " + usr.getName() + linebreak;
				msg += "Email: " + usr.getEmail() + linebreak;
			}

			else {

				msg="You need to inform group name.";
			}
		}


		else if ( message.startsWith("c2s") ) {

			if ( param.length > 1 ) {
			
				if ( param[1].equals("compression") ) {

					if ( param.length > 2 ) {

						if ( param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_c2s(message,linebreak);
						}
					}

					else {

						msg = ProcessCmd_c2s(message,linebreak);
					}
				}
			}
		}


		else if ( message.startsWith("s2s") ) {

			if ( param.length > 1 ) {

				String s2s_cmd = param[1];

				if ( s2s_cmd.equals("enable") || s2s_cmd.equals("disable") || s2s_cmd.equals("config") ) {

					if ( param.length ==2 ) {

						msg = ProcessCmd_s2s(message,linebreak);
					}	
				}

				if ( s2s_cmd.equals("compression")) {

					if ( param.length ==2 ) {

						msg = ProcessCmd_s2s(message,linebreak);
					}

					else {

						if ( param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_s2s(message,linebreak);
						}
					}
				}

				else if ( s2s_cmd.equals("whitelist") || s2s_cmd.equals("blacklist") ) {

					if ( param.length > 2 ) {

						if ( param[2].equals("add") || param[2].equals("del") || param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_s2s(message,linebreak);
						}
					}

					else  {

						msg = ProcessCmd_s2s(message,linebreak);
					}
				}
			}
		}


		else if ( message.startsWith("anonymous login") ) {

			if ( param.length == 2 ) {

				if ( anonymousLogin ) {

					msg="Anonymous login permitted.";
				}

				else {

					msg="Anonymous login forbidden.";
				}
			}

			else {

				String anon_cmd = param[2];

				if ( anon_cmd.equals("enable") || anon_cmd.equals("disable") ) {

					if ( anon_cmd.equals("enable") ) {

						if ( anonymousLogin ) {

							msg="Anonymous login already permitted.";
						}

						else {

							try {
	
								authHandler.setAllowAnonymous(true);
							}
							catch (Exception e) {

								Log.error(e.getMessage(), e);
							}

							msg="Anonymous login permitted.";
						}
					}

					else {

				 		if ( ! anonymousLogin ) {

							msg="Anonymous login already forbidden.";
						}

						else {

							try {

								authHandler.setAllowAnonymous(false);
							}
							catch (Exception e) {

								Log.error(e.getMessage(), e);
							}

							msg="Anonymous login forbidden.";
						}
					}
				
				}
			}
		}

		if ( msg.equals("") ) {

			msg=Integer.toString(msgTot);
		}

		return msg;

	}


	public String ProcessCmd_c2s(String message, String linebreak) {

		String c2scompression = JiveGlobals.getProperty("xmpp.client.compression.policy");

		Log.debug("B9 - Process c2s commands.");

		if ( message.equals("c2s compression") ) {

			if ( c2scompression.equals("optional") ) {

				return "c2s compression available.";
			}

			else {

				return "c2s compression disabled.";
			}
		}

		else if ( message.equals("c2s compression enable") ) {

			if ( c2scompression.equals("optional") ) {

				return "Client to Server compression already enabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.client.compression.policy","optional");
				return "Client to Server compression enabled.";
			}
		}

		else if ( message.equals("c2s compression disable") )  {

			if ( c2scompression.equals("disabled") ) {

				return "Client to Server compression already disabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.client.compression.policy","disabled");
				return "Client to Server compression disabled.";
			}
		}


		return "error";
	}

	public String ProcessCmd_s2s(String message, String linebreak) {

		String s2sconfig = JiveGlobals.getProperty("xmpp.server.socket.active");
		String s2slconfig = JiveGlobals.getProperty("xmpp.server.permission");
		String s2scompression = JiveGlobals.getProperty("xmpp.server.compression.policy");
		Collection<RemoteServerConfiguration> s2swl = RemoteServerManager.getAllowedServers();
		Collection<RemoteServerConfiguration> s2sbl = RemoteServerManager.getBlockedServers();

	  	String[] param = message.split(" ");

		Log.debug("B9 - Process s2s commands.");

		if ( message.equals("s2s config") ) {

			if ( s2sconfig.equals("true") ) {

				msg = "Server to Server configuration enabled." + linebreak;
				
				if ( s2slconfig.equals("blacklist") ) {

					msg += "Any server can connect (except those in blacklist).";
				}
			
				else {
					
					msg += " Whitelist enabled.";
				}

				return msg;
			}

			else {

				return "s2s disabled.";
			}
		}

		else if ( message.equals("s2s enable") )  {

			if ( s2sconfig.equals("true") ) {

				return "Server to Server already enabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.server.socket.active","true");
				return "Server to Server enabled.";
			}
		}

		else if ( message.equals("s2s disable") ) {

			if ( s2sconfig.equals("false") ) {

				return "Server to Server already disabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.server.socket.active","false");
				return "Server to Server disabled.";
			}
		}

		else if ( message.equals("s2s compression") ) {

			if ( s2scompression.equals("optional") ) {

				return "s2s compression available.";
			}

			else {

				return "s2s compression disabled.";
			}
		}

		else if ( message.equals("s2s compression enable") ) {

			if ( s2scompression.equals("optional") ) {

				return "Server to Server compression already enabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.server.compression.policy","optional");
				return "Server to Server compression enabled.";
			}
		}

		else if ( message.equals("s2s compression disable") ) {

			if ( s2scompression.equals("disabled") ) {

				return "Server to Server compression already disabled.";
			}

			else {

				JiveGlobals.setProperty("xmpp.server.compression.policy","disabled");
				return "Server to Server compression disabled.";
			}
		}


		else if ( message.startsWith("s2s whitelist") ) {

			if ( s2sconfig.equals("false") ) {

				return "Server to Server disabled.";
			}

			if ( s2slconfig.equals("blacklist") ) {

				msg = "Whitelist disabled." + linebreak;
			}

			else {

				msg = "Whitelist enabled." + linebreak;
			}

			msg += "Server(s) in whitelist:";

			if ( param.length == 2 ) {

				for (RemoteServerConfiguration server : s2swl) {

				   	msg += linebreak + server.getDomain()+":"+Integer.toString(server.getRemotePort());
				}

				return msg;
			}

			else {

				String s2scmd = param[2];
	
				if ( s2scmd.equals("add") || s2scmd.equals("del") || s2scmd.equals("enable") || s2scmd.equals("disable") ) {
		
					if ( s2scmd.equals("enable") || s2scmd.equals("disable") ) {

						if ( s2scmd.equals("enable") ) {

							if ( s2slconfig.equals("whitelist") ) {

								return "Whitelist already enabled.";
							}	

							else {

								RemoteServerManager.setPermissionPolicy("whitelist");
								return "Whitelist enabled.";
							}
						}

						else {

							if ( s2slconfig.equals("blacklist") ) {

								return "Whitelist already disabled.";
							}

							else {

								RemoteServerManager.setPermissionPolicy("blacklist");
								return "Whitelist disabled.";
							}
						}
					}

					else {

						String s2shost = "";
						int s2sport = 5269;

						if ( param.length < 4) {

							return "You need to inform at least server hostname or IP.";
						}

						if ( s2scmd.equals("add") ) {

							if ( param.length  > 4 ) {

								if ( !isNumeric (param[4]) ) {

									return "You need to inform a valid port.";
								}

								if ( Integer.valueOf(param[4]) < 0 || Integer.valueOf(param[4]) > 65535) {

									return "You need to inform a valid port.";
								}
	
								s2sport = Integer.valueOf(param[4]);
							}
		
							s2shost = param[3];

							RemoteServerConfiguration remoteServerConfiguration = new RemoteServerConfiguration(s2shost);
							remoteServerConfiguration.setRemotePort(s2sport);
					
							RemoteServerManager.allowAccess(remoteServerConfiguration);
							return "Server " + s2shost + ":" + s2sport + " added to s2s whitelist.";
						}

						else {

							s2shost = param[3];
							Boolean s2swlin=false;

							for (RemoteServerConfiguration server : s2swl) {

								if ( server.getDomain().equals(s2shost) ) {

									s2swlin=true;
								}
							}

							if ( !s2swlin ) {
						
								return "Server " + s2shost + " is not in whitelist.";
							}

							RemoteServerManager.deleteConfiguration(s2shost);
							return "Server " + s2shost + " removed from s2s whitelist.";
						}
					}

				}

				else {

					return "Command " + s2scmd + " invalid. Try again.";
				}
			}

		}

		else if ( message.startsWith("s2s blacklist") ) {

			if ( s2sconfig.equals("false") ) {

				return "Server to Server disabled.";
			}

			if ( s2slconfig.equals("whitelist") ) {

				msg = "Blacklist disabled." + linebreak;
			}

			else {
				msg = "Blacklist enabled." + linebreak;
			}

			msg += "Server(s) in blacklist:";

			if ( param.length == 2 ) {

				for (RemoteServerConfiguration server : s2sbl) {

					msg += linebreak + server.getDomain();
				}

				return msg;
			}

			else {

				String s2scmd = param[2];

				if ( s2scmd.equals("add") || s2scmd.equals("del") || s2scmd.equals("enable") || s2scmd.equals("disable") ) {

					if ( s2scmd.equals("enable") || s2scmd.equals("disable") ) {

						if ( s2scmd.equals("enable") ) {

							if ( s2slconfig.equals("blacklist") ) {

								return "Blacklist already enabled.";
							}

							else {

								RemoteServerManager.setPermissionPolicy("blacklist");
								return "Blacklist enabled.";
							}
						}

						else {

							if ( s2slconfig.equals("whitelist") ) {

								return "Blacklist already disabled.";
							}

							else {

								RemoteServerManager.setPermissionPolicy("whitelist");
								return "Blacklist disabled.";
							}
						}
					}

					else {
					
						String s2shost = "";

						if ( param.length < 4) {

							return "You need to inform at least server hostname or IP.";
						}

						if ( s2scmd.equals("add") ) {

							s2shost = param[3];

							RemoteServerManager.blockAccess(s2shost);
							return "Server " + s2shost + " added to s2s blacklist.";
						}

						else {

							s2shost = param[3];
							Boolean s2sblin=false;

							for (RemoteServerConfiguration server : s2sbl) {

								if ( server.getDomain().equals(s2shost) ) {

									s2sblin=true;
								}
							}

							if ( !s2sblin ) {
						
								return "Server " + s2shost + " is not in blacklist.";
							}
								
							RemoteServerManager.deleteConfiguration(s2shost);
							return "Server " + s2shost + " removed from s2s blacklist.";
						}
					}
				}

				else {

					return "Command " + s2scmd + " invalid. Try again.";
				}
			}
		}

		return "error";
	}

	public String ProcessCmd_help(String linebreak) {

		Log.debug("B9 - Process help command.");

		msg  = "Available commands:" + linebreak;
		msg += "anonymous login" + linebreak;
		msg += "anonymous login disable" + linebreak;
		msg += "anonymous login enable" + linebreak;
		msg += "c2s compression" + linebreak;
		msg += "c2s compression disable" + linebreak;
		msg += "c2s compression enable" + linebreak;
		msg += "create conference <room name> [members]" + linebreak;
		msg += "invite conference <room name> <members>" + linebreak;
		msg += "free memory" + linebreak;
		msg += "group members <group name>" + linebreak;
		msg += "help" + linebreak;
		msg += "java version" + linebreak;
		msg += "list conferences" + linebreak;
		msg += "list groups" + linebreak;
		msg += "max memory" + linebreak;
		msg += "online users" + linebreak;
		msg += "openfire version" + linebreak;
		msg += "openfire host" + linebreak;
		msg += "openfire uptime" + linebreak;
		msg += "s2s compression" + linebreak;
		msg += "s2s compression disable" + linebreak;
		msg += "s2s compression enable" + linebreak;
		msg += "s2s config" + linebreak;
		msg += "s2s blacklist" + linebreak;
		msg += "s2s blacklist add <host>" + linebreak;
		msg += "s2s blacklist del <host>" + linebreak;
		msg += "s2s blacklist disable" + linebreak;
		msg += "s2s blacklist enable" + linebreak;
		msg += "s2s enable" + linebreak;
		msg += "s2s disable" + linebreak;
		msg += "s2s whitelist" + linebreak;
		msg += "s2s whitelist add <host> <port>" + linebreak;
		msg += "s2s whitelist del <host>" + linebreak;
		msg += "s2s whitelist disable" + linebreak;
		msg += "s2s whitelist enable" + linebreak;
		msg += "server sessions" + linebreak;
		msg += "total memory" + linebreak;
		msg += "total users" + linebreak;
		msg += "used memory" + linebreak;
		msg += "user info" + linebreak;
		msg += "version" + linebreak;

		return msg;
	
	}
}
