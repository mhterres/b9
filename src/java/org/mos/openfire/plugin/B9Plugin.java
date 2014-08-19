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
 *     http://www.apache.org/licenses/LICENSE-2.0
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

    private String serviceName;
    private SessionManager sessionManager;
    private ComponentManager componentManager;
    private PluginManager pluginManager;
    private UserManager userManager;

    /**
     * Constructs a new b9 plugin.
     */
    public B9Plugin() {
        serviceName = JiveGlobals.getProperty("plugin.b9.serviceName", "adminbot");
    }

    // Plugin Interface

    public void initializePlugin(PluginManager manager, File pluginDirectory)
    {

	Log.info("B9 - Starting plugin.");

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
    }

    public void destroyPlugin() {

	Log.info("B9 - Closing plugin.");

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
    }

    public void initialize(JID jid, ComponentManager componentManager) {
    }

    public void start() {
    }

    public void shutdown() {
 	Log.info("B9 - Shutdown thread.");
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


    private void processMessage(Message message, boolean targetSrv,boolean canProceed) 
    {
        if (targetSrv)
        {

            String body = message.getBody();

            MyMessage MyMsg = new MyMessage();
            String text = MyMsg.returnMessage(message);

            String xmppdomain = "@" + JiveGlobals.getProperty("xmpp.domain");
            String to = message.getFrom().toBareJID();

            Message newMessage = new Message();
            newMessage.setTo(to);
            newMessage.setFrom("b9@adminbot."+JiveGlobals.getProperty("xmpp.domain"));
            newMessage.setSubject("Resultado");
            newMessage.setBody(text);

            try
            {
                componentManager.sendPacket(this, newMessage);
            } catch (Exception e)
            {
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


class MyMessage {

  private String msg =  "";
  private int msgTot = 0;

  private GroupManager groupManager = GroupManager.getInstance();
  private UserManager userManager = UserManager.getInstance();
  private SessionManager sessionManager = SessionManager.getInstance();
  private XMPPServer xmppServer = XMPPServer.getInstance();
  private DecimalFormat mbFormat = new DecimalFormat("#0.00");
  private DecimalFormat mbIntFormat = new DecimalFormat("#0");
  private AdminManager adminManager = AdminManager.getInstance();
  private Collection<Group> groups = groupManager.getGroups();
  private Collection<User> users = userManager.getUsers();

  private MultiUserChatManager multiUserChatManager = xmppServer.getMultiUserChatManager();

  private String xmppdomain = JiveGlobals.getProperty("xmpp.domain");
  private IQAuthHandler authHandler = XMPPServer.getInstance().getIQAuthHandler();
  private Boolean anonymousLogin = authHandler.isAnonymousAllowed();


  public static boolean isNumeric(String str)  
  {  
    try  
    {  
      double d = Double.parseDouble(str);  
    }  
    catch(NumberFormatException nfe)  
    {  
      return false;  
    }  
    return true;  
  }

  public String returnMessage(Message messg) {

        String message = messg.getBody();
  	String[] param = message.split(" ");

        String to = messg.getFrom().toBareJID();

	Log.debug("B9 - Verifying if user is admin.");

	if (adminManager.isUserAdmin(messg.getFrom(),false)) {

	  	msg =  "Invalid command: " + message + ". Try again.";

		Log.debug("B9 - Command: " + message + ".");


		if ( message.equals("online users") )  {
       			msg = "";
			msgTot = sessionManager.getUserSessionsCount(true);
		}

		else if ( message.equals("help") ) { 

			msg = ProcessCmd_help();

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

			msg="B9 version 0.1.1";
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

		else if ( message.equals("list conferences") ) {

			if ( multiUserChatManager.getMultiUserChatServicesCount() == 0 ) {

				msg = "There is no conference service enabled.";
			}
			else {

				MultiUserChatService multiUserChatService = multiUserChatManager.getMultiUserChatServices().get(0);

				msg = "List of available conference rooms:";
				
				List<MUCRoom> mucRooms = multiUserChatService.getChatRooms();

				for (MUCRoom mucRoom:  mucRooms) {

					msg += "\r" + mucRoom.getName();
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

					Groups += "\r";
				}

				Groups += group.getName();
			}

			msg = Integer.toString(msgTot) + " groups available in " + xmppdomain + "\r" + Groups;

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

					return "Group " + group + " not found.";
				}
					
				String members = "";

                               	Collection<JID> jids = grp.getMembers();

                                for (JID jid : jids) {

					members += jid.toBareJID() + "\r";
                               	}

				msg = "Group " + group + " member(s):\r";
				msg += members;
			}

			else {

				return "You need to inform group name.";
			}
		}

		else if ( message.startsWith("user info") )  {

			String group = "";

			if (param.length > 2) {

				String user = param[2];

				Boolean userFound = false;
				User usr = new User();

                               	for (User suser : users) {

					msg += suser.getUsername()+".\r";

                                        if ( suser.getUsername().equals(user) ) {
							
						usr = suser;
						userFound = true;
					}
                                }

				if ( !userFound ) {

					return "User " + user + " not found.";
				}
					
				msg = "User " + user + "\r";
				msg += "Name: " + usr.getName() + "\r";
				msg += "Email: " + usr.getEmail() + "\r";
			}
			else {
				return "You need to inform group name.";
			}
		}


		else if ( message.startsWith("c2s") ) {

			if ( param.length > 1 ) {
			
				if ( param[1].equals("compression") ) {

					if ( param.length > 2 ) {

						if ( param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_c2s(message);
						}
					}
					else {

						msg = ProcessCmd_c2s(message);
					}
				}
			}
		}


		else if ( message.startsWith("s2s") ) {

			if ( param.length > 1 ) {

				String s2s_cmd = param[1];

				if ( s2s_cmd.equals("enable") || s2s_cmd.equals("disable") || s2s_cmd.equals("config") ) {

					if ( param.length ==2 ) {

						msg = ProcessCmd_s2s(message);
					}
				}

				if ( s2s_cmd.equals("compression")) {

					if ( param.length ==2 ) {

						msg = ProcessCmd_s2s(message);
					}
					else {

						 if ( param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_s2s(message);
						}
					}
				}

			else if ( s2s_cmd.equals("whitelist") || s2s_cmd.equals("blacklist") ) {

					if ( param.length > 2 ) {

						if ( param[2].equals("add") || param[2].equals("del") || param[2].equals("enable") || param[2].equals("disable") ) {

							msg = ProcessCmd_s2s(message);
						}
					}
					else  {
						msg = ProcessCmd_s2s(message);
					}
						
				}
			}
				
		}


		else if ( message.startsWith("anonymous login") ) 
			{

			if ( param.length == 2 ) {

				if ( anonymousLogin ) {

					return "Anonymous login permitted.";
					}
				else 
				{
					return "Anonymous login forbidden.";
				}
			}
			else 
			{

				String anon_cmd = param[2];

				if ( anon_cmd.equals("enable") || anon_cmd.equals("disable") ) {

					if ( anon_cmd.equals("enable") ) {

                                        	if ( anonymousLogin ) {

							return "Anonymous login already permitted.";
                                                 }
                                                 else {

			        			try {
                                                        	authHandler.setAllowAnonymous(true);
							}
        						catch (Exception e) {
            							Log.error(e.getMessage(), e);
        						}

							return "Anonymous login permitted.";
                                                 }
                                         }
                                         else 
					 {
					 	if ( ! anonymousLogin ) {

                                                	return "Anonymous login already forbidden.";
                                                }
                                                else 
						{
			        			try {
                                                        	authHandler.setAllowAnonymous(false);
							}
        						catch (Exception e) {
            							Log.error(e.getMessage(), e);
        						}

							return "Anonymous login forbidden.";
                                                 }
					}

				}
			}
		}
 

		if ( msg.equals("") ) {
			return Integer.toString(msgTot);
		}
		else
		{
			return msg;
		}
	}
	
	else
		{
		return "JID " + to + " is not an Openfire Administrator.";
		}
  }

  public String ProcessCmd_c2s(String message) {

  	String c2scompression = JiveGlobals.getProperty("xmpp.client.compression.policy");

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

 
  	return "wow";
  }

  public String ProcessCmd_s2s(String message) {

  	String s2sconfig = JiveGlobals.getProperty("xmpp.server.socket.active");
  	String s2slconfig = JiveGlobals.getProperty("xmpp.server.permission");
  	String s2scompression = JiveGlobals.getProperty("xmpp.server.compression.policy");
  	Collection<RemoteServerConfiguration> s2swl = RemoteServerManager.getAllowedServers();
  	Collection<RemoteServerConfiguration> s2sbl = RemoteServerManager.getBlockedServers();

  	String[] param = message.split(" ");

	if ( message.equals("s2s config") ) {

		if ( s2sconfig.equals("true") ) {

			msg = "Server to Server configuration enabled.\r";
				
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

			msg = "Whitelist disabled.\r";
		}
		else {

			msg = "Whitelist enabled.\r";
		}

		msg += "Server(s) in whitelist:";

		if ( param.length == 2 ) {

			for (RemoteServerConfiguration server : s2swl) {

                               	msg += "\r" + server.getDomain()+":"+Integer.toString(server.getRemotePort());
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

			msg = "Blacklist disabled.\r";
		}
		else {
			msg = "Blacklist enabled.\r";
		}

		msg += "Server(s) in blacklist:";

		if ( param.length == 2 ) {

			for (RemoteServerConfiguration server : s2sbl) {

				msg += "\r" + server.getDomain();
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

  	return "";
  }

  public String ProcessCmd_help() {

	msg  = "Available commands:\r";
	msg += "anonymous login\r";
	msg += "anonymous login disable\r";
	msg += "anonymous login enable\r";
	msg += "c2s compression\r";
	msg += "c2s compression disable\r";
	msg += "c2s compression enable\r";
	msg += "free memory\r";
	msg += "group members <group name>\r";
	msg += "help\r";
	msg += "java version\r";
	msg += "list conferences\r";
	msg += "list groups\r";
	msg += "max memory\r";
	msg += "online users\r";
	msg += "openfire version\r";
	msg += "openfire host\r";
	msg += "openfire uptime\r";
	msg += "s2s compression\r";
	msg += "s2s compression disable\r";
	msg += "s2s compression enable\r";
	msg += "s2s config\r";
	msg += "s2s blacklist\r";
	msg += "s2s blacklist add <host>\r";
	msg += "s2s blacklist del <host>\r";
	msg += "s2s blacklist disable\r";
	msg += "s2s blacklist enable\r";
	msg += "s2s enable\r";
	msg += "s2s disable\r";
	msg += "s2s whitelist\r";
	msg += "s2s whitelist add <host> <port>\r";
	msg += "s2s whitelist del <host>\r";
	msg += "s2s whitelist disable\r";
	msg += "s2s whitelist enable\r";
	msg += "server sessions\r";
	msg += "total memory\r";
	msg += "total users\r";
	msg += "used memory\r";
	msg += "user info\r";
	msg += "version\r";

	return msg;
	
  }
}


