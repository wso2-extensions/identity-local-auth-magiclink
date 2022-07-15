# identity-local-auth-magiclink
Magic link authenticator for WSO2 Identity Server

Download the source code from [here](https://github.com/wso2-incubator/identity-local-auth-magiclink)

Navigate to the folder you just downloaded, which contains the pom.xml file and build the source code by running the following command on your terminal.

    $ mvn clean install

Copy the org.wso2.carbon.identity.application.authenticator.magiclink-1.0.0.jar file found inside the target folder and paste it in the <IS_HOME>/repository/components/dropins folder.

# Configuring Magic Link Authenticator
This section provides the instructions to configure Magic Link Authenticator in WSO2 Identity Server (WSO2 IS). The Magic Link Authentication is a password-less authentication implemented by sending an embedded token via a link in email. 



### Enabling configurations on WSO2 IS

Follow the steps below to configure WSO2 IS to send email once the Magic Link Authenticator is enabled.

1. Shut down the server if it is running.

2. Add the following properties to the deployment.toml file in the IS_HOME/repository/conf folder to configure the email server.
      
            [output_adapter.email]
            from_address= "wso2iamtest@gmail.com"
            username= "wso2iamtest"
            password= "Wso2@iam70"
            hostname= "smtp.gmail.com"
            port= 587
            enable_start_tls= true
            enable_authentication= true
 
3. Add the following configurations to the <IS_HOME>/repository/conf/identity/application-authentication.xml  file  under the section.

        <AuthenticatorConfig name="MagicLinkAuthenticator" enabled="true">     
           <Parameter name="ExpiryTime">300</Parameter>
        </AuthenticatorConfig>
    
    Hint : Edit the file <IS_HOME>/repository/resources/conf/templates/repository/conf/identity/application-authentication.xml.j2

4. Create the magic_link_notification.jsp file by copying the code in [this](magic_link_notification.md) file 
   and add the file inside the <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint
   
5. Add the following configurations inside <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/web.xml

            <servlet>
               <servlet-name>magic_link_notification.do</servlet-name>
               <jsp-file>/magic_link_notification.jsp</jsp-file>
            </servlet>
  
           <servlet-mapping>
               <servlet-name>magic_link_notification.do</servlet-name>
               <url-pattern>/magic_link_notification.do</url-pattern>
           </servlet-mapping>
    
7.Start WSO2 IS

