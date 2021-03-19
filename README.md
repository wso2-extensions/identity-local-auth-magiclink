# identity-local-auth-magiclink
Magic link authenticator for WSO2 Identity Server
# Configuring Magic Link Authenticator
This section provides the instructions to configure Magic Link Authenticator in WSO2 Identity Server (WSO2 IS). The Magic Link Authentication is a password-less authentication implemented by sending an embedded token via a link in email. 

Let's take a look at the tasks you need to follow to configure Magic Link Authenticator:

- [Enabling configurations on WSO2 IS](#enabling-configurations-on-WSO2-IS)
- [Configure the Service Provider](#configure-the-service-provider)
- [Deploy the sample web application](#deploy-the-sample-web-application)
- [Create a user and update the email address of the user](#create-a-user-and-update-the-email-address-of-the-user)
- [Using HTML Templates in Emails](#Using-HTML-Templates-in-Emails)
 
**Before you begin!**
To ensure you get the full understanding of configuring Magic Link Authenticator with WSO2 IS, the sample pickup-dispatch application is used in this use case. The samples run on the Apache Tomcat server and are written based on Servlet 3.0. Therefore, download Tomcat 8.x from here. Install Apache Maven to build the samples.

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
 	     <Parameter name="Duration">180000</Parameter>
           <Parameter name="Issuer">ServerOrigin</Parameter>
           <Parameter name="Audience">ServerOrigin</Parameter>
        </AuthenticatorConfig>
    
    Hint : Edit the file <IS_HOME>/repository/resources/conf/templates/repository/conf/identity/application-authentication.xml.j2

4. Create the MagicLinkNotification.jsp file by copying the following code https://github.com/thukaraka/MagicLinkAuthenticator/blob/main/MagicLinkNotification.jsp
   and add the file inside the <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint
   
5. Add the following configurations inside <IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/web.xml

            <servlet>
               <servlet-name>MagicLinkNotification.do</servlet-name>
               <jsp-file>/MagicLinkNotification.jsp</jsp-file>
            </servlet>
  
           <servlet-mapping>
               <servlet-name>MagicLinkNotification.do</servlet-name>
               <url-pattern>/MagicLinkNotification.do</url-pattern>
           </servlet-mapping>
    
7.Start WSO2 IS

### Configure the Service Provider

Follow the steps below add a service provider:

1. Return to the Management Console home screen.


2. Click Add under Add under Main > Identity > Service Providers.

   ![](images/service_provider_console.png)

3. Enter pickup-dispatch as the Service Provider Name.

   ![](images/pickup_dispatch_console.png)
  
4. Click Register.

5. Expand OAuth/OpenID connect Configuration under Inbound Authentication Configuration.

6. Enter the following value as the Callback URL: http://localhost.com:8080/pickup-dispatch/oauth2client.

   ![](images/callback_URL.png)

7. Click Add. Note the OAuth Client Key and Client Secret that is displayed. You will need these values later on when deploying the sample application.

8. Click Register to save the changes.

9. Go to the Local and Outbound Authentication Configuration section and select the Advanced configuration radio button option.

      1. Creating the first authentication step:
      
          - Click Add Authentication Step.
       
          - Click Add Authenticator that is under Local Authenticators of Step 1 to add the identity-first handler as the first step.
      
     2. Creating the second authentication step:

         - Click Add Authentication Step.

         - Click Add Authenticator that is under Local Authenticators of Step 2 to add the MagicLink   
         
    ![](images/advance_configuration.png)

10. Click Update.
 
### Deploy the sample web application

1. Use the Apache Tomcat server to do this. If you have not downloaded Apache Tomcat already, [download](https://tomcat.apache.org/download-80.cgi) it from here.

2. Copy the .war file into the webapps folder. For example, <TOMCAT_HOME>/apache-tomcat-/webapps .

3. Download the pickup-dispatch.war file from the latest release assets. Refer this [document](https://is.docs.wso2.com/en/5.9.0/learn/deploying-the-sample-app/#deploying-the-pickup-dispatch-webapp) to add further configurations. 

4. Start the Tomcat server.

Hint: To check the sample application, navigate to http://<TOMCAT_HOST>:<TOMCAT_PORT>/pickup-dispatch/oauth2client on your browser.
For example,  http://localhost.com:8080/pickup-dispatch/oauth2client
Note: It is recommended that you use a hostname that is not localhost to avoid browser errors. Modify the /etc/hosts entry in your machine to reflect this. Note that localhost is used throughout this documentation as an example, but you must modify this when configuring these authenticators or connectors with this sample application.

###  Create a user and update the email address of the user

Follow the steps given below to update the user's email address.

1. Return to the WSO2 Identity Server Management Console home screen.

   ![](images/users_console.png)

2. Click Add

3. Click Add New User. 

   ![](images/add_user_console.png)

4. The Add User page opens. Provide the username and password and click Finish. 

   ![](images/add_user_name.png)

5. Click the User Profile. 

   ![](images/user_profile.png)

6. Click the User Profile and provide First Name and Email. 

   ![](images/user_email.png)

7. Click Update.

### Using HTML Templates in Emails

### Configure the Email Templates
1. Login to the Carbon Console and Goto **Manage > Email Templates > Add** and click on **Add Email Template Type** to add a 
new Email Template type. 

2. Use **magiclink** as the **Template Display Name** and click **Add**.
3. Goto **Manage > Email Templates > Add** and click on **Add Email Template**. 
4. Select the **magiclink** template type from the **Email Template Type** dropdown list and complete the form with 
parameters as follows.

|Parameter Name| Value|
|:---|:---|
|**Template Name**|magiclink|
|**Select the Template Language**|English (United States)|
|**Email Content Type**|text/html|
|**Subject**|WSO2 - Magic Link for Sign In|
|**Email Body**|Refer [Email Template](#email-template)| 
|**Email Footer**|---|

5. Click **Add**.

### Email Template
      <table align="center" cellpadding="0" cellspacing="0" border="0" width="100%"bgcolor="#f0f0f0">
            <tr>
            <td style="padding: 30px 30px 20px 30px;">
                <table cellpadding="0" cellspacing="0" border="0" width="100%" bgcolor="#ffffff" style="max-width: 650px; margin: auto;">
                <tr>
                    <td colspan="2" align="center" style="background-color: #333; padding: 40px;">
                        <a href="http://wso2.com/" target="_blank"><img src="http://cdn.wso2.com/wso2/newsletter/images/nl-2017/wso2-logo-transparent.png" border="0" /></a>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="center" style="padding: 50px 50px 0px 50px;">
                        <h1 style="padding-right: 0em; margin: 0; line-height: 40px; font-weight:300; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 1em;">
                          WSO2 - Magic Link for Sign In   
                        </h1>
                    </td>
                </tr>
                <tr>
                    <td style="text-align: left; padding: 0px 50px 20px 50px;" valign="top">
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 3%;">
                            Hi {{user-name}},
                        </p>
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #666; text-align: left; padding-bottom: 3%;">
                       
                            Please click the button below to confirm your account.
                        </p>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 0px 50px 0px 50px; text-align: left;">
                        <table align="left" cellpadding="0" cellspacing="0" border="0" style="border-radius: 4px; background-color: #ff5000;">
                            <tr>
                                <td style="border-radius: 6px;  padding: 14px 0px;">
                                    <a href="{{carbon.product-url}}/commonauth?mL={{magicToken}}"
                                       target="_blank" style="width: 230px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif;  font-size: 18px; line-height: 21px; font-weight: 600; color: #fff; text-decoration: none; background-color: #ff5000; text-align: center; display: inline-block;cursor: pointer;">Click</a>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
             
                <tr>
                    <td style="text-align: left; padding: 30px 50px 50px 50px;" valign="top">
                        <p style="font-size: 18px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #505050; text-align: left;">
                            Thanks,<br/>WSO2 Identity Server Team
                        </p>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" align="center" style="padding: 20px 40px 40px 40px;" bgcolor="#f0f0f0">
                        <p style="font-size: 12px; margin: 0; line-height: 24px; font-family: 'Nunito Sans', Arial, Verdana, Helvetica, sans-serif; color: #777;">
                            &copy;2021
                            <a href="http://wso2.com/" target="_blank" style="color: #777; text-decoration: none">WSO2</a>
                            <br>
                            787 Castro Street, Mountain View, CA 94041.
                        </p>
                    </td>
                </tr>
                </table>
            </td>
            </tr>
        </table>
                            
                            
                            
                            
                            
                            
                            
                            
                            









 
 
 

