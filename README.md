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
- [Test the sample](#test-the-sample)

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

4. Click Register.

5. Expand OAuth/OpenID connect Configuration under Inbound Authentication Configuration.

6. Enter the following value as the Callback URL: http://localhost.com:8080/pickup-dispatch/oauth2client.

7. Click Add. Note the OAuth Client Key and Client Secret that is displayed. You will need these values later on when deploying the sample application.

8. Click Register to save the changes.

9. Go to the Local and Outbound Authentication Configuration section and select the Advanced configuration radio button option.

      1. Creating the first authentication step:
      
          - Click Add Authentication Step.
       
          - Click Add Authenticator that is under Local Authenticators of Step 1 to add the identity-first handler as the first step.
      
     2. Creating the second authentication step:

         - Click Add Authentication Step.

         - Click Add Authenticator that is under Local Authenticators of Step 2 to add the MagicLink   
         
![](images/service_provider_console.png)

10. Click Update.
 



### Deploy the travelocity sample

Follow the steps below to deploy the travelocity.com sample application:

**Download the samples**

To be able to deploy a sample of Identity Server, you need to download it onto your machine first. 

Follow the instructions below to download a sample from GitHub.

   1. Create a folder in your local machine and navigate to it using your command line.

   2. Run the following commands.
    
    mkdir is-samples
    cd is-samples/
    git init
    git remote add -f origin https://github.com/wso2/product-is.git
    git config core.sparseCheckout true

   3. Navigate into the .git/info/ directory and list out the folders/files you want to check out using the echo 
   command below.  
    
    cd .git
    cd info
    echo "modules/samples/" >> sparse-checkout

   4. Navigate out of .git/info directory and checkout the v5.4.0 tag to update the empty repository with the remote 
   one. 
    
    cd ..
    cd ..
    git checkout -b v5.4.0 v5.4.0
 
   Access the samples by navigating to the  is-samples/modules/samples  directory.

**Deploy the sample web app**

Deploy this sample web app on a web container.

 1. Use the Apache Tomcat server to do this. If you have not downloaded Apache Tomcat already, download it from here. 
 2. Copy the .war file into the  webapps  folder. For example,  <TOMCAT_HOME>/apache-tomcat-<version>/webapps .
 3. Start the Tomcat server.

To check the sample application, navigate to http://<TOMCAT_HOST>:<TOMCAT_PORT>/travelocity.com/index.jsp on your browser.

For example, http://localhost:8080/travelocity.com/index.jsp.

***Note:***
 It is recommended that you use a hostname that is not localhost to avoid browser errors. Modify the 
/etc/hosts entry in your machine to reflect this. Note that localhost is used throughout thisdocumentation as an example, but you must modify this when configuring these authenticators or connectors with this sample application.


### Configure the Identity Provider

Follow the steps below to add an identity provider:

1. Click Add under Main > Identity > Identity Providers.
![](images/image2017-11-17_19-39-44.png)

2. Provide a suitable name for the identity provider.
![](images/image2017-11-17_19-30-35.png)

3. Expand the  EmailOTPAuthenticator Configuration under Federated Authenticators.
   - Select the Enable and Default check boxes.
   - Click Register.
![](images/image2017-11-17_19-31-57.png)

You have now added the identity provider.

### Configure the Service Provider

Follow the steps below add a service provider:

 1. Return to the Management Console home screen.

 2. Click **Add** under **Add** under **Main > Identity > Service Providers**.

 ![](images/image2017-11-17_19-38-59.png)

 3. Enter travelocity.com as the Service Provider Name.
 
 ![](images/image2017-11-17_19-41-38.png)

 4. Click **Register**.

 5. Expand **SAML2 Web SSO Configuration** under **Inbound Authentication Configuration**.

 6. Click **Configure**.
 ![](images/sp.png)

 7. Now set the configuration as follows:
    - **Issuer**: travelocity.com
    - **Assertion Consumer URL**: http://localhost:8080/travelocity.com/home.jsp
    - Select the following check-boxes: **Enable Response Signing**, **Enable Single Logout**, **Enable Attribute Profile**, and 
    **Include Attributes in the Response Always**.

 8. Click **Update** to save the changes. Now you will be sent back to the Service Providers page.

 9. Go to **Claim Configuration** and select the **http://wso2.org/claims/emailaddress** claim.
 ![](images/image2017-11-17_19-51-34.png)

 10. Go to **Local and Outbound Authentication Configuration** section.
     - Select the **Advanced configuration** radio button option.

     - Creating the first authentication step:
       - Click **Add Authentication Step**.
       - Click **Add Authenticator** that is under Local Authenticators of Step 1 to add the basic authentication as the 
       first step.
       
       Adding basic authentication as a first step ensures that the first step of authentication will be done using 
       the user's credentials that are configured with the WSO2 Identity Server

     - Creating the second authentication step:
         - Click Add Authentication Step.
         - Click Add Authenticator that is under Federated Authenticators of Step 2 to add the EmailOTP identity 
          provider you created as the second step.
            EmailOTP is a second step that adds another layer of authentication and security.

![](images/two_steps.png)

 11. Click **Update**.

 You have now added and configured the service provider.

 For more information on service provider configuration, see Configuring Single Sign-On.

### Update the email address of the user

Follow the steps given below to update the user's email address.

 1. Return to the WSO2 Identity Server Management Console home screen.
 2. Click **List** under **Add** under **Main > Identity > Users and Roles**. 
 ![](images/image2017-11-17_20-6-42.png)
     - Click Users. 
     ![](images/image2017-11-17_20-10-37.png)
     - Click User Profile under Admin. 
     ![](images/image2017-11-17_20-11-48.png)
     - Update the email address.    
     ![](images/mail_claim.png)
     - Click Update.


### Configure the user claims

Follow the steps below to map the user claims:

For more information about claims, see  Adding Claim Mapping. 

   1. Click **Add** under **Main > Identity > Claims**.
   ![](images/image2017-11-17_20-14-1.png)
      - Click Add **Local Claim**.
      
      ![](images/image2017-11-17_20-14-54.png)
       
      - Select the **Dialect** from the drop down provided and enter the required information.

      - Add the following:
          - **Claim URI** : http://wso2.org/claims/identity/emailotp_disabled
          - **Display Name**: DisableEmailOTP
          - **Description**: DisableEmailOTP
          - **Mapped Attribute (s)**: title
          - **Supported by Default**: checked
    
![](images/Email-otp-claim.png)
      - Click **Add**. 

 To disable this claim for the admin user, navigate to Users and Roles > List and click Users. Click on the User Profile link corresponding to admin account and then click Disable EmailOTP. This will disable the second factor authentication for the admin user.

### Test the sample

   1. To test the sample, go to the following URL: http://localhost:8080/travelocity.com

![](images/travelocity.jpeg)

   2. Click the link to log in with SAML from WSO2 Identity Server.

   3. The basic authentication page appears. Use your WSO2 Identity Server credentials.
    ![](images/basic.png)

   4.   You receive a token to your email account. Enter the code to authenticate. If the authentication is successful, 
   you are taken to the home page of the travelocity.com app.
   ![](images/code.png)

   ![](images/authenticated_user.png)

### UseCase Definitions.
|Value|Definitions|
|---|---|
|local|This is the default value and is based on the federated username. You must set the federated username in the local userstore . The federated username must be the same as the local username.|
|association|The federated username must be associated with the local account in advance in the end user dashboard. The local username is retrieved from the association. To associate the user, log into the  end user dashboard  and go to  Associated Account  by clicking  **View details** .|
|subjectUri|When configuring the federated authenticator, select the attribute in the subject identifier under the service provider section in UI, this is used as the username of the  EmailOTP authenticator.|
|userAttribute|The name of the  federated authenticator's user attribute. That is the local username that is contained in a federated user's attribute. When using this, add the following parameter under the \<AuthenticatorConfig name="EmailOTP" enabled="true"> section in the \<IS_HOME>/repository/conf/identity/application-authentication.xml file and put the value, <br>e.g., email and screen_name, id.<br>\<Parameter name="userAttribute">email\</Parameter><br><br>If you use OpenID Connect supported authenticators such as LinkedIn and Foursquare or in the case of multiple social login options as the first step and EmailOTP assecondstep, you need to add similar configuration for the specific authenticator in the \<IS_HOME>/repository/conf/identity/application-authentication.xml file under the \<AuthenticatorConfigs> section. <br><br>Examples:<br><br>Fourquare<br>\<AuthenticatorConfig name="Foursquare" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">http://wso2.org/foursquare/claims/email \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">http://wso2.org/foursquare/claims/email \</Parameter><br>\</AuthenticatorConfig><br><br>LinkedIn<br>\<AuthenticatorConfig name="LinkedIn" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">http://wso2.org/linkedin/claims/emailAddress \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">http://wso2.org/linkedin/claims/emailAddress \</Parameter><br>\</AuthenticatorConfig><br><br>Facebook<br>\<AuthenticatorConfig name="FacebookAuthenticator" enabled="true"><br>\<Parameter name="EmailOTP-userAttribute">email \</Parameter><br>\<Parameter name="federatedEmailAttributeKey">email \</Parameter><br>\</AuthenticatorConfig><br><br>Likewise, you can add the Authenticator Config for Amazon, Google, Twitter, and Instagram with the relevant values.|

