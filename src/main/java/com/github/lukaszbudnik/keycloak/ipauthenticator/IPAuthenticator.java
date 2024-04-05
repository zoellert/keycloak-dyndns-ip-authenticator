package com.github.lukaszbudnik.keycloak.ipauthenticator;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;

public class IPAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IPAuthenticator.class);
    private static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        String remoteIPAddress = context.getConnection().getRemoteAddr();
        String[] hostNames = getAllowedDynDnsHostnames(context);


        if (hostNames.length < 1) {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            logger.warn("Dyndns hostnames missing in configuration. Please configure plugin.");
            context.success();
            return;
        }

        try {
            for (String hostnameToCheck : getAllowedDynDnsHostnames(context)) {
                if (checkIPIsMatchingDynDnsName(remoteIPAddress, hostnameToCheck)) {
                    user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
                    logger.infof("Remote ip %s matched with one of the given dyndns hostnames!", remoteIPAddress);
                    context.success();
                    return;
                }
            }

            logger.infof("DnyDns resolved ips do not match remote user ip. User %s logged in from untrusted ip %s", user.getUsername(), remoteIPAddress);
            SubjectCredentialManager credentialManager = user.credentialManager();

            if (!credentialManager.isConfiguredFor(OTPCredentialModel.TYPE)) {
                user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            }

            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
        } catch (UnknownHostException e) {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            context.success();
            return;
        }

        context.success();
    }

    public static boolean checkIPIsMatchingDynDnsName (String inputIP, String dynDnsHostname)
            throws UnknownHostException {
        InetAddress dynDnsAddress = InetAddress.getByName(dynDnsHostname);
        String ipAddress = dynDnsAddress.getHostAddress();

        return ipAddress.equals(inputIP);
    }

    private String[] getAllowedDynDnsHostnames(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return config.get(IPAuthenticatorFactory.ALLOWED_DYNDNS_HOSTNAMES_CONFIG).split(",");
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
