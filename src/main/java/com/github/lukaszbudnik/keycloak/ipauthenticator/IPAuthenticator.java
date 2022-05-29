package com.github.lukaszbudnik.keycloak.ipauthenticator;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
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
        String[] allowedIPAddress = getAllowedIPAddress(context);


        if (allowedIPAddress.length != 2) {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            context.success();
            return;
        }

        try {
            if (!checkIPIsInGivenRange(remoteIPAddress, allowedIPAddress[0], allowedIPAddress[1])) {
                logger.infof("IPs do not match. User %s logged in from untrusted ip %s", realm.getName(), user.getUsername(), remoteIPAddress);
                UserCredentialManager credentialManager = session.userCredentialManager();

                if (!credentialManager.isConfiguredFor(realm, user, OTPCredentialModel.TYPE)) {
                    user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
                }

                user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            } else {
                user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
            }
        } catch (AddressStringException e) {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            context.success();
            return;
        }

        context.success();
    }

    public static boolean checkIPIsInGivenRange (String inputIP, String rangeStartIP, String rangeEndIP)
            throws AddressStringException {
        IPAddress startIPAddress = new IPAddressString(rangeStartIP).getAddress();
        IPAddress endIPAddress = new IPAddressString(rangeEndIP).getAddress();
        IPAddressSeqRange ipRange = startIPAddress.toSequentialRange(endIPAddress);
        IPAddress inputIPAddress = new IPAddressString(inputIP).toAddress();

        return ipRange.contains(inputIPAddress);
    }

    private String[] getAllowedIPAddress(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return config.get(IPAuthenticatorFactory.ALLOWED_IP_ADDRESS_CONFIG).split(",");
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
