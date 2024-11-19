package se.digg.eudiw.auth.config;

import java.text.ParseException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jwt.SignedJWT;

import se.digg.eudiw.auth.model.SwedenConnectAuthenticationToken;
import se.digg.eudiw.auth.model.SwedenConnectPrincipal;
import se.swedenconnect.auth.commons.dto.ClientAuthStatus;
import se.swedenconnect.auth.commons.idtoken.IdTokenClaims;
import se.swedenconnect.auth.commons.response.IdTokenValidationException;
import se.swedenconnect.auth.commons.response.IdTokenValidator;

@Component
public class SwedenConnectAuthenticationProvider implements AuthenticationProvider {
    Logger logger = LoggerFactory.getLogger(SwedenConnectAuthenticationProvider.class);

    @Autowired
    private IdTokenValidator idTokenValidator;

    public SwedenConnectAuthenticationProvider() {
    }

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {

        if (authentication instanceof SwedenConnectAuthenticationToken) {
            SwedenConnectAuthenticationToken a = (SwedenConnectAuthenticationToken) authentication;

            if (!ClientAuthStatus.OK.equals(a.getCredentials().getStatus())) {
                AuthenticationException authException = new BadCredentialsException("Authentication failed");
                logger.trace("Authentication failed with status: {}", a.getCredentials().getStatus(), authException);
                // TODO decide AuthenticationException type based on status
                throw authException;
            }
            try {
                SignedJWT signedJWT = idTokenValidator.validateIdToken(a.getCredentials().getIdToken());
                IdTokenClaims idTokenClaims = null;
                if (signedJWT != null) {
                    try {
                        idTokenClaims = idTokenValidator.getIdTokenClaims(signedJWT);

                        SwedenConnectAuthenticationToken token = new SwedenConnectAuthenticationToken(new SwedenConnectPrincipal(idTokenClaims.getSubjectAttributes()), a.getCredentials(), List.of(new SimpleGrantedAuthority("USER")) );
                        token.setDetails(
                            a.getDetails()
                        );

                        SecurityContext context = SecurityContextHolder.createEmptyContext(); 
                        context.setAuthentication(token);

                        SecurityContextHolder.setContext(context);
                        return token;
                    } catch (JsonProcessingException | ParseException e) { 
                        logger.error("Could not parse swedenconnect jwt", e);
                        // TODO should throw AuthenticationException?
                        return null;
                    } 
                }
            } catch (IdTokenValidationException e) {
                logger.error("swedenconnect jwt validation failed", e);
                // TODO should throw AuthenticationException?
                return null;
            }
        }
        logger.trace("No swedenconnect authentication is returned", authentication.getName());
        return null;

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(SwedenConnectAuthenticationToken.class);
    }
}
