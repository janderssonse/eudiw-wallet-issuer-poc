package se.digg.eudiw.auth.config;

import java.io.IOException;
import java.util.Base64;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.web.exchanges.HttpExchange.Principal;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.digg.eudiw.auth.context.EudiwSessionSecurityContextRepository;
import se.digg.eudiw.auth.model.SwedenConnectAuthenticationToken;
import se.swedenconnect.auth.commons.dto.ClientAuthResponse;

public class SwedenconnectAuthenticationReturnFilter extends AbstractAuthenticationProcessingFilter {
     
    Logger logger = LoggerFactory.getLogger(SwedenconnectAuthenticationReturnFilter.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/auth/return/**",
			"POST");

    private AuthenticationManager authenticationManager;
    
    private EudiwSessionSecurityContextRepository contextRepository;


    SwedenconnectAuthenticationReturnFilter(AuthenticationManager authenticationManager, EudiwSessionSecurityContextRepository contextRepository) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
        this.contextRepository = contextRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (HttpMethod.POST.name().equals(((HttpServletRequest)request).getMethod()) && new AntPathRequestMatcher("/auth/return/**").matches((HttpServletRequest)request)) {
            try {         
                String authResponse = request.getParameter("response");
                
                if (authResponse != null) {
                    byte[] decodedJsonBytes = Base64.getDecoder().decode(authResponse);
                    logger.info("AUTH CONTEXT1 " + SecurityContextHolder.getContext());

                    
                    ClientAuthResponse responseData = OBJECT_MAPPER.readValue(decodedJsonBytes, ClientAuthResponse.class);
                    SwedenConnectAuthenticationToken token = new SwedenConnectAuthenticationToken(new Principal("swedenconnnect"), responseData, List.of(new SimpleGrantedAuthority("USER")));
                
                    setDetails(request, token);
                    authenticationManager.authenticate(token);
                    logger.info("AUTH CONTEXT2 " + SecurityContextHolder.getContext());

                    contextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
                    
                    return token;
                }
            }
            catch (Exception e) {
                logger.error("Error in swedenconnect login attempt", e);
            }
        }
        return null;
    }


    protected void setDetails(HttpServletRequest request, SwedenConnectAuthenticationToken authRequest) {
		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
	}

}