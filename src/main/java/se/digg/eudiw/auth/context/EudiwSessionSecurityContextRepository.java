package se.digg.eudiw.auth.context;

import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.security.core.context.SecurityContext;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class EudiwSessionSecurityContextRepository extends HttpSessionSecurityContextRepository{
    Logger logger = LoggerFactory.getLogger(EudiwSessionSecurityContextRepository.class);

    // TODO serialize/deserialize context och spara i redis
    Map<String, SecurityContext> pendingContexts = new HashMap<String, SecurityContext>();

    public EudiwSessionSecurityContextRepository() {
        super();
    }

   	@Override
	public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        SecurityContext ctx = readSecurityContextFromPath(request);
        if (ctx != null) {
            return new PathDeferredSecurityContext(ctx);
        }
        return super.loadDeferredContext(request);
    }

    private SecurityContext readSecurityContextFromPath(HttpServletRequest request) {
        String reqUri = request.getRequestURI();
        logger.trace("reqUri: {}", reqUri);
        if (reqUri != null && reqUri.startsWith("/auth/return/")) {
            String[] tokenizer = reqUri.split("/");
            if (tokenizer.length == 4) {
                String authenticationId = tokenizer[3];
                SecurityContext context = pendingContexts.get(authenticationId);
                if (context != null) {
                    pendingContexts.remove(authenticationId);
                    logger.trace("Found security context for path: {}", reqUri);
        
                    return context;
                }
            }
        }
        logger.trace("Did not find security context in path: {}", reqUri);
        return null;
    }

    public void addPendingContext(String authenticationId, SecurityContext context) {
        pendingContexts.put(authenticationId, context);
    }

}
