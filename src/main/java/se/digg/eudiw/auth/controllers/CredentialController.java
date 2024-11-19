package se.digg.eudiw.auth.controllers;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;

import se.digg.eudiw.auth.config.EudiwConfig;
import se.digg.eudiw.credentialissuer.model.Address;
import se.digg.eudiw.credentialissuer.model.CredentialIssuerMetadata;
import se.digg.eudiw.credentialissuer.model.CredentialOfferParam;
import se.digg.eudiw.credentialissuer.model.CredentialParam;
import se.digg.eudiw.credentialissuer.util.PidBuilder;

@RestController
public class CredentialController {

	@Autowired
	private EudiwConfig eudiwConfig;

	@GetMapping("/demo-credential")
	String demoCredential() {
        try {
			return new PidBuilder(eudiwConfig.getIssuer())
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("IdentityCredential")
                        .addSelectiveDisclosure("given_name", "John")
                        .addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
 
    }

	@GetMapping("/.well-known/openid-credential-issuer")
	CredentialIssuerMetadata metadata() {
		return new CredentialIssuerMetadata(
			eudiwConfig.getIssuer(),
			Stream.of(eudiwConfig.getAuthHost()).collect(Collectors.toSet()),
			String.format("%s/credential", eudiwConfig.getCredentialHost()),
			null,
			null,
			null,
			null,
			false,
			false,
			null,
			null
		);
	}

	@CrossOrigin(origins = "https://wallet-dev.eudiw.se:9443")
    @PostMapping("/credential")
	String credential(@AuthenticationPrincipal Jwt jwt, @RequestBody CredentialParam credential) { // @AuthenticationPrincipal Jwt jwt,
        try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication.getPrincipal() instanceof Jwt) {
				// TODO - get PID data from ID token and authentic source (t.ex. skatteverket)
				String c = new PidBuilder(eudiwConfig.getIssuer())
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("https://attestations.eudiw.se/se_pid")
                        .addSelectiveDisclosure("given_name", jwt.getClaim("givenName"))
                        .addSelectiveDisclosure("last_name", jwt.getClaim("surname"))
						.addSelectiveDisclosure("birthdate", jwt.getClaim("birthDate"))
                        //.addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();

				return c;
			}
			
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
		return null;
    }

    @GetMapping("/credential_offer")
    Map<String, Object> credentialOffer(@RequestParam("credential_offer") CredentialOfferParam credentialOffer) {
        try {
			return Map.of("todo", "foobar");
		} catch(Exception e) {
			throw new RuntimeException(e);
		}

    }

}