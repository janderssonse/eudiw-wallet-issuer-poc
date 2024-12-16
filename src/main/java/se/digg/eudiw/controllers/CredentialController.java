package se.digg.eudiw.controllers;

import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;

import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.config.SignerConfig;
import se.digg.eudiw.service.OpenIdFederationService;
import se.digg.eudiw.credentialissuer.model.Address;
import se.digg.eudiw.credentialissuer.model.CredentialOfferParam;
import se.digg.eudiw.credentialissuer.model.CredentialParam;
import se.digg.eudiw.credentialissuer.util.PidBuilder;
import se.digg.wallet.metadata.WalletOAuthClientMetadata;

@RestController
public class CredentialController {

	private final EudiwConfig eudiwConfig;
	private final SignerConfig signerConfig;
	private final OpenIdFederationService openIdFederationService;

	public CredentialController(@Autowired EudiwConfig eudiwConfig, @Autowired OpenIdFederationService openIdFederationService, @Autowired SignerConfig signerConfig) {
		this.eudiwConfig = eudiwConfig;
		this.signerConfig = signerConfig;
		this.openIdFederationService = openIdFederationService;
	}

	@GetMapping("/demo-oidfed-client")
	String oidfedClientDemo() {
        try {
            return openIdFederationService.resolveWallet("1234567890").toJson(true);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

	@GetMapping("/demo-credential")
	String demoCredential() {
        try {
			return new PidBuilder(eudiwConfig.getIssuer(), signerConfig)
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("IdentityCredential")
                        .addSelectiveDisclosure("given_name", "John")
                        .addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"))
                        .build();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
 
    }

    @PostMapping("/credential")
	String credential(@AuthenticationPrincipal Jwt jwt, @RequestBody CredentialParam credential) { // @AuthenticationPrincipal Jwt jwt,
        try {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication.getPrincipal() instanceof Jwt) {

				WalletOAuthClientMetadata walletOAuthClientMetadata = openIdFederationService.resolveWallet("1234567891");
				Optional<JWK> jwk;
				if (walletOAuthClientMetadata != null) {
					jwk = walletOAuthClientMetadata.getJwkSet().getKeys().stream().findFirst();
				}
				else {
					jwk = Optional.empty();
				}

				// TODO - get PID data from ID token and authentic source (t.ex. skatteverket)
				PidBuilder builder = new PidBuilder(eudiwConfig.getIssuer(), signerConfig)
                        .withExp(eudiwConfig.getExpHours())
                        .withVcType("https://attestations.eudiw.se/se_pid")
                        .addSelectiveDisclosure("given_name", "FOO" + jwt.getClaim("givenName"))
                        .addSelectiveDisclosure("last_name", "FOO" + jwt.getClaim("surname"))
						.addSelectiveDisclosure("birthdate", "FOO" + jwt.getClaim("birthDate"))
                        .addSelectiveDisclosure("address", new Address("123 Main St", "Anytown", "Anystate", "US"));

				jwk.ifPresent(value -> builder.withCnf(Map.of("jwk", value.toPublicJWK().toJSONObject())));

				return builder.build();
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