package se.digg.eudiw.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import se.digg.eudiw.config.EudiwConfig;
import se.digg.eudiw.service.OpenIdFederationService;
import se.digg.wallet.metadata.WalletOAuthClientMetadata;

@Component
public class FederatedRegisteredClientRepository implements RegisteredClientRepository {

    private final String walletProviderAnchor;
    private final OpenIdFederationService openIdFederationService;


    FederatedRegisteredClientRepository(@Autowired EudiwConfig eudiwConfig, @Autowired OpenIdFederationService openIdFederationService) {
        this.walletProviderAnchor = eudiwConfig.getOpenidFederation().walletProviderAnchor();
        this.openIdFederationService = openIdFederationService;
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        return null;
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        WalletOAuthClientMetadata walletOAuthClientMetadata = openIdFederationService.resolveWallet(clientId);
        return null;
    }
}
