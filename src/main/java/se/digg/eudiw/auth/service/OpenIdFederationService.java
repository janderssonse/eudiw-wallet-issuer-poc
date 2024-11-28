package se.digg.eudiw.auth.service;

import se.digg.wallet.metadata.WalletOAuthClientMetadata;

public interface OpenIdFederationService {
    WalletOAuthClientMetadata resolveWallet(String walletId);
    String trustMark(String trustMarkId, String subject);
}

