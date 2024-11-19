package se.digg.eudiw.credentialissuer.model;

import java.util.Set;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialIssuerMetadata {
    String credentialIssuer;
    Set<String> authorizationServers;
    String credentialEndpoint;
    String batchCredentialEndpoint;
    String deferredCredentialEndpoint;
    Set<String> credentialResponseEncryptionAlgValuesSupported;
    Set<String> credentialResponseEncryptionEncValuesSupported;
    boolean requireCredentialResponseEncryption;
    boolean credentialIdentifiersSupported;
    Set<DisplayProperty> display;
    Set<CredentialSupport> credentialsSupported;

    public CredentialIssuerMetadata() {
        this.credentialIssuer = "";
        this.authorizationServers = null;
        this.credentialEndpoint = "";
        this.batchCredentialEndpoint = null;
        this.deferredCredentialEndpoint = null;
        this.credentialResponseEncryptionAlgValuesSupported = null;
        this.credentialResponseEncryptionEncValuesSupported = null;
        this.requireCredentialResponseEncryption = false;
        this.credentialIdentifiersSupported = false;
        this.display = null;
        this.credentialsSupported = null;
    }

    public CredentialIssuerMetadata(String credentialIssuer, Set<String> authorizationServers,
            String credentialEndpoint, String batchCredentialEndpoint, String deferredCredentialEndpoint,
            Set<String> credentialResponseEncryptionAlgValuesSupported,
            Set<String> credentialResponseEncryptionEncValuesSupported, boolean requireCredentialResponseEncryption,
            boolean credentialIdentifiersSupported, Set<DisplayProperty> display,
            Set<CredentialSupport> credentialsSupported) {
        this.credentialIssuer = credentialIssuer;
        this.authorizationServers = authorizationServers;
        this.credentialEndpoint = credentialEndpoint;
        this.batchCredentialEndpoint = batchCredentialEndpoint;
        this.deferredCredentialEndpoint = deferredCredentialEndpoint;
        this.credentialResponseEncryptionAlgValuesSupported = credentialResponseEncryptionAlgValuesSupported;
        this.credentialResponseEncryptionEncValuesSupported = credentialResponseEncryptionEncValuesSupported;
        this.requireCredentialResponseEncryption = requireCredentialResponseEncryption;
        this.credentialIdentifiersSupported = credentialIdentifiersSupported;
        this.display = display;
        this.credentialsSupported = credentialsSupported;
    }

    public String getCredentialIssuer() {
        return credentialIssuer;
    }

    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

    public Set<String> getAuthorizationServers() {
        return authorizationServers;
    }

    public void setAuthorizationServers(Set<String> authorizationServers) {
        this.authorizationServers = authorizationServers;
    }

    public String getCredentialEndpoint() {
        return credentialEndpoint;
    }

    public void setCredentialEndpoint(String credentialEndpoint) {
        this.credentialEndpoint = credentialEndpoint;
    }

    public String getBatchCredentialEndpoint() {
        return batchCredentialEndpoint;
    }

    public void setBatchCredentialEndpoint(String batchCredentialEndpoint) {
        this.batchCredentialEndpoint = batchCredentialEndpoint;
    }

    public String getDeferredCredentialEndpoint() {
        return deferredCredentialEndpoint;
    }

    public void setDeferredCredentialEndpoint(String deferredCredentialEndpoint) {
        this.deferredCredentialEndpoint = deferredCredentialEndpoint;
    }

    public Set<String> getCredentialResponseEncryptionAlgValuesSupported() {
        return credentialResponseEncryptionAlgValuesSupported;
    }

    public void setCredentialResponseEncryptionAlgValuesSupported(
            Set<String> credentialResponseEncryptionAlgValuesSupported) {
        this.credentialResponseEncryptionAlgValuesSupported = credentialResponseEncryptionAlgValuesSupported;
    }

    public Set<String> getCredentialResponseEncryptionEncValuesSupported() {
        return credentialResponseEncryptionEncValuesSupported;
    }

    public void setCredentialResponseEncryptionEncValuesSupported(
            Set<String> credentialResponseEncryptionEncValuesSupported) {
        this.credentialResponseEncryptionEncValuesSupported = credentialResponseEncryptionEncValuesSupported;
    }

    public boolean isRequireCredentialResponseEncryption() {
        return requireCredentialResponseEncryption;
    }

    public void setRequireCredentialResponseEncryption(boolean requireCredentialResponseEncryption) {
        this.requireCredentialResponseEncryption = requireCredentialResponseEncryption;
    }

    public boolean isCredentialIdentifiersSupported() {
        return credentialIdentifiersSupported;
    }

    public void setCredentialIdentifiersSupported(boolean credentialIdentifiersSupported) {
        this.credentialIdentifiersSupported = credentialIdentifiersSupported;
    }

    public Set<DisplayProperty> getDisplay() {
        return display;
    }

    public void setDisplay(Set<DisplayProperty> display) {
        this.display = display;
    }

    public Set<CredentialSupport> getCredentialsSupported() {
        return credentialsSupported;
    }

    public void setCredentialsSupported(Set<CredentialSupport> credentialsSupported) {
        this.credentialsSupported = credentialsSupported;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((credentialIssuer == null) ? 0 : credentialIssuer.hashCode());
        result = prime * result + ((authorizationServers == null) ? 0 : authorizationServers.hashCode());
        result = prime * result + ((credentialEndpoint == null) ? 0 : credentialEndpoint.hashCode());
        result = prime * result + ((batchCredentialEndpoint == null) ? 0 : batchCredentialEndpoint.hashCode());
        result = prime * result + ((deferredCredentialEndpoint == null) ? 0 : deferredCredentialEndpoint.hashCode());
        result = prime * result + ((credentialResponseEncryptionAlgValuesSupported == null) ? 0
                : credentialResponseEncryptionAlgValuesSupported.hashCode());
        result = prime * result + ((credentialResponseEncryptionEncValuesSupported == null) ? 0
                : credentialResponseEncryptionEncValuesSupported.hashCode());
        result = prime * result + (requireCredentialResponseEncryption ? 1231 : 1237);
        result = prime * result + (credentialIdentifiersSupported ? 1231 : 1237);
        result = prime * result + ((display == null) ? 0 : display.hashCode());
        result = prime * result + ((credentialsSupported == null) ? 0 : credentialsSupported.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CredentialIssuerMetadata other = (CredentialIssuerMetadata) obj;
        if (credentialIssuer == null) {
            if (other.credentialIssuer != null)
                return false;
        } else if (!credentialIssuer.equals(other.credentialIssuer))
            return false;
        if (authorizationServers == null) {
            if (other.authorizationServers != null)
                return false;
        } else if (!authorizationServers.equals(other.authorizationServers))
            return false;
        if (credentialEndpoint == null) {
            if (other.credentialEndpoint != null)
                return false;
        } else if (!credentialEndpoint.equals(other.credentialEndpoint))
            return false;
        if (batchCredentialEndpoint == null) {
            if (other.batchCredentialEndpoint != null)
                return false;
        } else if (!batchCredentialEndpoint.equals(other.batchCredentialEndpoint))
            return false;
        if (deferredCredentialEndpoint == null) {
            if (other.deferredCredentialEndpoint != null)
                return false;
        } else if (!deferredCredentialEndpoint.equals(other.deferredCredentialEndpoint))
            return false;
        if (credentialResponseEncryptionAlgValuesSupported == null) {
            if (other.credentialResponseEncryptionAlgValuesSupported != null)
                return false;
        } else if (!credentialResponseEncryptionAlgValuesSupported
                .equals(other.credentialResponseEncryptionAlgValuesSupported))
            return false;
        if (credentialResponseEncryptionEncValuesSupported == null) {
            if (other.credentialResponseEncryptionEncValuesSupported != null)
                return false;
        } else if (!credentialResponseEncryptionEncValuesSupported
                .equals(other.credentialResponseEncryptionEncValuesSupported))
            return false;
        if (requireCredentialResponseEncryption != other.requireCredentialResponseEncryption)
            return false;
        if (credentialIdentifiersSupported != other.credentialIdentifiersSupported)
            return false;
        if (display == null) {
            if (other.display != null)
                return false;
        } else if (!display.equals(other.display))
            return false;
        if (credentialsSupported == null) {
            if (other.credentialsSupported != null)
                return false;
        } else if (!credentialsSupported.equals(other.credentialsSupported))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialIssuerMetadata [credentialIssuer=" + credentialIssuer + ", authorizationServers="
                + authorizationServers + ", credentialEndpoint=" + credentialEndpoint + ", batchCredentialEndpoint="
                + batchCredentialEndpoint + ", deferredCredentialEndpoint=" + deferredCredentialEndpoint
                + ", credentialResponseEncryptionAlgValuesSupported=" + credentialResponseEncryptionAlgValuesSupported
                + ", credentialResponseEncryptionEncValuesSupported=" + credentialResponseEncryptionEncValuesSupported
                + ", requireCredentialResponseEncryption=" + requireCredentialResponseEncryption
                + ", credentialIdentifiersSupported=" + credentialIdentifiersSupported + ", display=" + display
                + ", credentialsSupported=" + credentialsSupported + "]";
    }

}
