package se.digg.eudiw.credentialissuer.model;

import java.util.Set;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class CredentialSupport {
    String format;
    String scope;
    Set<String> cryptographicBindingMethodsSupported;
    Set<String> cryptographicSuitesSupported;
    Set<String> proofTypesSupported;
    Set<CredentialSupportDisplay> display;

    public CredentialSupport() {
        this.format = "";
        this.scope = null;
        this.cryptographicBindingMethodsSupported = null;
        this.cryptographicSuitesSupported = null;
        this.proofTypesSupported = null;
        this.display = null;
    }

    public CredentialSupport(String format, String scope, Set<String> cryptographicBindingMethodsSupported, Set<String> cryptographicSuitesSupported, Set<String> proofTypesSupported, Set<CredentialSupportDisplay> display) {
        this.format = format;
        this.scope = scope;
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported;
        this.cryptographicSuitesSupported = cryptographicSuitesSupported;
        this.proofTypesSupported = proofTypesSupported;
        this.display = display;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Set<String> getCryptographicBindingMethodsSupported() {
        return cryptographicBindingMethodsSupported;
    }

    public void setCryptographicBindingMethodsSupported(Set<String> cryptographicBindingMethodsSupported) {
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported;
    }

    public Set<String> getCryptographicSuitesSupported() {
        return cryptographicSuitesSupported;
    }

    public void setCryptographicSuitesSupported(Set<String> cryptographicSuitesSupported) {
        this.cryptographicSuitesSupported = cryptographicSuitesSupported;
    }

    public Set<String> getProofTypesSupported() {
        return proofTypesSupported;
    }

    public void setProofTypesSupported(Set<String> proofTypesSupported) {
        this.proofTypesSupported = proofTypesSupported;
    }

    public Set<CredentialSupportDisplay> getDisplay() {
        return display;
    }

    public void setDisplay(Set<CredentialSupportDisplay> display) {
        this.display = display;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((format == null) ? 0 : format.hashCode());
        result = prime * result + ((scope == null) ? 0 : scope.hashCode());
        result = prime * result + ((cryptographicBindingMethodsSupported == null) ? 0
                : cryptographicBindingMethodsSupported.hashCode());
        result = prime * result
                + ((cryptographicSuitesSupported == null) ? 0 : cryptographicSuitesSupported.hashCode());
        result = prime * result + ((proofTypesSupported == null) ? 0 : proofTypesSupported.hashCode());
        result = prime * result + ((display == null) ? 0 : display.hashCode());
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
        CredentialSupport other = (CredentialSupport) obj;
        if (format == null) {
            if (other.format != null)
                return false;
        } else if (!format.equals(other.format))
            return false;
        if (scope == null) {
            if (other.scope != null)
                return false;
        } else if (!scope.equals(other.scope))
            return false;
        if (cryptographicBindingMethodsSupported == null) {
            if (other.cryptographicBindingMethodsSupported != null)
                return false;
        } else if (!cryptographicBindingMethodsSupported.equals(other.cryptographicBindingMethodsSupported))
            return false;
        if (cryptographicSuitesSupported == null) {
            if (other.cryptographicSuitesSupported != null)
                return false;
        } else if (!cryptographicSuitesSupported.equals(other.cryptographicSuitesSupported))
            return false;
        if (proofTypesSupported == null) {
            if (other.proofTypesSupported != null)
                return false;
        } else if (!proofTypesSupported.equals(other.proofTypesSupported))
            return false;
        if (display == null) {
            if (other.display != null)
                return false;
        } else if (!display.equals(other.display))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialSupport [format=" + format + ", scope=" + scope + ", cryptographicBindingMethodsSupported="
                + cryptographicBindingMethodsSupported + ", cryptographicSuitesSupported="
                + cryptographicSuitesSupported + ", proofTypesSupported=" + proofTypesSupported + ", display=" + display
                + "]";
    }

}


