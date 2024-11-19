package se.digg.eudiw.credentialissuer.model;

public class CredentialParam {
    CredentialFormatEnum format;
    JwtProof proof;

    public CredentialParam() {
        this.format = CredentialFormatEnum.JWT_VC_JSON;
        this.proof = null;
    }

    public CredentialParam(CredentialFormatEnum format, JwtProof proof) {
        this.format = format;
        this.proof = proof;
    }

    public CredentialFormatEnum getFormat() {
        return format;
    }

    public void setFormat(CredentialFormatEnum format) {
        this.format = format;
    }

    public JwtProof getProof() {
        return proof;
    }

    public void setProof(JwtProof proof) {
        this.proof = proof;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((format == null) ? 0 : format.hashCode());
        result = prime * result + ((proof == null) ? 0 : proof.hashCode());
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
        CredentialParam other = (CredentialParam) obj;
        if (format != other.format)
            return false;
        if (proof == null) {
            if (other.proof != null)
                return false;
        } else if (!proof.equals(other.proof))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CredentialParam [format=" + format + ", proof=" + proof + "]";
    }

    
}
