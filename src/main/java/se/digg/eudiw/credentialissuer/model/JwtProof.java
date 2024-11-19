package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class JwtProof {
    String proofType;
    String jwt;

    public JwtProof() {
        this.jwt = "";
        this.proofType = "jwt";
    }

    public JwtProof(String jwt) {
        this.jwt = jwt;
        this.proofType = "jwt";
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public String getProofType() {
        return proofType;
    }

    public void setProofType(String proofType) {
        this.proofType = proofType;
    }

    
    
}
