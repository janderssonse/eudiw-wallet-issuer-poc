package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum CredentialFormatEnum {

    @JsonProperty("jwt_vc_json")
    JWT_VC_JSON("jwt_vc_json"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    LDP_VC("ldp_vc");

    private String format;

    CredentialFormatEnum(String format) {
        this.format = format;
    }

    public String getFormat() {
        return format;
    }

    public static CredentialFormatEnum fromString(String format) {
        for (CredentialFormatEnum b : CredentialFormatEnum.values()) {
            if (b.format.equalsIgnoreCase(format)) {
                return b;
            }
        }
        return null;
    }

    public static CredentialFormatEnum fromStringOrDefault(String format) {
        CredentialFormatEnum credentialFormatEnum = fromString(format);
        if (credentialFormatEnum == null) {
            return JWT_VC_JSON;
        }
        return credentialFormatEnum;
    }

    public String toString() {
        return format;
    }
}
