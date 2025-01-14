package se.digg.eudiw.credentialissuer.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Arrays;

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
        return Arrays.stream(values())
                .filter(credFormat -> credFormat.format.equalsIgnoreCase(format))
                .findFirst()
                .orElse(null);
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
