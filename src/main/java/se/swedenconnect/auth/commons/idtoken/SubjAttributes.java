package se.swedenconnect.auth.commons.idtoken;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SubjAttributes {

  private String personalNumber;
  private String name;
  private String givenName;
  private String surname;
  private String coordinationNumber;
  private String prid;
  private String pridPersistence;
  private String eidasPersonIdentifier;
  private String personalNumberBinding;
  private String orgNumber;
  private String orgAffiliation;
  private String orgName;
  private String orgUnit;
  private String userCertificate;
  private String userSignature;
  private String deviceIp;
  private String authnEvidence;
  private String country;
  private String birthName;
  private String placeOfbirth;
  private Integer age;
  private String birthDate;
}
