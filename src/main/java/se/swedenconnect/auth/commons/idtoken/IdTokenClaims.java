package se.swedenconnect.auth.commons.idtoken;

import java.time.Instant;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Parsed data content of IdTokenClaims
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IdTokenClaims {

  String tokenId;
  String issuer;
  Instant issueTime;
  Instant expirationTime;
  String audience;
  String inResponseTo;
  String idp;
  String loa;
  SourceID sourceId;
  SubjAttributes subjectAttributes;
  Map<SubjAttributeType, Object> subjectAttributeMap;

}
