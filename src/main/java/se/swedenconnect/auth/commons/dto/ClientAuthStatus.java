package se.swedenconnect.auth.commons.dto;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum ClientAuthStatus {
  OK,
  NULL_SESSION,
  EXPIRED,
  STATE_VIOLATION,
  ILLEGAL_SESSION,
  INVALID_CLIENT_PROVIDER_RETURN_URL,
  INVALID_IDENTITY_PROVIDER,
  NO_MATCHING_IDENTITY_PROVIDER,
  INVALID_CLIENT_REQUEST_ID,
  INVALID_CLIENT_REQUEST,
  UNSUPPORTED_LOA,
  UNSUPPORTED_PROFILE,
  INVALID_AUTHENTICATION,
  CANCELLED_BY_USER,
  INTERNAL_ERROR,
  OTHER
}
