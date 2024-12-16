package se.digg.eudiw.config;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import se.digg.eudiw.authentication.*;
import se.digg.eudiw.authorization.PreAuthCodeGrantAuthenticationConverter;
import se.digg.eudiw.authorization.PreAuthCodeGrantAuthenticationProvider;
import se.digg.eudiw.context.EudiwSessionSecurityContextRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.JWKSource;

@Configuration
@EnableWebSecurity
public class OAuth2ServerConfig {

  @Autowired
  private SwedenConnectAuthenticationProvider authProvider;

  @Autowired
  EudiwSessionSecurityContextRepository contextRepository;
  //@Autowired
  //private ClientRegistrationRepository clientRegistrationRepository;

  @Autowired
  private EudiwConfig config;

  @Autowired
  ApplicationContext applicationContext;



  @Bean
  @Order(2)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http, @Autowired RegisteredClientRepository registeredClientRepository, @Autowired AuthenticationManager authenticationManager, @Autowired OAuth2AuthorizationService authorizationService, @Autowired OAuth2TokenGenerator<?> tokenGenerator) throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
            OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
            .authorizeHttpRequests( authorizeHttpRequests -> authorizeHttpRequests
                    .requestMatchers("/oauth2/token*").permitAll()
                    .anyRequest().authenticated()
            )
            .with(authorizationServerConfigurer, (authorizationServer) ->
                    authorizationServer
                            .registeredClientRepository(registeredClientRepository)
                            .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
                            .authorizationEndpoint(authorizationEndpoint ->
                                    authorizationEndpoint
                                            .authenticationProvider(authProvider)
                            )
                            .tokenEndpoint(tokenEndpoint -> tokenEndpoint

                                    .accessTokenRequestConverter(new PreAuthCodeGrantAuthenticationConverter(contextRepository))
                                    .authenticationProvider(new PreAuthCodeGrantAuthenticationProvider(authorizationService, tokenGenerator, registeredClientRepository)))

            )
            .exceptionHandling(exception -> exception
                    // Redirect to the login page when not authenticated
                    // authorization endpoint
                    .authenticationEntryPoint( new LoginUrlAuthenticationEntryPoint("/auth/login"))
            );

    return http.build();
  }

  @Bean
  @Order(3)
  SecurityFilterChain authenticationSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

    http
            .securityMatcher("/auth/*")
            .authenticationProvider(authProvider)
            .authorizeHttpRequests(
                    authorizeRequests ->
                            authorizeRequests
                                    .requestMatchers("/auth/login").permitAll()
                                    .requestMatchers("/auth/return/*").permitAll()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            ;

    return http.build();
  }

  @Bean
  @Order(4)
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

      http
            .addFilterBefore(new SwedenconnectAuthenticationReturnFilter(authenticationManager, contextRepository), UsernamePasswordAuthenticationFilter.class)
            .authenticationProvider(authProvider)
            .authorizeHttpRequests(
                    authorizeRequests ->
                            authorizeRequests
                                    .requestMatchers("/favicon.ico").permitAll()
                                    .requestMatchers("/.well-known/**").permitAll()
                                    .requestMatchers("/cert/**").permitAll()
                                    .requestMatchers("/actuator/**").permitAll()
                                    .requestMatchers("/v3/api-docs/**").permitAll()
                                    .requestMatchers("/error**").permitAll()
                                    .requestMatchers("/login*").permitAll()
                                    .requestMatchers("/demo-credential").permitAll()
                                    .requestMatchers("/demo-oidfed-client").authenticated()
                                    .requestMatchers("/credential").authenticated() //hasAuthority("SCOPE_VerifiablePortableDocumentA1")
                                    .requestMatchers("/credential_offer").hasAuthority("SCOPE_VerifiablePortableDocumentA1")
                                    .anyRequest().authenticated()
            )
            .csrf(AbstractHttpConfigurer::disable)
            .cors(AbstractHttpConfigurer::disable)
            .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()))
            .exceptionHandling(exception -> exception
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/auth/login"))
            );

      http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .securityContext(securityContext -> securityContext.securityContextRepository(contextRepository));
      return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
      AuthenticationManagerBuilder authenticationManagerBuilder =
          http.getSharedObject(AuthenticationManagerBuilder.class);
      authenticationManagerBuilder.authenticationProvider(authProvider);
      return authenticationManagerBuilder.build();
  }

  @Bean
  public IdProxyRequestBuilder idProxyRequestBuilder() {
    return new IdProxyRequestBuilder(config);
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {



    RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId(config.getClientId())
      .clientAuthenticationMethods(s -> {
        s.add(ClientAuthenticationMethod.NONE);
      })
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:pre-authorized_code"));


    registeredClientBuilder = registeredClientBuilder.redirectUri(String.format("%s/login/oauth2/code/messaging-client-pkce", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/auth-flow", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback-demo-auth", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/credentials", config.getIssuerBaseUrl()))
      .redirectUri(String.format("%s/callback-demo-pre-auth", config.getIssuerBaseUrl()))
      .redirectUri("com.example.eudiwdemo:/oauthredirect")
      .redirectUri(config.getIssuerBaseUrl());

    for (String uri : config.getRedirectUris()) {
      registeredClientBuilder = registeredClientBuilder.redirectUri(uri);
    }

    registeredClientBuilder = registeredClientBuilder.scope("identitycredential.read")
            .scope("VerifiablePortableDocumentA1")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder()
                      .requireAuthorizationConsent(true)
                      .requireProofKey(true) //Only PKCE is supported
                      .build())
            .tokenSettings(TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED) // Generate JWT token
                    .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                    .accessTokenTimeToLive(Duration.ofSeconds(30 * 60))
                    .refreshTokenTimeToLive(Duration.ofSeconds(60 * 60))
                    .reuseRefreshTokens(true)
                    .build())
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build());
    RegisteredClient registeredClient = registeredClientBuilder.build();
    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
      return AuthorizationServerSettings.builder().issuer(config.getIssuer()).build();
  }

  @Bean
  public OAuth2AuthorizationService authorizationService() {
    return new InMemoryOAuth2AuthorizationService();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = Jwks.generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> accessTokenCustomizer() {
      return (context) -> {
        Authentication principal = context.getPrincipal();
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
          Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
              .collect(Collectors.toSet());

          context.getClaims().claim("authorities", authorities);

          // TODO det mesta borde flyttas till idToken eller userinfo någonting
          JwtClaimsSet.Builder claims = context.getClaims();
          if (principal.getPrincipal() instanceof SwedenConnectPrincipal) {
            SwedenConnectPrincipal p = (SwedenConnectPrincipal) principal.getPrincipal();
            if (p.getSubjAttributes().getPersonalNumber() != null) claims.claim("personalNumber", p.getSubjAttributes().getPersonalNumber());
            if (p.getSubjAttributes().getName() != null) claims.claim("name", p.getSubjAttributes().getName());
            if (p.getSubjAttributes().getGivenName() != null) claims.claim("givenName", p.getSubjAttributes().getGivenName());
            if (p.getSubjAttributes().getSurname() != null) claims.claim("surname", p.getSubjAttributes().getSurname());
            if (p.getSubjAttributes().getCoordinationNumber() != null) claims.claim("coordinationNumber", p.getSubjAttributes().getCoordinationNumber());
            if (p.getSubjAttributes().getPrid() != null) claims.claim("prid", p.getSubjAttributes().getPrid());
            if (p.getSubjAttributes().getPridPersistence() != null) claims.claim("pridPersistence", p.getSubjAttributes().getPridPersistence());
            if (p.getSubjAttributes().getEidasPersonIdentifier() != null) claims.claim("eidasPersonIdentifier", p.getSubjAttributes().getEidasPersonIdentifier());
            if (p.getSubjAttributes().getPersonalNumberBinding() != null) claims.claim("personalNumberBinding", p.getSubjAttributes().getPersonalNumberBinding());
            if (p.getSubjAttributes().getOrgNumber() != null) claims.claim("orgNumber", p.getSubjAttributes().getOrgNumber());
            if (p.getSubjAttributes().getOrgAffiliation() != null) claims.claim("orgAffiliation", p.getSubjAttributes().getOrgAffiliation());
            if (p.getSubjAttributes().getOrgName() != null) claims.claim("orgName", p.getSubjAttributes().getOrgName());
            if (p.getSubjAttributes().getOrgUnit() != null) claims.claim("orgUnit", p.getSubjAttributes().getOrgUnit());
            if (p.getSubjAttributes().getUserCertificate() != null) claims.claim("userCertificate", p.getSubjAttributes().getUserCertificate());
            if (p.getSubjAttributes().getUserSignature() != null) claims.claim("userSignature", p.getSubjAttributes().getUserSignature());
            if (p.getSubjAttributes().getDeviceIp() != null) claims.claim("deviceIp", p.getSubjAttributes().getDeviceIp());
            if (p.getSubjAttributes().getAuthnEvidence() != null) claims.claim("authnEvidence", p.getSubjAttributes().getAuthnEvidence());
            if (p.getSubjAttributes().getCountry() != null) claims.claim("country", p.getSubjAttributes().getCountry());
            if (p.getSubjAttributes().getBirthName() != null) claims.claim("birthName", p.getSubjAttributes().getBirthName());
            if (p.getSubjAttributes().getPlaceOfbirth() != null) claims.claim("placeOfbirth", p.getSubjAttributes().getPlaceOfbirth());
            if (p.getSubjAttributes().getAge() != null) claims.claim("age", p.getSubjAttributes().getAge());
            if (p.getSubjAttributes().getBirthDate() != null) claims.claim("birthDate", p.getSubjAttributes().getBirthDate());
          }

        }
      };
  }


  static class Jwks {

    private Jwks() {
    }

    public static RSAKey generateRsa() {
      KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
      return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();
    }
  }

  static class KeyGeneratorUtils {

    private KeyGeneratorUtils() {
    }

    static KeyPair generateRsaKey() {
      KeyPair keyPair;
      try {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
        throw new IllegalStateException(ex);
      }
      return keyPair;
    }
  }

  @Bean
  public OAuth2TokenGenerator<?> tokenGenerator() {
    JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource());
    JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
    OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
    OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
    return new DelegatingOAuth2TokenGenerator(
            jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
  }

  @Bean
  public AuthenticationEventPublisher authenticationEventPublisher
          (ApplicationEventPublisher applicationEventPublisher) {
    return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
  }
}
