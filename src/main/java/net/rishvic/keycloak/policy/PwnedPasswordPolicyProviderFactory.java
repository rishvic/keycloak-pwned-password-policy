// SPDX-FileCopyrightText: 2026 Rishvic Pushpakaran
//
// SPDX-License-Identifier: Apache-2.0

package net.rishvic.keycloak.policy;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.function.IntSupplier;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class PwnedPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {

  public static final String ID = "pwnedPassword";

  public static final String BASE_URL_PROPERTY = "hibpBaseUrl";
  public static final String DEFAULT_BASE_URL = "https://api.pwnedpasswords.com";

  public static final String FAIL_OPEN_PROPERTY = "failOpen";
  public static final boolean DEFAULT_FAIL_OPEN = true;

  public static final String LOOKUP_TIMEOUT_PROPERTY = "lookupTimeoutMillis";
  public static final long DEFAULT_LOOKUP_TIMEOUT = 3000L;

  public static final String USER_AGENT_PROPERTY = "userAgent";
  public static final String DEFAULT_USER_AGENT = getDefaultUserAgent();

  private volatile Config.Scope config;
  private volatile String baseUrl = DEFAULT_BASE_URL;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public PasswordPolicyProvider create(KeycloakSession session) {
    IntSupplier thresholdSupplier =
        () -> session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(ID);
    return new PwnedPasswordPolicyProvider(
        thresholdSupplier,
        this::getFailOpen,
        new HibpHttpClient(session, baseUrl, getLookupTimeout(), getUserAgent()));
  }

  @Override
  public void init(Config.Scope config) {
    this.config = config;
    this.baseUrl = resolveBaseUrl(config);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public String getDisplayName() {
    return "Pwned Passwords";
  }

  @Override
  public String getConfigType() {
    return PasswordPolicyProvider.INT_CONFIG_TYPE;
  }

  @Override
  public String getDefaultConfigValue() {
    return "1";
  }

  @Override
  public boolean isMultiplSupported() {
    return false;
  }

  @Override
  public void close() {}

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    ProviderConfigurationBuilder builder = ProviderConfigurationBuilder.create();

    builder
        .property()
        .name(BASE_URL_PROPERTY)
        .type(ProviderConfigProperty.URL_TYPE)
        .helpText(
            "Base URL of the Have I Been Pwned Pwned Passwords range API; the policy appends"
                + " /range/{prefix}. Override only to target a HIBP-compatible mirror or proxy."
                + " Must be a valid absolute URL or the server fails to start.")
        .defaultValue(DEFAULT_BASE_URL)
        .add();

    builder
        .property()
        .name(FAIL_OPEN_PROPERTY)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText(
            "If true (default), allow password when HIBP API is unreachable. If false, reject the"
                + " password.")
        .defaultValue(DEFAULT_FAIL_OPEN)
        .add();

    builder
        .property()
        .name(LOOKUP_TIMEOUT_PROPERTY)
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .helpText(
            "Total time budget in milliseconds for a single HIBP lookup, including any retries the"
                + " shared HTTP client performs. On expiry the request is aborted and the failOpen"
                + " policy decides.")
        .defaultValue(DEFAULT_LOOKUP_TIMEOUT)
        .add();

    builder
        .property()
        .name(USER_AGENT_PROPERTY)
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "User-Agent header sent with each HIBP lookup; by convention this identifies the"
                + " application calling the API. Defaults to this plugin's name and version."
                + " Override to send a custom value; a blank value falls back to the default.")
        .defaultValue(DEFAULT_USER_AGENT)
        .add();

    return builder.build();
  }

  private static String resolveBaseUrl(Config.Scope config) {
    String configured =
        config == null ? DEFAULT_BASE_URL : config.get(BASE_URL_PROPERTY, DEFAULT_BASE_URL);
    // Normalize trailing slashes: we own the "/range/{prefix}" path joining ourselves.
    String normalized = configured.replaceAll("/+$", "");
    URI uri;
    try {
      uri = new URI(normalized);
    } catch (URISyntaxException e) {
      throw new RuntimeException(
          "Invalid '" + BASE_URL_PROPERTY + "' value '" + configured + "': " + e.getMessage(), e);
    }
    if (!uri.isAbsolute()) {
      throw new RuntimeException(
          "Invalid '"
              + BASE_URL_PROPERTY
              + "' value '"
              + configured
              + "': must be an absolute URL");
    }
    return normalized;
  }

  private boolean getFailOpen() {
    return config == null
        ? DEFAULT_FAIL_OPEN
        : config.getBoolean(FAIL_OPEN_PROPERTY, DEFAULT_FAIL_OPEN);
  }

  private Duration getLookupTimeout() {
    long configured =
        config == null
            ? DEFAULT_LOOKUP_TIMEOUT
            : config.getLong(LOOKUP_TIMEOUT_PROPERTY, DEFAULT_LOOKUP_TIMEOUT);
    return Duration.ofMillis(configured > 0 ? configured : DEFAULT_LOOKUP_TIMEOUT);
  }

  private String getUserAgent() {
    String userAgent =
        config == null ? DEFAULT_USER_AGENT : config.get(USER_AGENT_PROPERTY, DEFAULT_USER_AGENT);
    return userAgent.isBlank() ? DEFAULT_USER_AGENT : userAgent;
  }

  private static String getDefaultUserAgent() {
    String version =
        Optional.ofNullable(
                PwnedPasswordPolicyProviderFactory.class.getPackage().getImplementationVersion())
            .orElse("dev");
    return "keycloak-pwned-password-policy/"
        + version
        + " (+https://codeberg.org/rishvic/keycloak-pwned-password-policy)";
  }
}
