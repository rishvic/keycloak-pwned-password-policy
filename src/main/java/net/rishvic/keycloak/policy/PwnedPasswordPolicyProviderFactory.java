/*
 * Copyright 2026 Rishvic Pushpakaran
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.rishvic.keycloak.policy;

import java.util.List;
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

  public static final String FAIL_OPEN_PROPERTY = "failOpen";
  public static final boolean DEFAULT_FAIL_OPEN = true;

  private volatile Config.Scope config;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public PasswordPolicyProvider create(KeycloakSession session) {
    IntSupplier thresholdSupplier =
        () -> session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(ID);
    return new PwnedPasswordPolicyProvider(
        thresholdSupplier, this::getFailOpen, new HibpHttpClient(session));
  }

  @Override
  public void init(Config.Scope config) {
    this.config = config;
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
        .name(FAIL_OPEN_PROPERTY)
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText(
            "If true (default), allow password when HIBP API is unreachable. If false, reject the"
                + " password.")
        .defaultValue(DEFAULT_FAIL_OPEN)
        .add();

    return builder.build();
  }

  private boolean getFailOpen() {
    return config == null
        ? DEFAULT_FAIL_OPEN
        : config.getBoolean(FAIL_OPEN_PROPERTY, DEFAULT_FAIL_OPEN);
  }
}
