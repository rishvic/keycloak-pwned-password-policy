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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.junit.jupiter.api.Test;

/**
 * Guards the bundled default i18n messages shipped via Keycloak theme resources. Every message key
 * the provider emits in a {@link org.keycloak.policy.PolicyError} must have a non-blank default in
 * {@code theme-resources/messages/messages_en.properties}; otherwise Keycloak would render the raw
 * key string to end users.
 */
public class DefaultMessagesTest {

  private static final String BUNDLE = "/theme-resources/messages/messages_en.properties";

  @Test
  public void everyProviderMessageKeyHasNonBlankDefault() throws IOException {
    Properties messages = loadBundle();

    assertThat(messages.getProperty(PwnedPasswordPolicyProvider.ERROR_MESSAGE)).isNotBlank();
    assertThat(messages.getProperty(PwnedPasswordPolicyProvider.ERROR_MESSAGE_LOOKUP_UNAVAILABLE))
        .isNotBlank();
    assertThat(messages.getProperty(PwnedPasswordPolicyProvider.ERROR_MESSAGE_NO_SHA1_ALGO))
        .isNotBlank();
  }

  private static Properties loadBundle() throws IOException {
    Properties messages = new Properties();
    try (InputStream in = DefaultMessagesTest.class.getResourceAsStream(BUNDLE)) {
      assertThat(in)
          .as("bundled message resource %s should be on the classpath", BUNDLE)
          .isNotNull();
      messages.load(in);
    }
    return messages;
  }
}
