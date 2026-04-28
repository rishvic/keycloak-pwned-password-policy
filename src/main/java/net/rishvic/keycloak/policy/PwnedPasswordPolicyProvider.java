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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.function.IntSupplier;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

class PwnedPasswordPolicyProvider implements PasswordPolicyProvider {

  private static final Logger logger = Logger.getLogger(PwnedPasswordPolicyProvider.class);
  private static final String ERROR_MESSAGE = "invalidPasswordPwnedPasswordBreachedMessage";
  private static final String ERROR_MESSAGE_NO_SHA1_ALGO =
      "invalidPasswordPwnedNoSuchAlgorithmMessage";

  private final IntSupplier thresholdSupplier;
  private final BreachedPasswordLookup lookup;

  public PwnedPasswordPolicyProvider(IntSupplier thresholdSupplier, BreachedPasswordLookup lookup) {
    this.thresholdSupplier = thresholdSupplier;
    this.lookup = lookup;
  }

  @Override
  public PolicyError validate(String username, String password) {
    int breachThreshold = thresholdSupplier.getAsInt();

    try {
      MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
      String passwordDigest =
          HexFormat.of()
              .withUpperCase()
              .formatHex(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
      int count = lookup.getBreachCount(passwordDigest);
      return count >= breachThreshold ? new PolicyError(ERROR_MESSAGE, breachThreshold) : null;
    } catch (IOException e) {
      // Fail-open; allow password to be used if cannot reach 3rd party API
      logger.warnf("Could not reach Have I Been Pwned API: %s", e.getMessage());
      return null;
    } catch (NoSuchAlgorithmException e) {
      logger.errorf("SHA-1 digest algorithm not found: %s", e.getMessage());
      return new PolicyError(ERROR_MESSAGE_NO_SHA1_ALGO);
    }
  }

  @Override
  public PolicyError validate(RealmModel realm, UserModel user, String password) {
    return validate(user.getUsername(), password);
  }

  @Override
  public Object parseConfig(String value) {
    return parseInteger(value, 1);
  }

  @Override
  public void close() {}
}
