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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PwnedPasswordPolicyProviderTest {

  private static final String BREACHED_PASSWORD = "password";
  private static final String BREACHED_PASSWORD_SHA1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
  private static final String LESS_BREACHED_PASSWORD = "dragon";
  private static final String LESS_BREACHED_PASSWORD_SHA1 =
      "AF8978B1797B72ACFFF9595A5A2A373EC3D9106D";

  @Test
  public void validate_rejectsBreachedPassword() {
    PwnedPasswordPolicyProvider provider =
        new PwnedPasswordPolicyProvider(() -> 5, new FakeLookup());
    String user = "user";
    String password = BREACHED_PASSWORD;

    assertNotNull(provider.validate(user, password));
  }

  @Test
  public void validate_allowsUnbreachedPassword() {
    PwnedPasswordPolicyProvider provider =
        new PwnedPasswordPolicyProvider(() -> 5, new FakeLookup());
    String user = "user";
    String password = "securepassword";

    assertNull(provider.validate(user, password));
  }

  @Test
  public void validate_allowsLessBreachedPassword() {
    PwnedPasswordPolicyProvider provider =
        new PwnedPasswordPolicyProvider(() -> 5, new FakeLookup());
    String user = "user";
    String password = LESS_BREACHED_PASSWORD;

    assertNull(provider.validate(user, password));
  }

  @Test
  public void validate_rejectsThresholdBreachedPassword() {
    PwnedPasswordPolicyProvider provider =
        new PwnedPasswordPolicyProvider(() -> 2, new FakeLookup());
    String user = "user";
    String password = LESS_BREACHED_PASSWORD;

    assertNotNull(provider.validate(user, password));
  }

  @Test
  public void validate_allowsLookupFailure() {
    PwnedPasswordPolicyProvider provider =
        new PwnedPasswordPolicyProvider(() -> 5, new FakeLookup(new IOException("test exception")));
    String user = "user";
    String password = BREACHED_PASSWORD;

    assertNull(provider.validate(user, password));
  }

  private static class FakeLookup implements BreachedPasswordLookup {

    private final Map<String, Integer> counts =
        Map.of(BREACHED_PASSWORD_SHA1, 10, LESS_BREACHED_PASSWORD_SHA1, 2);
    private final IOException error;

    public FakeLookup(IOException error) {
      this.error = error;
    }

    public FakeLookup() {
      this(null);
    }

    @Override
    public int getBreachCount(String sha1Hash) throws IOException {
      if (error != null) throw error;
      return counts.getOrDefault(sha1Hash, 0);
    }
  }
}
