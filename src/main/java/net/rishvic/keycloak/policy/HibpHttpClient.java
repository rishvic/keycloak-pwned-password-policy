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
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;

public class HibpHttpClient implements BreachedPasswordLookup {

  private static final String BASE_URL = "https://api.pwnedpasswords.com/range/";
  private final KeycloakSession session;

  public HibpHttpClient(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public int getBreachCount(String sha1Hash) throws IOException {
    SimpleHttpResponse response =
        SimpleHttp.create(session)
            .doGet(BASE_URL + sha1Hash.substring(0, 5))
            .header("Accept", "*/*")
            .header("Add-Padding", "true")
            .asResponse();
    if (response.getStatus() != 200) {
      return 0;
    }
    Map<String, Integer> breaches = parseResponseBody(response.asString());
    return breaches.getOrDefault(sha1Hash.substring(5), 0);
  }

  static Map<String, Integer> parseResponseBody(String body) {
    return Arrays.stream(body.split("\\n"))
        .map(
            (line) -> {
              try {
                String[] vals = line.split(":", 2);
                return vals.length == 2
                    ? Optional.of(new PwnedPasswordEntry(vals[0], Integer.parseInt(vals[1])))
                    : Optional.<PwnedPasswordEntry>empty();
              } catch (NumberFormatException e) {
                return Optional.<PwnedPasswordEntry>empty();
              }
            })
        .filter(Optional::isPresent)
        .map(Optional::get)
        .filter((entry) -> entry.count() > 0)
        .collect(Collectors.toMap(PwnedPasswordEntry::hash, PwnedPasswordEntry::count));
  }

  private record PwnedPasswordEntry(String hash, int count) {}
}
