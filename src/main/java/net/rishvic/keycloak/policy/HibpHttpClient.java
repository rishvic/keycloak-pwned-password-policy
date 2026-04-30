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
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
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
    RequestConfig requestConfig =
        RequestConfig.custom()
            .setConnectTimeout(3000)
            .setConnectionRequestTimeout(3000)
            .setSocketTimeout(5000)
            .build();

    SimpleHttpResponse response =
        SimpleHttp.create(session)
            .withRequestConfig(requestConfig)
            .doGet(BASE_URL + sha1Hash.substring(0, 5))
            .header("Accept", "*/*")
            .header("Add-Padding", "true")
            .asResponse();
    int statusCode = response.getStatus();
    if (statusCode != HttpStatus.SC_OK) {
      String reasonPhrase = EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null);
      throw new HttpResponseException(
          statusCode, reasonPhrase == null ? "Unknown Status Code" : reasonPhrase);
    }

    Map<String, Integer> breaches = parseResponseBody(response.asString());
    return breaches.getOrDefault(sha1Hash.substring(5), 0);
  }

  static Map<String, Integer> parseResponseBody(String body) {
    return body.lines()
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
