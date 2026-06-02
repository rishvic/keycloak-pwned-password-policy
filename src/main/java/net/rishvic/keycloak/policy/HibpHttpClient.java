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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.OptionalInt;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.ParseException;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.connections.httpclient.SafeInputStream;
import org.keycloak.models.KeycloakSession;

public class HibpHttpClient implements BreachedPasswordLookup {

  private static final String BASE_URL = "https://api.pwnedpasswords.com/range/";
  private final HttpClient httpClient;
  private final long maxConsumedResponseSize;

  public HibpHttpClient(KeycloakSession session) {
    HttpClientProvider provider = session.getProvider(HttpClientProvider.class);
    this.httpClient = provider.getHttpClient();
    this.maxConsumedResponseSize = provider.getMaxConsumedResponseSize();
  }

  @Override
  public int getBreachCount(String sha1Hash) throws IOException {
    RequestConfig requestConfig =
        RequestConfig.custom()
            .setConnectTimeout(3000)
            .setConnectionRequestTimeout(3000)
            .setSocketTimeout(5000)
            .build();

    HttpGet request = new HttpGet(BASE_URL + sha1Hash.substring(0, 5));
    request.setHeader("Accept", "*/*");
    request.setHeader("Add-Padding", "true");
    request.setConfig(requestConfig);

    HttpResponse response = httpClient.execute(request);

    StatusLine statusLine = response.getStatusLine();
    if (statusLine == null) {
      throw new ClientProtocolException("HIBP response had no status line");
    }

    int statusCode = statusLine.getStatusCode();
    if (statusCode != HttpStatus.SC_OK) {
      String reasonPhrase = EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null);
      throw new HttpResponseException(
          statusCode, reasonPhrase == null ? "Unknown Status Code" : reasonPhrase);
    }

    HttpEntity entity = response.getEntity();
    if (entity == null) {
      // getEntity() may contractually be null, but a 200 GET should carry a body, so null is
      // anomalous, not "not breached" - throw so the provider's fail-open/closed policy decides.
      throw new ClientProtocolException("HIBP response had no body");
    }

    Charset charset = resolveCharset(entity);

    try (InputStream inputStream = entity.getContent()) {
      SafeInputStream safeInputStream = new SafeInputStream(inputStream, maxConsumedResponseSize);
      return pwnedCount(new InputStreamReader(safeInputStream, charset), sha1Hash.substring(5));
    }
  }

  private static Charset resolveCharset(HttpEntity entity) {
    // Body is ASCII hex; a malformed/unsupported Content-Type falls back to UTF-8, never fails.
    try {
      Charset charset = ContentType.getOrDefault(entity).getCharset();
      return charset != null ? charset : StandardCharsets.UTF_8;
    } catch (ParseException | UnsupportedCharsetException e) {
      return StandardCharsets.UTF_8;
    }
  }

  static int pwnedCount(Reader response, String hashSuffix) throws IOException {
    try (BufferedReader reader = new BufferedReader(response)) {
      String prefix = hashSuffix + ":";
      OptionalInt breachCount =
          reader
              .lines()
              .filter(line -> line.startsWith(prefix))
              .map(HibpHttpClient::parseCount)
              .flatMapToInt(OptionalInt::stream)
              .findFirst();

      return breachCount.orElse(0);
    } catch (UncheckedIOException e) {
      throw e.getCause();
    }
  }

  private static OptionalInt parseCount(String line) {
    try {
      return OptionalInt.of(Integer.parseInt(line.substring(36)));
    } catch (NumberFormatException e) {
      return OptionalInt.empty();
    }
  }
}
