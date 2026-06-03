// SPDX-FileCopyrightText: 2026 Rishvic Pushpakaran
//
// SPDX-License-Identifier: Apache-2.0

package net.rishvic.keycloak.policy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.time.Duration;
import java.util.OptionalInt;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.ParseException;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.connections.httpclient.SafeInputStream;
import org.keycloak.executors.ExecutorsProvider;
import org.keycloak.models.KeycloakSession;

public class HibpHttpClient implements BreachedPasswordLookup {

  private final HttpClient httpClient;
  private final ExecutorService executor;
  private final String baseUrl;
  private final long maxConsumedResponseSize;
  private final Duration lookupTimeout;
  private final String userAgent;

  public HibpHttpClient(
      KeycloakSession session, String baseUrl, Duration lookupTimeout, String userAgent) {
    this(
        session.getProvider(HttpClientProvider.class).getHttpClient(),
        session.getProvider(ExecutorsProvider.class).getExecutor("hibp-lookup"),
        baseUrl,
        session.getProvider(HttpClientProvider.class).getMaxConsumedResponseSize(),
        lookupTimeout,
        userAgent);
  }

  HibpHttpClient(
      HttpClient httpClient,
      ExecutorService executor,
      String baseUrl,
      long maxConsumedResponseSize,
      Duration lookupTimeout,
      String userAgent) {
    this.httpClient = httpClient;
    this.executor = executor;
    this.baseUrl = baseUrl;
    this.maxConsumedResponseSize = maxConsumedResponseSize;
    this.lookupTimeout = lookupTimeout;
    this.userAgent = userAgent;
  }

  @Override
  public int getBreachCount(String sha1Hash) throws IOException {
    // baseUrl is validated at factory init time and the prefix is hex, so this cannot throw.
    HttpGet request = new HttpGet(URI.create(baseUrl + "/range/" + sha1Hash.substring(0, 5)));
    request.setHeader("User-Agent", userAgent);
    request.setHeader("Accept", "*/*");
    request.setHeader("Add-Padding", "true");

    Future<Integer> future = executor.submit(() -> executeAndCount(request, sha1Hash.substring(5)));
    try {
      return future.get(lookupTimeout.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      request.abort();
      future.cancel(true);
      throw new InterruptedIOException(
          "HIBP lookup exceeded its budget of " + lookupTimeout.toMillis() + " ms");
    } catch (InterruptedException e) {
      request.abort();
      future.cancel(true);
      Thread.currentThread().interrupt();
      throw new InterruptedIOException("Interrupted while awaiting HIBP lookup");
    } catch (ExecutionException e) {
      throw unwrap(e.getCause());
    }
  }

  private int executeAndCount(HttpUriRequest request, String hashSuffix) throws IOException {
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
      return pwnedCount(new InputStreamReader(safeInputStream, charset), hashSuffix);
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

  private static IOException unwrap(Throwable cause) {
    if (cause instanceof IOException ioerr) {
      return ioerr;
    }
    if (cause instanceof RuntimeException rterr) {
      throw rterr;
    }
    if (cause instanceof Error err) {
      throw err;
    }
    return new IOException("HIBP lookup failed", cause);
  }
}
