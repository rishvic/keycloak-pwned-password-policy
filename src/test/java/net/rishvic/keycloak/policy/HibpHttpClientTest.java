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

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.*;

import java.util.Map;
import org.junit.jupiter.api.Test;

public class HibpHttpClientTest {
  @Test
  public void parseResponseBody_generatesValidMap() {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:1\r
        012A7CA357541F0AC487871FEEC1891C49C:2\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    Map<String, Integer> expectedMap =
        Map.ofEntries(
            entry("0018A45C4D1DEF81644B54AB7F969B88D65", 1),
            entry("00D4F6E8FA6EECAD2A3AA415EEC418D38EC", 2),
            entry("011053FD0102E94D6AE2F8B83D76FAF94F6", 1),
            entry("012A7CA357541F0AC487871FEEC1891C49C", 2),
            entry("0136E006E24E7D152139815FB0FC6A50B15", 2));

    Map<String, Integer> map = HibpHttpClient.parseResponseBody(responseBody);

    assertThat(map).containsExactlyInAnyOrderEntriesOf(expectedMap);
  }

  @Test
  public void parseResponseBody_removePaddedEntries() {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:0\r
        012A7CA357541F0AC487871FEEC1891C49C:0\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    Map<String, Integer> expectedMap =
        Map.ofEntries(
            entry("0018A45C4D1DEF81644B54AB7F969B88D65", 1),
            entry("0136E006E24E7D152139815FB0FC6A50B15", 2));

    Map<String, Integer> map = HibpHttpClient.parseResponseBody(responseBody);

    assertThat(map).containsExactlyInAnyOrderEntriesOf(expectedMap);
  }

  @Test
  public void parseResponseBody_skipInvalidEntries() {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        invalidentry\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    Map<String, Integer> expectedMap =
        Map.ofEntries(
            entry("0018A45C4D1DEF81644B54AB7F969B88D65", 1),
            entry("0136E006E24E7D152139815FB0FC6A50B15", 2));

    Map<String, Integer> map = HibpHttpClient.parseResponseBody(responseBody);

    assertThat(map).containsExactlyInAnyOrderEntriesOf(expectedMap);
  }

  @Test
  public void parseResponseBody_skipNonNumericCount() {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:invalidcount\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    Map<String, Integer> expectedMap =
        Map.ofEntries(
            entry("0018A45C4D1DEF81644B54AB7F969B88D65", 1),
            entry("0136E006E24E7D152139815FB0FC6A50B15", 2));

    Map<String, Integer> map = HibpHttpClient.parseResponseBody(responseBody);

    assertThat(map).containsExactlyInAnyOrderEntriesOf(expectedMap);
  }

  @Test
  public void parseResponseBody_emptyBodyGivesEmptyMap() {
    String responseBody = "";

    Map<String, Integer> map = HibpHttpClient.parseResponseBody(responseBody);

    assertThat(map).isEmpty();
  }
}
