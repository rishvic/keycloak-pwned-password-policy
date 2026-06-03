// SPDX-FileCopyrightText: 2026 Rishvic Pushpakaran
//
// SPDX-License-Identifier: Apache-2.0

package net.rishvic.keycloak.policy;

import static org.assertj.core.api.Assertions.*;

import java.io.IOException;
import java.io.StringReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class HibpHttpClientTest {
  @ParameterizedTest
  @CsvSource({
    "0018A45C4D1DEF81644B54AB7F969B88D65, 1",
    "00D4F6E8FA6EECAD2A3AA415EEC418D38EC, 2",
    "011053FD0102E94D6AE2F8B83D76FAF94F6, 1",
    "012A7CA357541F0AC487871FEEC1891C49C, 2",
    "0136E006E24E7D152139815FB0FC6A50B15, 2",
  })
  public void pwnedCount_returnsCountForMatchingHash(String hash, int expectedCount)
      throws IOException {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:1\r
        012A7CA357541F0AC487871FEEC1891C49C:2\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash))
        .isEqualTo(expectedCount);
  }

  @Test
  public void pwnedCount_returnsZeroForNonMatchingHash() throws IOException {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:1\r
        012A7CA357541F0AC487871FEEC1891C49C:2\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    String hash = "EE8D8728F435FD550F83852AABAB5234CE1DA528";

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash)).isZero();
  }

  @ParameterizedTest
  @CsvSource({
    "0018A45C4D1DEF81644B54AB7F969B88D65, 1",
    "0136E006E24E7D152139815FB0FC6A50B15, 2",
    "728F435FD550F83852AABAB5234CE1DA528, 0",
  })
  public void pwnedCount_skipsInvalidEntries(String hash, int expectedCount) throws IOException {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        invalidentry\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash))
        .isEqualTo(expectedCount);
  }

  @ParameterizedTest
  @CsvSource({
    "0018A45C4D1DEF81644B54AB7F969B88D65, 1",
    "0136E006E24E7D152139815FB0FC6A50B15, 2",
    "728F435FD550F83852AABAB5234CE1DA528, 0",
  })
  public void pwnedCount_skipsNonNumericCount(String hash, int expectedCount) throws IOException {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:invalidcount\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash))
        .isEqualTo(expectedCount);
  }

  @Test
  public void pwnedCount_treatsHashWithInvalidCountAsAbsent() throws IOException {
    String responseBody =
        """
        0018A45C4D1DEF81644B54AB7F969B88D65:1\r
        011053FD0102E94D6AE2F8B83D76FAF94F6:invalidcount\r
        0136E006E24E7D152139815FB0FC6A50B15:2\
        """;
    String hash = "011053FD0102E94D6AE2F8B83D76FAF94F6";

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash)).isZero();
  }

  @Test
  public void pwnedCount_parsesEmptyResponse() throws IOException {
    String responseBody = "";
    String hash = "728F435FD550F83852AABAB5234CE1DA528";

    assertThat(HibpHttpClient.pwnedCount(new StringReader(responseBody), hash)).isZero();
  }
}
