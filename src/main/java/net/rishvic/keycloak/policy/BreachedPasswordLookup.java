// SPDX-FileCopyrightText: 2026 Rishvic Pushpakaran
//
// SPDX-License-Identifier: Apache-2.0

package net.rishvic.keycloak.policy;

import java.io.IOException;

public interface BreachedPasswordLookup {
  /**
   * Given the SHA-1 hash of a password, returns the number of times the password has been breached.
   * If the password hasn't been breached, returns 0.
   *
   * @param sha1Hash uppercase hex SHA-1 of the password
   * @return breach count for the hash, or 0 if not breached
   * @throws IOException upstream failure
   */
  int getBreachCount(String sha1Hash) throws IOException;
}
