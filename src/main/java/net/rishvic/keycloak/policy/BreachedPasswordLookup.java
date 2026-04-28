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
