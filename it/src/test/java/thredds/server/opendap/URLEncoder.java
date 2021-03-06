/*
 * Copyright 1999,2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package thredds.server.opendap;

import java.util.BitSet;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.IOException;

/**
 * Define acceptable characters, all others are encoded with %xx. Uses UTF8 encoding.
 * <p/>
 * This class is very similar to the java.net.URLEncoder class.
 * Unfortunately, with java.net.URLEncoder there is no way to specify to the
 * java.net.URLEncoder which characters should NOT be encoded.
 * <p/>
 * Stolen from org.apache.catalina.
 *
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 * @author jcaron - add 2nd constructor
 */

public class URLEncoder {
  protected static final char[] hexadecimal =
      {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
       'A', 'B', 'C', 'D', 'E', 'F'};

  //Array containing the safe characters set.
  protected BitSet safeCharacters = new BitSet(256);

  /**
   * Default constructor - acceptable characters are alphanumerics only.
   */
  public URLEncoder() {
    for (char i = 'a'; i <= 'z'; i++) {
      addSafeCharacter(i);
    }
    for (char i = 'A'; i <= 'Z'; i++) {
      addSafeCharacter(i);
    }
    for (char i = '0'; i <= '9'; i++) {
      addSafeCharacter(i);
    }
  }

  /**
   * Default acceptable characters are alphanumerics.
   * @param accept other acceptable characters.
   */
  public URLEncoder(String accept) {
    this();
    for (int i = 0; i < accept.length(); i++) {
      char c = accept.charAt(i);
      addSafeCharacter(c);
    }
  }

  public void addSafeCharacter(char c) {
    safeCharacters.set(c);
  }

  public String encode(String path) {
    int maxBytesPerChar = 10;
    StringBuffer rewrittenPath = new StringBuffer(path.length());
    ByteArrayOutputStream buf = new ByteArrayOutputStream(maxBytesPerChar);
    OutputStreamWriter writer = null;
    try {
      writer = new OutputStreamWriter(buf, "UTF8");
    } catch (Exception e) {
      e.printStackTrace();
      writer = new OutputStreamWriter(buf);
    }

    for (int i = 0; i < path.length(); i++) {
      int c = (int) path.charAt(i);
      if (safeCharacters.get(c)) {
        rewrittenPath.append((char) c);
      } else {
        // convert to external encoding before hex conversion
        try {
          writer.write((char) c);
          writer.flush();
        } catch (IOException e) {
          buf.reset();
          continue;
        }
        byte[] ba = buf.toByteArray();
        for (int j = 0; j < ba.length; j++) {
          // Converting each byte in the buffer
          byte toEncode = ba[j];
          rewrittenPath.append('%');
          int low = (int) (toEncode & 0x0f);
          int high = (int) ((toEncode & 0xf0) >> 4);
          rewrittenPath.append(hexadecimal[high]);
          rewrittenPath.append(hexadecimal[low]);
        }
        buf.reset();
      }
    }
    return rewrittenPath.toString();
  }
}
