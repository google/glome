// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "base64.h"

#include <openssl/evp.h>

#define CHAR_62_CLASSIC '+'
#define CHAR_62_URLSAFE '-'
#define CHAR_63_CLASSIC '/'
#define CHAR_63_URLSAFE '_'

size_t base64url_encode(const uint8_t* src, size_t src_len, uint8_t* dst,
                        size_t dst_len) {
  size_t len = ENCODED_BUFSIZE(src_len);
  // The ENCODED_BUFSIZE macro has not been tested for operation close
  // to the overflow point, but up to SIZE_MAX/2 it behaves fine.
  if (src_len >= SIZE_MAX/2) {
    return 0;
  }
  if (len > dst_len) {
    return 0;
  }
  len = EVP_EncodeBlock(dst, src, src_len);
  // Replacing 62th and 63th character with '-' and '_' per RFC4648 section 5
  for (size_t i = 0; i < len; i++) {
    switch (dst[i]) {
      case CHAR_62_CLASSIC:
        dst[i] = CHAR_62_URLSAFE;
        break;
      case CHAR_63_CLASSIC:
        dst[i] = CHAR_63_URLSAFE;
        break;
    }
  }
  return len;
}
