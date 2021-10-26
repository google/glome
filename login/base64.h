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

#ifndef BASE64_H_
#define BASE64_H_
#include <inttypes.h>
#include <stdlib.h>

// Base64 needs 4 bytes for every 3 bytes of input (+ padding + NULL byte)
// NOTE: Caller is responsible for protecting against integer overflow.
#define ENCODED_BUFSIZE(n) ((((n) + 2) / 3) * 4 + 1)
#define DECODED_BUFSIZE(n) ((((n)*3) / 4))

size_t base64url_encode(const uint8_t* src, size_t src_len, uint8_t* dst,
                        size_t dst_len);
size_t base64url_decode(const uint8_t* src, size_t src_len, uint8_t* dst,
                        size_t dst_len);

#endif  // BASE64_H_
