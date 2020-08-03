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

#ifndef LOCKDOWN_H_
#define LOCKDOWN_H_

#define LOCKDOWN_DISABLED 0
#define LOCKDOWN_ENABLED 1

// Checks if the machine is in a lockdown state as indicated by the provided
// file. Returns LOCKDOWN_DISABLED if lockdown is disabled or no path was
// provided. Returns LOCKDOWN_ENABLED if lockdown is enabled. Returns other
// value if the lockdown state could not be determined.
int check_lockdown(const char* path);

#endif  // LOCKDOWN_H_
