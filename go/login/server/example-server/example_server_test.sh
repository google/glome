#!/bin/bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

go build ./main.go
./main run -a 127.0.0.1:8000 -k config/keys.yml -s config/authorization.sh &
ID="$!"

# Give the server enough time to finish setting up.
sleep 1

TOKEN=`curl -s 127.0.0.1:8000/v1/UYcvQ1u4uJ0OOtYqouURB07hleHDnvaogAFBi-ZW48N2/serial-number:1234567890=ABCDFGH%2F%23%3F/reboot/`
if [[ "$TOKEN" != "p8M_BUKj7zXBVM2JlQhNYFxs4J-DzxRAps83ZaNDquY=" ]]
then
    kill $ID
    exit 1
fi

TOKEN=`curl -s 127.0.0.1:8000/v1/AYUg8AmJMKdUdIt93LQ-91oNvzoNJjga9OukqY6qm05q0PU=/my-server.local/shell/root/`
if [[ "$TOKEN" != "lyHuaHuCcknb5sJEukWSFs8B1SUBIWMCXfNY64fIkFk=" ]]
then
  echo $TOKEN
    kill $ID
    exit 2
fi

kill $ID
exit 0


