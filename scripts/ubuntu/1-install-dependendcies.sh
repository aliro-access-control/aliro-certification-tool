#! /usr/bin/env bash

#
# Copyright (c) 2023 Aliro Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Install Docker Package Repo
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Silence user prompts about reboot and service restart required (script will prompt user to reboot in the end)
sudo sed -i "s/#\$nrconf{kernelhints} = -1;/\$nrconf{kernelhints} = -1;/g" /etc/needrestart/needrestart.conf
sudo sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf

sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install and Lock packages
PACKAGES_FILE="$(realpath "$(dirname "$0")")/packages-ubuntu.txt"
# regex to allow comments after each package entry
PACKAGES=$(grep -oE "^[^#[:space:]]+" "$PACKAGES_FILE")
sudo DEBIAN_FRONTEND=noninteractive echo "$PACKAGES" | sudo xargs apt-get install -y
echo "$PACKAGES" | sudo xargs apt-mark hold

# Install Peotry, needed for Test Harness CLI
curl -sSL https://install.python-poetry.org | python3 -
