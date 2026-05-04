# Aliro Certification Tool
A Test Harness and tooling designed to simplify development, testing, and certification for devices, guided by the Connectivity Standards Alliance - Aliro Working Group.

> [!NOTE]
> The tool is a complete reuse from CSA - Matter, and the UI still shows a lot of unrelated Matter-specific content. This will be fixed eventually.

This version of the Aliro Certification Tool uses:
* Aliro Specification Version 1.0
* Aliro CSG TT Test Plan Version for Aliro 1.0

# Setup Instructions
Following this section should take a couple of hours, mostly depending on internet speed.

## Requirements
* Computer with micro SD-reader (or micro SD-to-USB adapter if your computer does not have such a reader).
* Raspberry Pi 4 Model B - 8GB preferred (4GB might work).
    * Power adapter for Raspberry Pi.
    * Micro SD card (16 GB or more).
* NFC interface OM27160B1EVK (SPI based) or OM27160A1EVK (I2C based).
* Ethernet network cable (optional).
* LAN/Wi-Fi network with internet access.
* Murata LBUA0VG2BP-EVK-P (BLE/UWB interface) for BLE/UWB transport testing.
* Micro USB male to USB A male cable (for connecting the Murata BLE/UWB board).

> [!TIP] 
> It is possible to set up the TH entirely over SSH. Alternatively, access the Raspberry Pi directly using:
> * Micro HDMI to HDMI cable.
> * PC monitor.
> * USB keyboard.

> [!IMPORTANT]
> See https://github.com/aliro-access-control/aliro-actuator/tree/release/aliro-sve-v1.0/third_party for instructions on updating the Murata FW.

## A - Installing Ubuntu on SD-Card

1. Download and run Raspberry Pi Imager on your computer.
    * Available at https://www.raspberrypi.com/software/.
2. Click CHOOSE DEVICE under "Raspberry Pi Device".
    * Select "Raspberry Pi 4".
3. Click CHOOSE OS under "Operating System":
    1. Select "Other general-purpose OS".
    2. Select "Ubuntu".
    3. Depending on the version of Raspberry Pi Imager, pick exactly one of the following distributions:
      * "Ubuntu Server 22.04.3 LTS (64-bit)".
      * "Ubuntu Server 22.04.4 LTS (64-bit)".
      * "Ubuntu Server 22.04.5 LTS (64-bit)".

4. Click CHOOSE STORAGE under "Storage":
    * Select the microSD card that was previously inserted into your PC.
5. Click NEXT.

![Screenshot of Raspberry Pi imager](images/raspberry-pi-imager.png)

6. Click EDIT SETTINGS under "Would you like to apply OS customisation settings?":
    * Under GENERAL Tab:
        * Set hostname. Must be unique per TH setup. Eg. `aliro-th-pi1`.local.
        * Set username and password.
        * *Optionally configure wireless LAN if not using an Ethernet cable. (Only password-protected Wi-Fi networks are supported)*.
    * Under SERVICES Tab:
        * "Enable SSH" and choose "Use password authentication".

![Alt text](images/raspberry-pi-imager-os-customizations.png)

7. Click SAVE on "OS Customisation" modal window.
8. Select YES on "Would you like to apply OS customisation settings?".
9. Continue to write Ubuntu OS to micro SD-card.
10. Wait for writing and verification of SD-card to complete.

## B - Assembling Raspberry Pi

> [!TIP] 
> Start this with the Raspberry Pi disconnected from power.

1. Attach OM27160B1EVK or OM27160A1EVK NFC board to the Raspberry Pi.
2. [Optional] Connect the Murata LBUA0VG2BP-EVK-P to the Raspberry Pi using the micro-USB cable.

> [!NOTE]
> The Murata board is not needed if you only run NFC transport tests.

3. Insert micro SD-card.
4. [Optional] Attach Ethernet cable.
5. [Optional] Connect monitor and keyboard.
6. Power on Raspberry Pi.

## C - Connecting to Raspberry Pi
There are several ways you can connect to the Raspberry Pi.

### Connecting via SSH using hostname

> [!NOTE]
> Hostname access might not be supported on all computers and networks. If this fails, please try using the IP address directly. See below.

1. Wait for Raspberry Pi to boot.
2. Connect from terminal on PC via SSH using username and hostname assigned during OS configuration: `ssh <username>@<hostname>.local`.
    
    Example:
    ```
    ssh ubuntu@aliro-th-pi1.local
    ```

3. Enter password when prompted.

### Connecting via SSH using IP Address

1. Wait for Raspberry Pi to boot.
2. Connect from terminal on PC via SSH using username and IP address `ssh <username>@<ip-address>`.
    
    Example:
    ```
    ssh ubuntu@192.168.1.50
    ```

3. Enter password when prompted
   
> [!TIP] 
> If you don't know the IP address you can discover it from another machine on the LAN:
> - On Linux and macOS (might require `net-tools` installed)
>     ```
>     arp -na | grep -i  "b8:27:eb\|dc:a6:32\|e4:5f:01\|<other_raspberry_pi_foundation_mac_prefix>"
>     ```
> - On Windows:
>     ```
>     arp -a | findstr b8-27-eb dc-a6-32 e4-5f-01 <other_raspberry_pi_foundation_mac_prefix>
>     ```
> Note that your Raspberry Pi may use a MAC address prefix that is not among those listed above.
> In such a case, replace `<other_raspberry_pi_foundation_mac_prefix>` in the command with the MAC prefix (OUI) for your Raspberry Pi.

### Connecting using Monitor and Keyboard

This is mostly a backup if you need to configure the network or find the IP address.

1. Simply log in with the chosen username and password.

## D - Installing Aliro Test Harness on Raspberry Pi

1. On your Raspberry Pi, create an SSH key pair to access the GitHub repository.
    
    ```sh
    ssh-keygen -t ed25519 -C "<your github email>"
    ``` 
    
> [!NOTE]
> Use default file location, and set no passphrase, just press enter.

2. Copy the full output of the command below (your SSH public key):

    ```sh
    cat /home/ubuntu/.ssh/id_ed25519.pub
    ```

3. Add SSH Key to your account on GitHub:
   
   * Follow https://github.com/settings/ssh/new.
   * Alternatively:
     - Click your profile picture, then Settings, then "SSH and GPG keys" and finally "New SSH key".
     - Set the "Title" of the key.
     - Paste the key into the "Key" field.
     - Click "Add SSH key".
   
4. Get the Aliro Certification Tool code from GitHub:

    * Clone the repository in your home directory:
        ```sh
        cd ~
        git clone git@github.com:aliro-access-control/aliro-certification-tool.git
        ```

        * When asked if you trust the connection, please type `yes` and hit enter.

> [!TIP]
> You can check out a specific release, e.g. `aliro-sve-v1.0`.
> 
>   ```sh
>   cd  ~/aliro-certification-tool
>   git checkout aliro-sve-v1.0
>   ```

6. Auto-install Aliro Certification Tool:
   * Run auto installer script:
    
        ```sh
        cd  ~/aliro-certification-tool
        ./scripts/pi-setup/auto-install.sh
        ```

   * When prompted by `[sudo]` for user password, please type in password and hit enter.
   * When asked *"The HEAD is detached from a branch. Should it checkout to develop before proceeding?"*, please select "Yes" and hit enter.
   * When completed, script will prompt you to restart.
     * Type `1`  and press enter to reboot Raspberry Pi.
  
> [!NOTE]
> The auto installer is mostly hands-off, but can take more than an hour depending on your internet connection.

> [!NOTE]
> The first reboot after the auto installer might take 5 minutes or more, as several updates are applied.

## E - Starting the Aliro Test Harness on Raspberry Pi

1. Initialize the submodules:

    ```sh
    cd  ~/aliro-certification-tool
    git submodule update --init --recursive
    ```

2. Set up the Test Harness:

    * Run the setup script (note that it may take several minutes):
    > **_NOTE:_** By default, the `setup.sh` script will build NXP libraries for the SPI version of the [PN7160 evaluation kit](https://www.nxp.com/docs/en/application-note/AN12991.pdf).
    ```sh
    cd  ~/aliro-certification-tool/test_collections/aliro
    ./setup.sh
    ```
    > **_NOTE:_** For an I2C-based evaluation kit, run the script with the `NXP_TRANSPORT=I2C` environment variable set.
    ```sh
    cd  ~/aliro-certification-tool/test_collections/aliro
    NXP_TRANSPORT=I2C ./setup.sh
    ```
    * When prompted by `[sudo]` for user password, please type in password and hit enter.


3. Start the Test Harness:

    * Run the following commands:
    ```sh
    cd  ~/aliro-certification-tool
    ./scripts/start.sh
    ```

# Usage Instructions

> [!NOTE]
> The Test Harness will start automatically upon booting the Raspberry Pi.

## A - Opening the GUI

The UI of the tool is accessible via HTTP from a computer on the same LAN.
It can be opened by entering your Raspberry Pi's IP address in the web browser: `http://<raspberry-pi-ip-address>` (for example: http://192.168.2.9).

![Alt text](images/create_project.png)

> [!TIP]
> You can view the IP address of the Raspberry Pi by running
> `hostname -I` in a terminal on the Raspberry Pi.

> [!TIP]
> You need to wait a couple minutes after booting the Raspberry Pi, before attempting to connect.

## B - Configuring a Test Project

1. Start by clicking "Create Project".
2. Give the project a name.
3. Configure Parameters:
    * Click "Edit" in the "Project Config" window.
    * In the JSON, locate the `test_parameters` section.
    * It will be set to default configuration.
    * Set the test parameters as needed for your testing.

        Example:
        ```json
        "test_parameters": {
            "dut_reader_public_key":"043928f322019d4757893bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5d0eab192ee8873c5d34ee",
            "dut_reader_group_identifier":"00113344667799AA00113344667799AA",
            "dut_reader_issuer_group_identifier": "00113344667799AA00113344667799AB",
            "dut_reader_group_sub_identifier":"113344667799AA00113344667799AA00",
            "dut_reader_group_resolving_key":"00000000000000000000000000000000"
        }
        ```
        A full description of [Test Parameters](#test-parameters) is given in a later section.

        ![Example of project creation page.](<images/new_project_test_parameters.png>)

    * Click "Update" to save your configuration.
    * Click "Create" to finish creating the project.

## C - Creating a Test Run (Running test scripts)

1. Click the '▶️' ("Go To Test-Run") button next to the project.

    ![Screenshot showing go to test run button](images/go-to-test-run.png)

2. Click "Create new Test Run".

    ![Screenshot showing example of how to configure new test run](images/new-test-run.png)

3. Select "Operator Name" in the top right corner (it must be created on first use).
4. Select the whole Test Suite or specific Test Cases. Multiple test cases can be selected.

> [!NOTE]
> The Test Harness groups tests into suites by transport type and device role.
> Choose the suite that matches your use case.
> For example, to exercise a Reader with BLE/UWB, select the "BLE Reader" suite.

5. Click "Start".

    ![Screenshot showing a test run being executed](images/executing-test-run.png)
  
# Test Parameters

You can edit test parameters for a Project during project creation, but you can also click the "Edit" pencil icon on the row of the Project later.

## Test Parameters for Reader Tests

* `dut_reader_public_key` Public key for the Reader DUT.
  * Supported Format: 
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)
* `dut_reader_group_identifier` Group Identifier for Reader DUT.
  * Supported Format: 
    * HEX string
* `dut_reader_issuer_group_identifier` Group Identifier for Reader Issuer CA certificate.
  * Supported Format: 
    * HEX string
* `dut_reader_group_sub_identifier` Sub-group Identifier for Reader DUT.
  * Supported Format: 
    * HEX string
* `dut_reader_group_resolving_key` Group resolving key, used for the BLE tests, during 
the dynamic tag generation.
  * Supported Format: 
    * HEX string
* `th_access_credential_private_key` Private key for the user access credential, 
simulated by the tool. 
  * Supported Format:
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)
* `th_access_credential_public_key` Public key for the User access credential, 
simulated by the tool.  
  * Supported Format:
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)
* `dut_reader_issuer_public_key` Reader System Issuer CA certificate public key, used 
for certificate verification.  
  * Supported Format: 
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)

## Test Parameters for User Device Tests

> [!NOTE]
> Private and Public keys must match, and either none or both parameters should be set.

* `th_reader_private_key` Private key for the Reader, simulated by the tool. 
  * Supported Format: 
    * DER encoded HEX string (138 or 32 bytes)
    * PEM string (including `\n` as for line breaks)
* `th_reader_public_key` Public key for the Reader, simulated by the tool. 
  * Supported Format: 
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)
* `th_reader_group_identifier` Group Identifier for the Reader, simulated by the tool.
  * Supported Format: 
    * HEX string
* `th_reader_sub_group_identifier` Sub-group Identifier for the Reader, simulated by the tool.
  * Supported Format: 
    * HEX string
* `th_reader_certificate` Reader Certificate for the Reader, simulated by the tool. 
Used for LOAD CERT and AUTH1 command.
  * Supported Format: 
    * HEX string
* `th_reader_certificate` certificate to send during LOAD_CERT and AUTH1 commands.
  * Supported Format: 
    * HEX string
* `th_reader_group_resolving_key` Group resolving key, used for the BLE tests, during 
the dynamic tag generation.
  * Supported Format: 
    * HEX string
* `th_reader_spsm` spsm (Simplified Protocol / Service Multiplexer), used for the BLE 
tests, in the 'Reader SPSM and AC BLE UWB Protocol Version Characteristic Value 
declaration'.
  * Supported Format: 
    * HEX string
* `th_access_credential_public_key` Access credential public key, for the key slot 
lookup table used by the tool. 
  * Supported Format: 
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)
* `th_reader_issuer_public_key` Reader System Issuer CA certificate public key, used 
for key generation, when certificates are used.  
  * Supported Format: 
    * DER encoded HEX string
    * PEM string (including `\n` as for line breaks)

# Updating the Tool

Whenever there's an update to the tool, it can simply be updated by running these steps on the Raspberry Pi.

1. Check out the version of the tool you're updating to, eg. `aliro-sve-v1.0`

    ```sh
    cd  ~/aliro-certification-tool
    git fetch
    git checkout aliro-sve-v1.0
    ```

2. Run the update script:

    ```sh
    cd  ~/aliro-certification-tool
    ./scripts/update.sh
    ```
## Other Helpful commands

Test Harness will be started automatically when booting up the Raspberry Pi.

To **manually stop** the TH, run the command below in the `aliro-certification-tool` folder:
```sh
./scripts/stop.sh
```

To **manually start** the TH, run the command below in the `aliro-certification-tool` folder:
```sh
./scripts/start.sh
```

To **access logs** from the TH, run the command below in the `aliro-certification-tool` folder:
```sh
docker compose logs
```

Autostart on bootup can be disabled using the following command:
```sh
systemctl disable aliro-th
```

#### Configuring Raspberry Pi to connect to a Wi-Fi network without a password

Perform the following steps on the Raspberry Pi.

1. In `/etc/netplan/50-cloud-init.yaml`, add under `network`:
    ```yaml
        wifis:
            wlan0:
                dhcp4: true
                optional: true
                access-points:
                    "<network_name>": {}
    ```
2. Apply changes and reboot:
    ```
    sudo netplan apply
    sudo reboot
    ```

#### Configuring Raspberry Pi to support link-local address

In some cases, it may be useful to connect to the Raspberry Pi over a local link.
This can be enabled by updating the `netplan` configuration:

1. In `/etc/netplan/50-cloud-init.yaml`, add under `network`:
    ```yaml
    # /etc/netplan/50-cloud-init.yaml
    # network:
    #   ...
      ethernets:
          eth0:
              dhcp4: true
              optional: true
              link-local: [ ipv4, ipv6 ]
    ```

2. Apply changes and reboot:
    ```sh
    sudo netplan try # optional
    sudo netplan apply
    sudo reboot
    ```

## Authoring Test Scripts

If you want to contribute to the Aliro Test Harness, please follow the guidelines from [CONTRIBUTION.md](CONTRIBUTION.md).

Aliro test scripts are located in `aliro-certification-tool/test_collections/aliro`.
After changing/adding test scripts, the Test Harness backend must be restarted. This can be done using this command:

```sh
docker restart aliro-certification-tool-backend-1
```

Test Harness backend logs can be streamed using this command:
```sh
docker compose logs -f backend
```

## Step-up phase provisioning

For the Step-up phase we have three components:
- Access Document
- Device Request
- Device Response

Based on the `Device Request`, a `Device Response` is constructed from the `Access Document`.
In order for a test setup to validate the Step-up phase, you need to have the correct `Access Document` available on the DUT first.

For this purpose we have created a provisioning script that can be run to obtain the components used in the certification test and to load the correct `Access Document` onto the DUT.
This script is located at:
```
aliro-certification-tool/test_collections/aliro/support/access_doc/step-up/step_up_provision.py
```
> [!NOTE]
> You might need to install missing Python packages before the script can run successfully.
