
# Mirror and history of OpenOTP

It's a mirror and the historical release in a git repository.
I did the mirror because I used OpenOTP with [paper-token](https://github.com/adulau/paper-token) and [hotp-js](https://github.com/adulau/hotp-js).

OpenOTP author is Mark Fullmer.

# Original information page

Captured from [http://web.archive.org/web/20140620004358/http://www.splintered.net/sw/otp/](http://web.archive.org/web/20140620004358/http://www.splintered.net/sw/otp/).

~~~~
Open OTP Information

OpenOTP is an implementation of the HOTP protocol using a ZeitControl
Cardsystems ZC3.9 BasicCard and standalone balance reader, standalone Spyrus
PAR2 (Personal Access Reader), or PCSC-Lite supported Smart Card reader.

Included is a C library implementation of the HOTP protocol and
associated user database management, HOTP PAM library, OpenVPN plug-in module,
micro RADIUS server with HOTP support, and utilties for managing the Smart
Card, Spyrus reader, and host side HOTP user database.  The PCSC-Lite
API provides reader support for Smart Card management under FreeBSD and Linux.

The card management, firmware loaders, C API, and authentication methods
have been developed & tested for FreeBSD and Linux.

The PARII HOTP firmware is provided as a pre-compiled binary with source
for the HOTP implementation.  The Spyrus development toolkit and 
Hi-Tech/Microchip C compiler are required for modification.  Run-time
customization of strings is supported via an EEProm loader without need
for the development toolkit & PIC16 compiler.  A Unix tool is included for
downloading firmware to the reader with a Spyrus downloader cable.

Source and Binary for the BasicCard firmware is supplied.  Modification
requires the Windows BasicCard development software available as
a free download from ZeitControl.  A Unix version of bcload implemented
with the PCSC-Lite interface is included.

Distribution:

otp-control       - OTP database manager
otp-pam           - OTP PAM module
otp-sca           - Smart Card Admin Utility
otp-sct           - Smart Card Terminal
otp-openvpn       - OpenVPN OTP plug-in
urd               - Micro RADIUS server with HOTP integration
htsoft-downloader - PIC bootloader downloader utility for Spyrus firmware
bcload            - BasicCard firmware loader
basiccard         - BasicCard (Smart Card) firmware & source code
spyrus-par2       - Spyrus PAR2 firmware & source code
common            - otplib API and other common code
doc               - Documentation & Man pages in Unix and HTML format.
scripts           - shell scripts to setup list of users with HOTP
                    Unix and SC databases.
~~~~
