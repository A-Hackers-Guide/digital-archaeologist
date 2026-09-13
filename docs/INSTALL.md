# Digital Archaeologist v1.1.0-pre1

Native release binaries and command-line installers.

Windows.bat installs the matching Windows executable into the standard WindowsApps command-line location.
MacOS. is extensionless, uses sudo when needed, and installs /usr/local/bin/archaeologist with mode 0755.
Linux. is extensionless, uses sudo when needed, and installs /usr/local/bin/archaeologist with mode 0755.

The Windows installer expects the Windows binary beside it; the macOS/Linux installers fetch their native release binary over HTTPS.
