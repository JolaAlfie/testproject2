# PCCA Virtual Smart Card (Android)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Build Status](https://travis-ci.org/JolaAlfie/testproject2.svg?branch=master)](https://github.com/JolaAlfie/testproject2)

PCCA Virtual Smart Card (Android) is a software module that leverages the hardware secure enclave in smartphones to store and operate transient private keys. It offers functionalities such as

- Generating transient private keys in the hardware secure enclave;
- Generating the corresponding CSRs;
- Obtaining the corresponding [PCCA](https://pcca.proof.show) certificates;
- Signing digital digests using the transient private keys; and
- Wiping out the transient private keys.

### Requirement

* Android SDK 23.0+

### How to use

1. Download this project

2. Build the library using following command

##### On Windows
```
gradlew.bat build
```

##### On macOS/Linux
```
./gradlew build
```

3. Make the library file part of your project

### License

AGPL-3.0-or-later
