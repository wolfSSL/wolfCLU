# wolfCLU v0.0.8 (Mar 04, 2022)
### Commands Added
- Add rand command
- Add PKCS12 parsing support and command
- Add a basic s_client command for simple TLS client connections
- Add support for x509 verify command
- Add initial rsa command support
- Add CRL verify command
- Add ca command
- Add dsaparam command
- Add sha hash commands (sha256, sha384, sha512)
- Add dhparam command

### Fixes and Enhancements
- Support for parsing multiple organization names with conf file
- Set the default certificate request version to 3
- Add print out of private key to PKEY command
- Added support for -nosalt option
- Fix for RSA free with dgst command
- Testing with FIPS 140-3 wolfCrypt
- Add -subj support to req command
- Fix for -base64 with enc
- Fix for piping errors to stderr instead of stdout
- Removed testing-certs directory in favor of certs directory
- Fix for handling large file sizes with dgst and hash command
- Expanded req command to handle -text, -noout, -extensions and -verify
- Expanded x509 command to handle -subject, -issuer, -serial, -dates, -email, -fingerprint, -purpose, -hash
- Added -text support to ecparam command
- Added support for -sign with dgst command
- Tied in github actions for continuous integration testing
- Added support for creating encrypted private keys with -newkey


# wolfCLU v0.0.6 (Nov 09, 2021)

- Add ecparam for ECC key generation with parameters
- Refactoring of directory names for source and include
- Refactor return values to use WOLFCLU_SUCCESS
- Add a logging function for printing messages
- Add PEM key generation for ECC
- Add support for parsing a config file when creating a certificate or CSR
- Refactor all file calls to use XFILE wrapping
- Refactor strncmp and other system calls to use the X* wrapping
- Formatting on if else newlines throughout wolfCLU
- Change the name of bundle created with 'make dist'
- Add some error print outs and checking with FIPS builds
- Add check for warnings (Wall) as errors and the resulting fixes
- Static analysis tools ran to test code quality and resulting fixes
- Refactoring on ECC key generation
- Changed padding scheme in encrypt and decrypt to interop
- Add WOLFCLU to variable names and macros
- Add pkey command
- Update to req command and expanding its capabilities
- Add md5 command for creating legacy md5 hashes
- Add public key print out
- Convert parsing of input commands to not require '-' in front of them i.e './wolfssl -x509' now can be './wolfssl x509'
- Add check for libwolfssl to autotools with configure
- Add --with-wolfssl option to configure to specify location of wolfSSL library
- Updates to dgst verify command and testing
