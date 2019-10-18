# blowfish-abap
Blowfish encryption in ABAP

ABAP Version: 750 or higher

Blowfish encryption (ECB and CBC MODE) as defined by Bruce Schneier here: http://www.schneier.com/paper-blowfish-fse.html

The blowfish-abap is implemented with reference to [C#](https://www.schneier.com/code/blowfish.cs) source code.

## Usage
    DATA(blowfish) = NEW zcl_blowfish( conv #( '04B915BA43FEB5B6' ) ).
    
    DATA(plain)  = 'The quick brown fox jumped over the lazy dog.'.
    DATA(cipher) = blowfish->encrypt_cbc( CONV #( plain ) ).
    plain        = blowfish->decrypt_cbc( cipher ).
    
    cl_demo_output=>display( plain && cl_abap_char_utilities=>newline && cipher ).

## TODO
- [x] Exceptions
- [ ] Tests
- [ ] Support for ABAP 740
