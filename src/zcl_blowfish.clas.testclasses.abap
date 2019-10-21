*"* use this source file for your ABAP unit test classes
CLASS ltc_blowfish DEFINITION DEFERRED.
CLASS zcl_blowfish DEFINITION LOCAL FRIENDS ltc_blowfish.

CLASS ltc_blowfish DEFINITION FINAL FOR TESTING
DURATION SHORT RISK LEVEL HARMLESS.

  PRIVATE SECTION.

    TYPES: BEGIN OF ty_test,
             key    TYPE xstring,
             clear  TYPE xstring,
             cipher TYPE xstring,
           END OF ty_test.
    DATA: ecb_data TYPE STANDARD TABLE OF ty_test.
    DATA: cbc_data TYPE STANDARD TABLE OF ty_test.
    DATA: iv TYPE xstring.
    METHODS: setup.

    METHODS: encrypt_ecb_test FOR TESTING.
    METHODS: decrypt_ecb_test FOR TESTING.
    METHODS: encrypt_cbc_test FOR TESTING.
    METHODS: decrypt_cbc_test FOR TESTING.

ENDCLASS.

CLASS ltc_blowfish IMPLEMENTATION.

  METHOD setup.
    "more information, see https://www.schneier.com/code/vectors.txt
    ecb_data = VALUE #(
      ( key = `0000000000000000` clear = `0000000000000000` cipher = `4EF997456198DD78` )
      ( key = `FFFFFFFFFFFFFFFF` clear = `FFFFFFFFFFFFFFFF` cipher = `51866FD5B85ECB8A` )
      ( key = `3000000000000000` clear = `1000000000000001` cipher = `7D856F9A613063F2` )
      ( key = `1111111111111111` clear = `1111111111111111` cipher = `2466DD878B963C9D` )
      ( key = `0123456789ABCDEF` clear = `1111111111111111` cipher = `61F9C3802281B096` )
      ( key = `1111111111111111` clear = `0123456789ABCDEF` cipher = `7D0CC630AFDA1EC7` )
      ( key = `0000000000000000` clear = `0000000000000000` cipher = `4EF997456198DD78` )
      ( key = `FEDCBA9876543210` clear = `0123456789ABCDEF` cipher = `0ACEAB0FC6A0A28D` )
      ( key = `7CA110454A1A6E57` clear = `01A1D6D039776742` cipher = `59C68245EB05282B` )
      ( key = `0131D9619DC1376E` clear = `5CD54CA83DEF57DA` cipher = `B1B8CC0B250F09A0` )
      ( key = `07A1133E4A0B2686` clear = `0248D43806F67172` cipher = `1730E5778BEA1DA4` )
      ( key = `3849674C2602319E` clear = `51454B582DDF440A` cipher = `A25E7856CF2651EB` )
      ( key = `04B915BA43FEB5B6` clear = `42FD443059577FA2` cipher = `353882B109CE8F1A` )
      ( key = `0113B970FD34F2CE` clear = `059B5E0851CF143A` cipher = `48F4D0884C379918` )
      ( key = `0170F175468FB5E6` clear = `0756D8E0774761D2` cipher = `432193B78951FC98` )
      ( key = `43297FAD38E373FE` clear = `762514B829BF486A` cipher = `13F04154D69D1AE5` )
      ( key = `07A7137045DA2A16` clear = `3BDD119049372802` cipher = `2EEDDA93FFD39C79` )
      ( key = `04689104C2FD3B2F` clear = `26955F6835AF609A` cipher = `D887E0393C2DA6E3` )
      ( key = `37D06BB516CB7546` clear = `164D5E404F275232` cipher = `5F99D04F5B163969` )
      ( key = `1F08260D1AC2465E` clear = `6B056E18759F5CCA` cipher = `4A057A3B24D3977B` )
      ( key = `584023641ABA6176` clear = `004BD6EF09176062` cipher = `452031C1E4FADA8E` )
      ( key = `025816164629B007` clear = `480D39006EE762F2` cipher = `7555AE39F59B87BD` )
      ( key = `49793EBC79B3258F` clear = `437540C8698F3CFA` cipher = `53C55F9CB49FC019` )
      ( key = `4FB05E1515AB73A7` clear = `072D43A077075292` cipher = `7A8E7BFA937E89A3` )
      ( key = `49E95D6D4CA229BF` clear = `02FE55778117F12A` cipher = `CF9C5D7A4986ADB5` )
      ( key = `018310DC409B26D6` clear = `1D9D5C5018F728C2` cipher = `D1ABB290658BC778` )
      ( key = `1C587F1C13924FEF` clear = `305532286D6F295A` cipher = `55CB3774D13EF201` )
      ( key = `0101010101010101` clear = `0123456789ABCDEF` cipher = `FA34EC4847B268B2` )
      ( key = `1F1F1F1F0E0E0E0E` clear = `0123456789ABCDEF` cipher = `A790795108EA3CAE` )
      ( key = `E0FEE0FEF1FEF1FE` clear = `0123456789ABCDEF` cipher = `C39E072D9FAC631D` )
      ( key = `0000000000000000` clear = `FFFFFFFFFFFFFFFF` cipher = `014933E0CDAFF6E4` )
      ( key = `FFFFFFFFFFFFFFFF` clear = `0000000000000000` cipher = `F21E9A77B71C49BC` )
      ( key = `0123456789ABCDEF` clear = `0000000000000000` cipher = `245946885754369A` )
      ( key = `FEDCBA9876543210` clear = `FFFFFFFFFFFFFFFF` cipher = `6B5C5A9C5D9E0A5A` )
    ).

    iv = 'FEDCBA9876543210'.
    cbc_data = VALUE #(
      ( key = `0123456789ABCDEFF0E1D2C3B4A59687` clear = `37363534333231204E6F77206973207468652074696D6520666F72` cipher = `6B77B4D63006DEE605B156E27403979358DEB9E7154616D9297028778D6F5555` )
    ).

  ENDMETHOD.

  METHOD decrypt_cbc_test.
    LOOP AT cbc_data ASSIGNING FIELD-SYMBOL(<data>).
      DATA(blowfish) = NEW zcl_blowfish( <data>-key ).
      blowfish->set_iv( blowfish->hex_to_byte( iv ) ).
      DATA(string_result) = CONV string( blowfish->byte_to_hex( blowfish->crypt_cbc( text = blowfish->hex_to_byte( <data>-cipher ) decrypt = abap_true ) ) ).
      REPLACE ALL OCCURRENCES OF |00| IN string_result WITH ``.
      data(result) = CONV xstring( string_result ).
      cl_aunit_assert=>assert_equals(
        act = result
        exp = <data>-clear
        msg = 'clear:' && result && '<>' && <data>-clear && '.key: ' && <data>-key
      ).
    ENDLOOP.
  ENDMETHOD.

  METHOD decrypt_ecb_test.
    LOOP AT ecb_data ASSIGNING FIELD-SYMBOL(<data>).
      DATA(blowfish) = NEW zcl_blowfish( <data>-key ).
      DATA(result) = blowfish->byte_to_hex( blowfish->crypt_ecb( text = blowfish->hex_to_byte( <data>-cipher ) decrypt = abap_true ) ).
      cl_aunit_assert=>assert_equals(
        act = result
        exp = <data>-clear
        msg = 'clear:' && result && '<>' && <data>-clear && '.key: ' && <data>-key
      ).
    ENDLOOP.
  ENDMETHOD.

  METHOD encrypt_cbc_test.
    LOOP AT cbc_data ASSIGNING FIELD-SYMBOL(<data>).
      DATA(blowfish) = NEW zcl_blowfish( <data>-key ).
      blowfish->set_iv( blowfish->hex_to_byte( iv ) ).
      DATA(result) = blowfish->byte_to_hex( blowfish->crypt_cbc( text = blowfish->hex_to_byte( <data>-clear ) decrypt = abap_false ) ).
      cl_aunit_assert=>assert_equals(
        act = result
        exp = <data>-cipher
        msg = 'cipher:' && result && '<>' && <data>-cipher && '.key: ' && <data>-key
      ).
    ENDLOOP.
  ENDMETHOD.

  METHOD encrypt_ecb_test.
    LOOP AT ecb_data ASSIGNING FIELD-SYMBOL(<data>).
      DATA(blowfish) = NEW zcl_blowfish( <data>-key ).
      DATA(result) = blowfish->byte_to_hex( blowfish->crypt_ecb( text = blowfish->hex_to_byte( <data>-clear ) decrypt = abap_false ) ).
      cl_aunit_assert=>assert_equals(
        act = result
        exp = <data>-cipher
        msg = 'cipher:' && result && '<>' && <data>-cipher && '.key: ' && <data>-key
      ).
    ENDLOOP.
  ENDMETHOD.

ENDCLASS.
