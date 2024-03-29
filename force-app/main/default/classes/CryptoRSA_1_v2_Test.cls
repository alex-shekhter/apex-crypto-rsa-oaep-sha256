@IsTest
private class CryptoRSA_1_v2_Test {

  private static final String CLEAR_TEXT = 'Some UTF-8 text to be encrypted!\n';

  private static final String modulus1024 = '00946b1fc6fd8ce669f665bf35f35ee5c23c24910525763ec9e001fcda26c1fe5543e5c38f0cd3520a9e67114f3d0f06c5985a42d4b5669e5562a07c292fae9a4539ca45de7ebac0cf065369e0c0e06a9f84ae16bc7398cf4533b443acd79ae303e77f160a5510a7398ae00a60defc65f29d457fc13a72c75efb3e7408aa92a3f1';
  private static final String publicExponent1024 = '10001';
  private static final String privateExponent1024 = '2043b571c5d6e6942c7b6bf8e7823ec25ddeb923fc43db5c79751529bb793ab8007da768a6aa1dd0af24cacf85ff8942555f71ddd9dd881819cbb792208a7d80b0505af820bc4a3b6f5472deddfd11e48063b593388da6d2ca2d47c840bf2ccc27cb8381182b5b7e8db3329e3508b995c3345166c4d0d044f644e8a9a476d511';
  private static final String encryptedText1024 = 'fGlTYmWlHkCaUDlUD2F5SgqTSx8cGGWh1+cXK2PyY/o9Qssd55X61fYWc7sX+BeHTxOiNf17wtw1iV65+hG3hQXLUmnmCKJE5gRJEqZSG1UjEHQ5Zb7gADUQUo+7KaIWHE8bYfgGfGG78wBhC+T8IApqj/b1FmeOzB/3/abJwLw=';

  private static final String modulus2048 = '00ad72a0bc3501b50684365df7ce08da00bf0e56d3bcd1edf71aed75400045c878703b624bf9d8e046389fa83b1ffb9b87f3c7a6c065848b5078f82b4533c08240d11547bbb975cc47ef9cfe148f0f3e9e4c148607d7dd91165c9791e02734d4663ca5d183e3cd234210951f23c6af56b7e8d2ba11eb1ddb30e62fd4094d985ad8159cb4565192e17ef829909491b3e6856a6ce909f7f5b86c6541f90bb4bf1c00f213e1caf2d8ae3e42600df19d8a436010d55cd5688557062964f74bb2a196b7af4c8d3efb94ec46d2414d113325918ddfd371c88b9581270e8ba199d038187ac6c33289efcca9c1a3c5b80ddd1ebf8ef3fe5c3caa47581d1a2958823f2cbc49';
  private static final String publicExponent2048 = '10001';
  private static final String privateExponent2048 = '02d6fa9cba3d71ea4e65d97a022c90ed2c339ee64e941d524b6591e2df5e451efbaf6d37933aa2c96389f1a62e2adf6c0568c2692a00568b95bf726dea9fff41f26a67c7420d14b024d32c31c7f9d6eb9e914374836b4441da783cd22fb224bc1bc8173b1292bc3e0ba9755e0f95b554c38217bbcd5eaac50d2fc147f9b641de7ae55ba578cd256f58401f1b80176bf8f2dbe16830dcbdd1c29354d64b618a30c3a3857a37c4f07fcd8db2becb517f294ba19b6d59a692b33753eb387a7b7ef910d346b97447ce69c63abf22213d10de331ba16b17cece840a9689297c807e66b8ceedbd936b357ec83776972593cb875f3c5b02a241f5f4fc3d4a391c7a2745';
  private static final String encryptedText2048 = 'cNwn8g6JFlzI9tGF0LNJHOMnd63hqDTw+lmqRzgC/7C1LJbSSlguVNQPlRvfU/txc5qndmdKyhhTfItnoIOdxDFGXaicYdEttjpauycPBx/lEtbDDTsmEhL4AjPzc/uOQtg8R/MTrpFIvaRdgevbjEDpsQ83ZREpQDfLw3bizE1oQGhRPNAqdlwu878ENwoDuQw3/ZsTGSyetlIDoh/1HRecKjTY1bBWIsW0njJYOVKER11MgUU+KRw86HmLaaa+PxqmonI0vjS1O1eV4AWX0YLvtHHaujHWSrch9PoltjD9YXKSxcRud4oL3mS0gDt9NBTc0k7bo1O0UFn0lNzMRQ==';

  private static final String modulus4096 = '00af5c6fd1a30ffa60c9a99c0560c867af2600acfa6ca71fa37c95a17e58cb627f62ead2234063ef68a10b1fefb5cb37dd9c455ba97a23609a6363002f304e94a58f720ff7548c12fde55c44c0d21d9f19938ed0cfa244e186981fd5f2c43215e4f8765e48410ac327c550fb63c230d2800b420c990f1c5a4b4f70df45336cf784cef215c80c618b2171bfa36b36a7dd491ce2b1a5a924d88f7265371e9f80bc36c7ddeaf887389cda332d130978ad64ed59aa663ff0ad77078f9ba6ec8c77dab669fac2e85f7ee8bdd745f6b1ec03df35a83bd23c9087e47d6a199f8c5f147121f4cfae8463e14acbe8500975fb1d15097e983c71f68f18eac948b9956034383ce96caeb36c65a6cf01c4df406ea84b5daa0d8e5fe48c588d7c1dd19cd3b603d1b8bf6165246b337f7efe06d48f303622641e8099a85fd6079338fa1d74f1ce04b6d70939ca83b0013ea446817c93912e6ac21251ea6deae15014e2730e45baed883b18149e28c02c6aa2bc17af090e5180dc7ff8bdd06256d2c4a8bf4961c80faffe4b35db818d498838c08d80834cd35719664108950d0b0019db6dbed33b791c608aab514973a905666ebb571ed562189b3be3f7183b3ec464748f984ece7baa1aaff0e0407df1b2ffdd05c7f43cec52e55631ea55a26ca5a0b3150cf3d42fddbb5b554beaad5cc3c85598a7514f37d8ab36ec111d7ab1e1f22600b13d8511';
  private static final String publicExponent4096 = '10001';
  private static final String privateExponent4096 = '4f4d80bdefbd8a8f99b32bbd1ce3144c976587d46a2d7bf7dd9ff75be180fca6ba0f927f619fb005838ab9e31835f22a3481032e55ef48c119000cf5ca254740c5e9a1c1ca88dc0fd8d90cb89c6ccbe5ef9e8edccf37d23ba171083a94b247c777fb63b0ce453533379ee348de6960d08a06d116a8c83c2741a23c3e19bf060297e9cfa2dbc282fe5967fe59be6a547ebb62e34e94faf63a8cd3ac051bc1c69c096fd8d292a82dfad958e17a8f89ee920dd22b12705fa9ec0fec26a563f2d1c45b920cf1b439fabbdb6e26dd986bb9d614a214f5d1b0baca62a07ad02ab15e662a457f591ca82640a76b069445bf05a3f90d948c3f21c075711883e0c3146a779483e46857ca5412d3a2a85190f1380e5093e13030a7842538c08bbaf2e13698ff91291696f132d66799bb7e699aa4ee29261e7df897762e9caad3b2e77d0cc9796253c117705fa487bf4c19f702b00a7102cd8de32aff2652356d59cf3b98b176fb1bfce7d759894a67496a1a5746db507c4362cef2fc2f9cc42ecad6d7250f09df7899c9b81dfee5aaccf7fc8014dd95673dca24e8c8917ed18def757fcae1f00736d675bb6f3114b31cd8da3b894b123f8b2940c452361e39f6fa0021a97f310fe1fe10a5fd13faf375beb28c93626b5e4fb7df03d82bc9c21e0e7ff5a4a3d5b174c4184a397fe4174bcae8ee73c003c594d79835c6cb3bdb0aad5bc16667';
  private static final String encryptedText4096 = 'jkHJV1WJjaNIgCfd//PfNy1sKyH1GqsmhdsrEyxBDKs6oUfQoM/aU8MG5oKkfubFq2afHJIzn+x4uhj8C1cjvYgCMY/16YYNuBAqOVg6j28cy7N2HNAAwCjt0UlcITgbT7jalTj4hvu0r8x9VmTVQuXe80FW9L12TrL1CWuLmj5AchZfqeZ+zGj6NPZCkGelmadpH7s9w+6ZxZ3tOo3ce+LptN6AjKHGE1OHGEMHCahdxtNDp3uOf7CdzJL/Di11hexJejY76XGNpuTzufZlGaWg6enkAvTP1+lc1Ie4U6Js7IrxcI0d6HF2TSEgir6V5ZtfIFk82mTR6ItTbB4BHx6aGkJ0xOLuGf0UEioEW9LMtXXh1EAtQvSmmIGry9MPZTBM6jHYErc6JAJPEB8o1I6UwRqobqFimUl5UnlhMThGzsJDJF9kRQG0JDTGyU1IOnNyJUw5f3efJHQJY+8vKldP1BHyuxKpyhdXzEcklVxAc2PEJd2rsoDGqw8O+YNmdaZ6PfDiyHBLK1fb4H8sy0PjPtfjMQ6c1an7CvKbT2U0hlKapwq4lJGr9mh994Fob09avnVNhNZpRv1tZDukSMzWyrBka152Y/WPXipVIuz8T8NzCpRJkqzOVQeQq1YmlmRkNwrgAQnxHhh8WDseIw4koJsp+YcmyGfWds37uTo=';

  private static final String modulus = modulus1024;
  private static final String publicExponent = publicExponent1024;
  private static final String privateExponent = privateExponent1024;
  private static final String encryptedText = encryptedText1024;

  @IsTest
  public static void testDecryptionSunny() {
    Test.startTest();
    CryptoRSA_1_v2.Key key = new CryptoRSA_1_v2.Key(
      modulus, publicExponent, privateExponent
    );
    CryptoRSA_1_v2 rsa = new CryptoRSA_1_v2( key );
    String clearText = rsa.decrypt( encryptedText );
    Test.stopTest();

    System.assert( CLEAR_TEXT.equals( clearText ), 'Encryption test failed' );
  }

  @IsTest
  public static void testEncryptDecryptSunny() {
    Test.startTest();
    CryptoRSA_1_v2.Key key = new CryptoRSA_1_v2.Key(
      modulus, publicExponent, privateExponent
    );
    CryptoRSA_1_v2 rsa = new CryptoRSA_1_v2( key );
    String cipherText = rsa.encrypt( CLEAR_TEXT );
    String clearTxt = rsa.decrypt( cipherText );
    Test.stopTest();
    System.assert(
      CLEAR_TEXT.equals( clearTxt ), 
      'Encrypt/Decrypt test failed: cipherText: ' + cipherText + '; clearText: ' + clearTxt 
    );
  }
}
