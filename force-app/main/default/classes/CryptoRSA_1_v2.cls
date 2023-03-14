/**
 * RSA#1 version 2 assymetric encryption/decryption implementation
 * with OAEP padding and SHA-256 by default
 */
public inherited sharing class CryptoRSA_1_v2 {

    public class CryptoRSA_1_v2_Exception extends Exception {} 

    private inherited sharing class KeyPart {
        public Blob blb;
        public String hexStr;
        public Decimal dec;

        public KeyPart( String partHexStr ) {
            if ( !String.isBlank( partHexStr ) ) {
                blb = Blob.valueOf( partHexStr );
                hexStr = partHexStr;
                dec = hexToDecimal( hexStr );
            }
        }

        public override String toString() {
            String res;
            if ( blb != null ) {
                res = 'KeyPart: blb=' + EncodingUtil.convertToHex( blb ) 
                    + '; dec=' + dec + '; hexStr=' + hexStr;
            }
            else {
                res = 'KeyPart: blb=null; dec=null; hexStr=null';
            }
            return res;
        }
    }

    public inherited sharing class Key {
        private KeyPart modulus;
        private KeyPart publicExponent;
        private KeyPart privateExponent;

        public Key(String modulus, String publicExponent, String privateExponent ) {
            this.modulus = new KeyPart( modulus );
            this.publicExponent = new KeyPart( publicExponent );
            this.privateExponent = new KeyPart( privateExponent );
        }

        // k in RFC
        public Integer modulusLenOctets() {
            return modulus.hexStr.length() / 2 - 1;
        }
    }

    // Hex digits
    private static final String DIGITS = '0123456789abcdef';
    private static final Decimal HEX_BASE = 16;
            
    private Key key;
    private String label;
    private Blob lHash;
    private String hashAlgo;

    public CryptoRSA_1_v2(Key key) {
        this.key = key;
        this.label = '';
        this.hashAlgo = 'SHA-256';
        init();
    }

    public CryptoRSA_1_v2(Key key, String label) {
        this.key = key;
        this.label = label;
        this.hashAlgo = 'SHA-256';
        init();
    }

    public CryptoRSA_1_v2(Key key, String label, String hashAlgo ) {
        this.key = key;
        this.label = label;
        this.hashAlgo = hashAlgo;
        init();
    }

    private void init() {
        lHash = Crypto.generateDigest( hashAlgo, Blob.valueOf( label ) );
    }

    private Integer hLen() {
        return lHash.size();
    }

    /**
     * Encrypts input UTF-8 string using PKCS 1 v2 (RSA-OAEP-SHA256) assymetric encryption
     * 
     * @param - UTF-8 encoded clear text to be encrypted
     * @return - Base64 encoded cipher text
     */
    public String encrypt(String input) {
        String oaepInput = oaepEncode(input);

        String msg = os2ip( oaepInput );

        Decimal result = modPow( hexToDecimal( msg ), key.publicExponent.dec, key.modulus.dec);
        
        String hexResult = decimalToHex(result);

        Blob encodedData = EncodingUtil.convertFromHex(hexResult);
        
        return EncodingUtil.base64Encode(encodedData);
    }

    private String oaepEncode( String input ) {
        Blob pn = Blob.valueOf(input);
        String pnHex = EncodingUtil.convertToHex( pn );
        Integer k = key.modulusLenOctets();

        if ( pn.size() > k - hLen() - 2 ) {
            throw new CryptoRSA_1_v2_Exception( 'Data for encryption too large' );
        }

        // pad
        String ps = '00'.repeat( k - pn.size() - 2 * hLen() - 2);

        String db = EncodingUtil.convertToHex( lHash ) + ps + '01' + pnHex;

        // Calculate random seed
        Integer min = 0, max = DIGITS.length(), max_minus_min = max - min;
        String[] digs = DIGITS.split( '' );
        String seed = '';
        for ( Integer i = 0, up = hLen() * 2; i < up; i++ ) {
            seed += digs[ (Integer)((Math.random() * max_minus_min) + min) ];
        }

        String dbMask = mgf1( seed, k - hLen() - 1, hashAlgo, hLen() );

        String maskedDb = xor( db, dbMask );

        String seedMask = mgf1( maskedDb, hLen(), hashAlgo, hLen() );

        String maskedSeed = xor( seed, seedMask );

        return '00' + maskedSeed + maskedDb;
    }

    /**
     * Decrypt Base64 encoded cipher text using PKSC_1_v2 (OAEP)
     * 
     * @param - b64EncodedInput - base64 encoded cipher text
     * @return - UTF-8 encoded clear text 
     */
    public String decrypt(String b64EncodedInput) {
        String decrStr = modPowDecrypt( b64EncodedInput );

        return oaepDecode( decrStr );
    }
    
    
    private String modPowDecrypt(String input ) {
        
        Blob pn = EncodingUtil.base64Decode(input);

        Decimal pnDec = hexToDecimal(EncodingUtil.convertToHex(pn));
        
        Decimal result = modPow(pnDec, key.privateExponent.dec, key.modulus.dec);

        String hexResult = decimalToHex(result);

        hexResult = os2ip( hexResult );

        return hexResult;
    }
    
    private String oaepDecode( String rawDecrResHexStr ) {
        Integer clen = rawDecrResHexStr.length() / 2;

        String maskedSeed = rawDecrResHexStr.substring( 2, (1 + lHash.size()) * 2 );

        String maskedDb = rawDecrResHexStr.substring( (1 + lHash.size()) * 2 );

        String seedMask = mgf1( 
            maskedDb, lhash.size(), hashAlgo, lHash.size()
        );

        String seed = xor( maskedSeed, seedMask );

        Integer k = key.modulusLenOctets();

        String dbMask = mgf1( seed, k - lHash.size() - 1, hashAlgo, lHash.size() );
        
        String db = xor( maskedDb, dbMask );

        return extractClearText( db, lHash );
    }

    private String extractClearText( String db, Blob lHash ) {
        final Integer hLen = hLen() * 2; // 2 chars per byte
        final String lHashDb = db.substring( 0, hLen );
        if ( lHashDb != EncodingUtil.convertToHex( lHash ) ) {
            throw new CryptoRSA_1_v2_Exception( 'Decryption failed. Hashes are not equal...' );
        }

        String result = '';

        Integer i = hLen;
        while ( i < db.length() ) {
            String b = db.substring( i, i + 2 );
            if ( b == '00' ) {
                i += 2;
                continue;
            }
            else if ( b == '01' ) {
                i += 2;
                break;
            }
            else {
                throw new CryptoRSA_1_v2_Exception( 'Decryption failed. Unexpected data...' );
            }
        }

        result = db.substring( i );

        return blobToString( result, 'UTF-8' );
    }

    private static String[] splitHexStr( String s1 ) {
        String[] res = new String[ s1.length() / 2 ];
        for ( Integer i = 0, j = 0; i < s1.length(); i += 2 ) {
            res[ j++ ] = s1.substring( i, i + 2 );
        }
        return res;
    }

    private static String xor( String data, String mask ) {
        String[] dataParts = splitHexStr( data );
        String[] maskParts = splitHexStr( mask );
        
        Integer dataSz = dataParts.size();
        Integer maskSz = maskParts.size();

        String xorStr = '';
        for ( Integer i = 0, sz = Math.max( dataSz, maskSz ); i < sz; i++ ) {
            
            String h = '';
            
            if ( i < dataSz && i < maskSz ) {
                Integer i1 = hexToDecimal( dataParts[ i ] ).intValue();
                Integer i2 = hexToDecimal( maskParts[ i ] ).intValue();
                Integer x = i1 ^ i2;
                h = decimalToHex( x );
            }
            else if ( i < dataSz ) {
                h = dataParts[ i ];
            }

            xorStr += h;
            
            if ( String.isBlank( h ) ) {
                break;
            }
        }

        return xorStr;
    }

    private static String blobToString(String hex, String inCharset)
    {
        System.assertEquals(0, hex.length() & 1);
        
        final Integer bytesCount = hex.length() >> 1;
        String[] bytes = new String[bytesCount];
        
        for(Integer i = 0; i < bytesCount; ++i) {
            bytes[i] =  hex.mid(i << 1, 2);
        }
        
        for(Integer i = bytesCount-1; i >= 0; i--) {
            
            if (bytes[i].equals('00')) {
                List<String> bytesTemp = new List<String>();
                
                for(Integer j = i; j < bytesCount; j++)
                {
                    bytesTemp.add(bytes[j]);
                }
                
                bytes = bytesTemp;
                
                break;
            }
        }
        
        return EncodingUtil.urlDecode('%' + String.join(bytes, '%'), inCharset);
	}

    @testVisible
    private static Decimal hexToDecimal(String hex) {
        Decimal result = 0;
        integer length = hex.length();
        integer i = 0;
        while(i < length) {
            integer hexByte = DIGITS.indexOf(
                hex.substring(i, i + 1).toLowerCase()
            );
            i++;
            result += hexByte * HEX_BASE.pow(length - i);
        }
        return result;
    }

    @testVisible
    private static String decimalToHex(Decimal d) {
        String hex = '';
        while (d > 0) {
            // Decimal digit = modulus(d, HEX_BASE); // rightmost digit
            Decimal digit = d - d.divide( HEX_BASE, 0, RoundingMode.FLOOR ) * HEX_BASE;
            hex = DIGITS.substring(digit.intValue(), digit.intValue() + 1) + hex; // string concatenation
            d = d.divide(16, 0, RoundingMode.FLOOR);
        }
        if ( String.isBlank( hex ) ) {
            hex = '00';
        }
        else if ( (hex.length() & 1) == 1 ) {
            hex = '0' + hex;
        }
        return hex;
    }

    // base^exp % mod
    @testVisible
    private static Decimal modPow(Decimal base, Decimal exp, Decimal mod) {
        if (base < 1 || exp < 0 || mod < 1) {
            return -1;
        }

        Decimal result = 1;
        while (exp > 0) {
           if ((exp.longValue() & 1) == 1) {
                // result = modulus((result * base), mod);
                Decimal dividend = result * base;
                result = dividend - dividend.divide(mod, 0, RoundingMode.FLOOR) * mod;
            }
            // base = modulus((base * base), mod);
            Decimal dividend = base * base;
            base = dividend - dividend.divide(mod, 0, RoundingMode.FLOOR) * mod;
            exp = exp.divide(2, 0, RoundingMode.FLOOR);
        }
        return result;
    }

    // dividend % divisor
    // not used during decryption
    // since inlining saves more then 1 second during decryption
    @testVisible
    private static Decimal modulus(Decimal dividend, Decimal divisor) {
        Decimal d = dividend.divide(divisor, 0, RoundingMode.FLOOR);
        return dividend - (d * divisor);
    }

    /**
     * Returns hex string length l bytes of the input integer "i" 
     */
    private static String i2osp( Decimal i, Integer l ) {
        String res = decimalToHex( i );
        Integer resLen = res.length();
        Integer trgLen = l * 2;
        if ( trgLen > resLen ) {
            res = '0'.repeat( trgLen - resLen ) + res;
        }
        return res;
    }

    /**
     * @param - c - hex string to be enlarged 
     * @return hex String representing Decimal  
     */
    private String os2ip( String c ) {
        Integer k = key.modulusLenOctets();
        Integer repeat = k - c.length() / 2;
        String res = c;
        if ( repeat > 0 ) {
            res = '00'.repeat( repeat ) + c;
        }
        return res;        
    }

    /**
     * MGF1 using different algorithms
     * 
     * @return mask
     */
    private static String mgf1( String seedHexStr, Integer length, String algo, Integer hashLen ) {
        Blob res;

        Decimal hLen = (Decimal)hashLen;

        if ( length > (hLen.longValue() << 32) ) {
            throw new CryptoRSA_1_v2_Exception( 'Mask is too long' );
        }

        String T = '';
        Integer counter = 0;

        Decimal lim = Math.ceil( length / hLen );

        while (  counter < lim.intValue() ) {
            String C = i2osp( counter, 4 );
            String combinedSeedHexStr = seedHexStr + C;
            T += EncodingUtil.convertToHex( 
                Crypto.generateDigest( algo, EncodingUtil.convertFromHex( combinedSeedHexStr ) )
            );
            counter++;
        }

        T = T.substring( 0, length * 2 );

        return T;
    }
}
