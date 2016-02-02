/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.ntrureencrypt;

import java.util.Arrays;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.polynomial.IntegerPolynomial;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class TestNTRUReEncrypt {

    static EncryptionParameters[] eps = {
        EncryptionParameters.EES1087EP2, //0
        EncryptionParameters.EES1087EP2_FAST, //1
        EncryptionParameters.EES1171EP1, // 2
        EncryptionParameters.EES1171EP1_FAST, // 3
        EncryptionParameters.EES1499EP1, // 4
        EncryptionParameters.EES1499EP1_FAST, // 5
        EncryptionParameters.APR2011_439, // 6
        EncryptionParameters.APR2011_439_FAST, // 7
        EncryptionParameters.APR2011_743, // 8
        EncryptionParameters.APR2011_743_FAST // 9
    };

    public static void main(String[] args) throws Exception {
        test1();
        test2();
    }

    public static void test1() throws Exception {

        EncryptionParameters ep = eps[3];   // EES1171EP1_FAST

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(ep);

        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();

        IntegerPolynomial m = ntruReEnc.message(new byte[]{12,34,56});

        IntegerPolynomial c = ntruReEnc.encrypt(kpA.getPublic(), m);

        IntegerPolynomial m2 = ntruReEnc.decrypt(kpA.getPrivate(), c);


        if (Arrays.equals(m.coeffs, m2.coeffs)) {
            System.out.println("Test 1 OK!");
        } else {
            System.out.println("Test 1 Failed!");
        }
    }
    
    public static void test2() throws Exception {

        EncryptionParameters ep = eps[3];   // EES1171EP1_FAST

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(ep);

        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();

        IntegerPolynomial m = ntruReEnc.message(new byte[]{12,34,56});

        IntegerPolynomial c = ntruReEnc.encrypt(kpA.getPublic(), m);
        
        EncryptionKeyPair kpB = ntruReEnc.generateKeyPair();

        ReEncryptionKey rk = ntruReEnc.generateReEncryptionKey(kpA, kpB);
        
        IntegerPolynomial cB = ntruReEnc.reEncrypt(rk, c);
        
        IntegerPolynomial m2 = ntruReEnc.decrypt(kpB.getPrivate(), cB);


        if (Arrays.equals(m.coeffs, m2.coeffs)) {
            System.out.println("Test 2 OK!");
        } else {
            System.out.println("Test 2 Failed!");
        }
    }
}
