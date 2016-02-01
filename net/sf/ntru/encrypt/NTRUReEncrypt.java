/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.sf.ntru.encrypt;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import net.sf.ntru.polynomial.DenseTernaryPolynomial;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;
import net.sf.ntru.polynomial.ProductFormPolynomial;
import net.sf.ntru.polynomial.SparseTernaryPolynomial;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class NTRUReEncrypt {

    static boolean out = false;

    public static void main(String[] args) throws IOException {
        out = false;
//        int nReencryptions = testMultihop();
//        System.out.println("nReencryptions = " + nReencryptions);


        testParameters();



//        int c = 0;
//        while(test()>0){
//            
//            c++;
//            if(c%1000==0) System.out.println(c);      
//        }
//        System.out.println(c);
    }

    private static Polynomial generateBlindingPoly(byte[] seed, EncryptionParameters params) {
        int N = params.N;
        IndexGenerator ig = new IndexGenerator(seed, params);

        if (params.polyType == EncryptionParameters.TernaryPolynomialType.PRODUCT) {
            SparseTernaryPolynomial r1 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr1);
            SparseTernaryPolynomial r2 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr2);
            SparseTernaryPolynomial r3 = SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr3);
            return new ProductFormPolynomial(r1, r2, r3);
        } else if (params.sparse) {
            return SparseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr);
        } else {
            return DenseTernaryPolynomial.generateBlindingPoly(ig, N, params.dr);
        }
    }

    private static IntegerPolynomial plainEncrypt(IntegerPolynomial m, EncryptionPublicKey pub, EncryptionParameters ep) {
        Polynomial r = generateBlindingPoly(new byte[]{1, 2, 3, 4}, ep); // oid es cualquier cosa

        IntegerPolynomial e = r.mult(pub.h);
        e.add(m);
        e.ensurePositive(ep.q);
        return e;
    }

    public static int test() {
        int N = 11, q = 32, df = 3; //, df1, df2, df3;
        //int dr, dr1, dr2, dr3, dg, llen, maxMsgLenBytes, db = 0, bufferLenBits, bufferLenTrits, dm0 = 0, maxM1 = 0, pkLen, c = 0, minCallsR = 0, minCallsMask = 0;
        int db = 0, dm0 = 0, maxM1 = 0, c = 0, minCallsR = 0, minCallsMask = 0;

        byte[] rubbish = {15, 06, 07};
        boolean fastFp = true, hashseed = true, sparse = true;

        EncryptionParameters ep = EncryptionParameters.APR2011_743_FAST;

//        EncryptionParameters param = new EncryptionParameters(
//                N, q, df, dm0, maxM1, db, c, minCallsR, minCallsMask, 
//        
//                hashseed, oid, sparse, fastFp, "SHA-256");

        //N = 439, q = 2048, df = 9, dm0 = 8, maxM1 = 5, db = 130, c = 126, minCallsR = 128, 12, 32, 9, 
        //true, new byte[] {0, 7, 101}, true, true, "SHA-256"


        NtruEncrypt ntru = new NtruEncrypt(ep);
        N = ep.N;
        q = ep.q;
//        NtruEncrypt ntru = new NtruEncrypt(param);

        out("N = " + N);
        out("q = " + q);

        EncryptionKeyPair kpA = ntru.generateKeyPair();
        EncryptionPublicKey pubA = kpA.getPublic();



        IntegerPolynomial hA = pubA.h.toIntegerPolynomial();
        int[] hs = hA.coeffs;

        out("h = " + Arrays.toString(hs));

        EncryptionPrivateKey privA = kpA.getPrivate();


        IntegerPolynomial t = privA.t.toIntegerPolynomial();


        out("t = " + Arrays.toString(t.coeffs));

        IntegerPolynomial one = new IntegerPolynomial(N);
        one.coeffs[0] = 1;
//        out("p = " + Arrays.toString(p1.coeffs));

        IntegerPolynomial fA = privatePolynomial(privA);
        out("f = " + Arrays.toString(fA.coeffs));

        IntegerPolynomial fmod3 = fA.toIntegerPolynomial();
        fmod3.mod3();

        out("f mod 3 = " + Arrays.toString(fmod3.coeffs));

        IntegerPolynomial fp = privA.fp.toIntegerPolynomial();
        out("fp = " + Arrays.toString(fp.coeffs));



        EncryptionKeyPair kpB = ntru.generateKeyPair();
        EncryptionPublicKey pubB = kpB.getPublic();
        EncryptionPrivateKey privB = kpB.getPrivate();

        IntegerPolynomial fB = privatePolynomial(privB);



//        ReEncryptionKey rk = new ReEncryptionKey(privA, privB);

//        IntegerPolynomial checkA = rk.rk.mult(one)
        IntegerPolynomial rk = fA.mult(fB.invertFq(q));


        out("rk = " + Arrays.toString(rk.coeffs));


        IntegerPolynomial m = message(rubbish, ep);

        // Encrypt


        IntegerPolynomial eA = plainEncrypt(m, pubA, ep);

        out("eA = " + Arrays.toString(eA.coeffs));





        IntegerPolynomial aA = eA.toIntegerPolynomial().mult(fA);
        aA.modCenter(q);
        out("a  = " + Arrays.toString(aA.coeffs));

        IntegerPolynomial mA = aA.toIntegerPolynomial();
        mA.mod3();
        out("mA = " + Arrays.toString(mA.coeffs));

        if (Arrays.equals(m.coeffs, mA.coeffs)) {
            out("eA : Encryption & Decryption Success!");
        } else {
            out("eA : Decryption failure :(");
            return -1;
        }

        IntegerPolynomial eB = eA.toIntegerPolynomial().mult(rk);
        eB.ensurePositive(q);
        out("eB = " + Arrays.toString(eB.coeffs));

        IntegerPolynomial aB = eB.toIntegerPolynomial().mult(fB);
        aB.modCenter(q);
        out("aB  = " + Arrays.toString(aB.coeffs));

        IntegerPolynomial mB = aB.toIntegerPolynomial();
        mB.mod3();
        out("mB = " + Arrays.toString(mB.coeffs));

        if (Arrays.equals(m.coeffs, mB.coeffs)) {
            out("eB : Encryption, Re-Encryption and Decryption Success!");
            return 1;
        } else {
            out("eB : Decryption failure after re-encryption:(");
            return -2;
        }

    }

    public static int testMultihop(EncryptionParameters ep) {


        int N, q;

        byte[] rubbish = {15, 06, 07};


//        int bitsSec = 128;
//        EncryptionParameters ep = bitsSec == 128
//                ? EncryptionParameters.APR2011_439_FAST // 128 bits
//                : EncryptionParameters.APR2011_743_FAST;    // 256 bits




        NtruEncrypt ntru = new NtruEncrypt(ep);
        N = ep.N;
        q = ep.q;


//        System.out.println("N = " + N);
//        System.out.println("q = " + q);

        EncryptionKeyPair kpA = ntru.generateKeyPair();
        EncryptionPublicKey pubA = kpA.getPublic();



        IntegerPolynomial hA = pubA.h.toIntegerPolynomial();
        int[] hs = hA.coeffs;

        out("h = " + Arrays.toString(hs));

        EncryptionPrivateKey privA = kpA.getPrivate();



        IntegerPolynomial one = new IntegerPolynomial(N);
        one.coeffs[0] = 1;


        IntegerPolynomial fA = privatePolynomial(privA);
        out("f = " + Arrays.toString(fA.coeffs));

        IntegerPolynomial fmod3 = fA.toIntegerPolynomial();
        fmod3.mod3();

        out("f mod 3 = " + Arrays.toString(fmod3.coeffs));

        IntegerPolynomial fp = privA.fp.toIntegerPolynomial();
        out("fp = " + Arrays.toString(fp.coeffs));


        IntegerPolynomial m = message(rubbish, ep);


        /////////////////////////////////////////////////
        /////////////////////////////////////////////////
        // Encrypt
        /////////////////////////////////////////////////
        /////////////////////////////////////////////////

        IntegerPolynomial eA = plainEncrypt(m, pubA, ep);

        out("eA = " + Arrays.toString(eA.coeffs));

        // Decryption of re-encrypted message
        IntegerPolynomial aA = eA.toIntegerPolynomial().mult(fA);
        aA.modCenter(q);
        out("aA  = " + Arrays.toString(aA.coeffs));

        /////////////////////////////////////////////////
        /////////////////////////////////////////////////
        // ReEncrypt
        /////////////////////////////////////////////////
        /////////////////////////////////////////////////

        boolean rencWorks = true;
        int nReEncryptions = 0;
        while (rencWorks && nReEncryptions < 1000) {

            out("ReEncryption " + nReEncryptions);

            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // Key Generation for next user
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////

            EncryptionKeyPair kpB = ntru.generateKeyPair();

            EncryptionPrivateKey privB = kpB.getPrivate();

            IntegerPolynomial fB = privatePolynomial(privB);


            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // RK generation
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////

            IntegerPolynomial rk = fA.mult(fB.invertFq(q));//.mult(T);
            //rk.ensurePositive(q);
            out("rk = " + Arrays.toString(rk.coeffs));

            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // ReEncryption
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////


//            IndexGenerator ig = new IndexGenerator(new byte[]{6, 2, 3, 4}, ep);
//            Polynomial r = SparseTernaryPolynomial.generateBlindingPoly(ig, ep.N, ep.dr);

//            Polynomial r = generateBlindingPoly(new byte[]{6, 2, 3, 4}, ep);

            Polynomial r = generateBlindingPoly(new byte[]{1, 2, 3, 4}, ep); // message(rubbish, ep);

            IntegerPolynomial ruido = r.toIntegerPolynomial();
            ruido.mult(3);
            ruido.modCenter(q);

            out("ruido = " + Arrays.toString(ruido.coeffs));



            IntegerPolynomial eB = eA.toIntegerPolynomial().mult(rk);
            eB.add(ruido);
            eB.ensurePositive(q);
            out("eB = " + Arrays.toString(eB.coeffs));


            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // Decryption of re-encrypted message
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////

            IntegerPolynomial aB = eB.toIntegerPolynomial().mult(fB);


            out("aB  = " + Arrays.toString(aB.coeffs));


            aB.modCenter(q);


            out("aB  = " + Arrays.toString(aB.coeffs));


            IntegerPolynomial mB = aB.toIntegerPolynomial();
            mB.mod3();
            out("mB = " + Arrays.toString(mB.coeffs));



            if (Arrays.equals(m.coeffs, mB.coeffs)) {
                nReEncryptions++;
            } else {
                return nReEncryptions;
            }



            if (nReEncryptions % 100 == 0) {
                System.out.println(nReEncryptions);
            }

            fA = fB;
            eA = eB;
        }
        return Integer.MAX_VALUE;

    }

    public static double[] testVelocidad(EncryptionParameters ep) {



        double difEnc = 0, difDec = 0, difDecR = 0, difRe = 0, difReKey = 0, difKG = 0;

        int N, q;

        byte[] rubbish = {15, 06, 07};


        NtruEncrypt ntru = new NtruEncrypt(ep);
        N = ep.N;
        q = ep.q;

        

        int nCorrecto = 0;
        for (int i = 0; i < 100; i++) {
            IntegerPolynomial m = message(rubbish, ep);

            long t0 = System.nanoTime() / 1000000;
            EncryptionKeyPair kpA = ntru.generateKeyPair();
            EncryptionPublicKey pubA = kpA.getPublic();
            EncryptionPrivateKey privA = kpA.getPrivate();
            IntegerPolynomial fA = privatePolynomial(privA);
            long t1 = System.nanoTime() / 1000000;
            difKG += (t1 - t0);

            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // Encrypt
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////


            t0 = System.nanoTime() / 1000000;
            IntegerPolynomial eA = plainEncrypt(m, pubA, ep);
            t1 = System.nanoTime() / 1000000;
            out("eA = " + Arrays.toString(eA.coeffs));


            difEnc += (t1 - t0);

            // Decryption normal
            t0 = System.nanoTime() / 1000000;
            IntegerPolynomial aA = eA.toIntegerPolynomial().mult(fA);
            aA.modCenter(q);
            aA.mod3();
            t1 = System.nanoTime() / 1000000;
            difDec += (t1 - t0);

            out("aA  = " + Arrays.toString(aA.coeffs));



            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // Key Generation for next user
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////

            EncryptionKeyPair kpB = ntru.generateKeyPair();

            EncryptionPrivateKey privB = kpB.getPrivate();

            IntegerPolynomial fB = privatePolynomial(privB);


            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // RK generation
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////


            t0 = System.nanoTime() / 1000000;
            IntegerPolynomial rk = fA.mult(fB.invertFq(q));//.mult(T);
            //rk.ensurePositive(q);
            t1 = System.nanoTime() / 1000000;
            difReKey += (t1 - t0);

            out("rk = " + Arrays.toString(rk.coeffs));

            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // ReEncryption
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////

            
//            Polynomial r = message(rubbish, ep);
            Polynomial r = generateBlindingPoly(new byte[]{1, 2, 3, 4}, ep); // oid es cualquier cosa

            IntegerPolynomial ruido = r.toIntegerPolynomial();
            ruido.mult(3);
            ruido.modCenter(q);

//            out("ruido = " + Arrays.toString(ruido.coeffs));


            t0 = System.nanoTime() / 1000000;
            IntegerPolynomial eB = eA.toIntegerPolynomial().mult(rk);
            eB.add(ruido);
            eB.ensurePositive(q);
            t1 = System.nanoTime() / 1000000;

            difRe += (t1 - t0);
            out("eB = " + Arrays.toString(eB.coeffs));


            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            // Decryption of re-encrypted message
            /////////////////////////////////////////////////
            /////////////////////////////////////////////////
            t0 = System.nanoTime() / 1000000;
            IntegerPolynomial aB = eB.toIntegerPolynomial().mult(fB);
            aB.modCenter(q);
            IntegerPolynomial mB = aB.toIntegerPolynomial();
            mB.mod3();
            t1 = System.nanoTime() / 1000000;

            difDecR += (t1 - t0);

            out("mB = " + Arrays.toString(mB.coeffs));



            if (Arrays.equals(m.coeffs, mB.coeffs) && Arrays.equals(m.coeffs, aA.coeffs)) {
                nCorrecto++;
            }
        }




        return new double[]{nCorrecto,
                    difEnc / 100, difDec / 100, difDecR / 100, difRe / 100, difReKey / 100, difKG / 100};

    }

    public static void out(String s) {
        if (out) {
            System.out.println(s);
        }
    }

    public static IntegerPolynomial message(byte[] msg, EncryptionParameters ep) {
        // Crea un mensaje aleatorio con dm 0's, dm 1's y dm -1's.
        IntegerPolynomial m = new IntegerPolynomial(ep.N);
        Random rand = new SecureRandom(msg);
        ArrayList<Integer> list = new ArrayList<Integer>();
        while (list.size() < ep.dm0 * 3) {
            Integer i = rand.nextInt(ep.N);
            if (!list.contains(i)) {
                list.add(i);
            }
        }
        for (int j = 0; j < ep.dm0; j++) {
            m.coeffs[list.get(j)] = 0;
        }
        for (int j = ep.dm0; j < 2 * ep.dm0; j++) {
            m.coeffs[list.get(j)] = -1;
        }
        for (int j = 2 * ep.dm0; j < 3 * ep.dm0; j++) {
            m.coeffs[list.get(j)] = 1;
        }
        out("m = " + Arrays.toString(m.coeffs));
        return m;
    }

    public static IntegerPolynomial privatePolynomial(EncryptionPrivateKey priv) {
        IntegerPolynomial one = new IntegerPolynomial(priv.N);
        one.coeffs[0] = 1;

        IntegerPolynomial f = priv.t.toIntegerPolynomial();
        f.mult(3);
        f.add(one);

        return f;
    }

    public static void testParameters() {

        EncryptionParameters[] eps = {
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

        System.out.println("        nC\tenc\tdec\tdecr\tre\treky\tkg");
        for (int i = 0; i < eps.length; i++) {
            out = false;
            EncryptionParameters ep = eps[i];
            ep.fastFp = true; // Para que f = 1 mod p
            try {
                long t0 = System.nanoTime() / 1000000;
                int nR = testMultihop(ep);
                long t1 = System.nanoTime() / 1000000;
//
                double difT = t1 - t0;

                double cicloMs = difT / nR;
//
                System.out.printf("ep[%d]: nR = %d, tiempo ciclo = %02.2f ms \n", i, nR, cicloMs);

//                double[] est = testVelocidad(ep);

//                System.out.printf("ep[%d]: %02.0f\t%02.2f\t%02.2f\t%02.2f\t%02.2f\t%02.2f\t%02.2f\n", i,
//                        est[0], est[1], est[2], est[3], est[4], est[5], est[6]);
//                System.out.printf("%% ep[%d] = %s\n", i, ep);

            } catch (Exception e) {
            }
        }

    }
}
