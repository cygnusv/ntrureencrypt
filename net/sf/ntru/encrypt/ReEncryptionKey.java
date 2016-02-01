/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package net.sf.ntru.encrypt;

import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.polynomial.Polynomial;

/**
 *
 * @author David Nuñez <dnunez (at) lcc.uma.es>
 */
public class ReEncryptionKey {
    int N;
    int q;
    

    
    public IntegerPolynomial rk;
    
    

    ReEncryptionKey(EncryptionPrivateKey sk_a, EncryptionPrivateKey sk_b) {
        
        this.N = sk_a.N;
        this.q = sk_a.q;
        
        IntegerPolynomial fA = sk_a.t.toIntegerPolynomial();
        IntegerPolynomial fBinv = sk_b.t.toIntegerPolynomial().invertFq(q);
        
        rk = fA.toIntegerPolynomial().mult(fBinv);
        
        
        
        
        
    }
    
}
