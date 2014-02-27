package IBE;
import java.math.BigInteger;
import java.security.spec.ECPoint;

import IatePair.PairParameter;


public class BF_PKGPublicKey {
   PairParameter param;
   ECPoint       pubPoint;
 
   public BF_PKGPublicKey(PairParameter param,ECPoint   pubPoint){
	   this.param    = param;
	   this.pubPoint = pubPoint;
   }
   public BF_PKGPublicKey(PairParameter param,String pubKey){
	   this.param    = param;
	   String[] point = pubKey.split(",");
	   System.out.println(point[0]);
	   System.out.println(point[1]);
	   System.out.println(pubKey);
	   BigInteger X = new BigInteger(point[0],16);
	   System.out.println(X);
	   BigInteger Y = new BigInteger(point[1],16);
	   System.out.println(Y);
	   this.pubPoint = new ECPoint(new BigInteger(point[0],16),new BigInteger(point[1],16));
   }
   public  PairParameter getPairParameter(){
	   return this.param;
   }
   
   public ECPoint getPubPoint(){
	   return this.pubPoint;
   }
   public String getPubString(){
	   return pubPoint.getAffineX().toString(16)+","+
			   pubPoint.getAffineY().toString(16);
   }
}
