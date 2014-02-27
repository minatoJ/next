package IBE;
import java.math.BigInteger;

import IatePair.PairParameter;


public class BF_PKGPrivateKey {
	   PairParameter param;
	   BigInteger    masterKey;
	 
	   public BF_PKGPrivateKey(PairParameter param,BigInteger  masterKey){
		   this.param     = param;
		   this.masterKey = masterKey;
	   }
	   
	   public  PairParameter getPairParameter(){
		   return this.param;
	   }
	   
	   public BigInteger getMasterKey(){
		   return this.masterKey;
	   }
}
