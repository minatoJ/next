package IBE;
import java.math.BigInteger;
import java.security.spec.ECPoint;

import IatePair.ECCp;
import IatePair.PairParameter;
import IatePair.TatePair;

//wota
public class PKG {
  
  PairParameter ECCParam;
  ECPoint pubPoint;
  BigInteger masterKey;
  TatePair   tate;
  public PKG(PairParameter ECCParam,BigInteger masterKey){
	  this.ECCParam  = ECCParam;
	  this.masterKey = masterKey;
	  
	  this.tate      = new TatePair(this.ECCParam);
	  ECPoint g      = tate.getBasePoint1();
	  ECCp ECC_p     = this.tate.getECCp();
	  pubPoint       = ECC_p.multiply(g,masterKey);
	  System.out.println("#####start@参数建立");
	  System.out.println("椭圆曲线方程参数 ");
	  System.out.println("y^2 = x^3 + ax + b");
	  System.out.println("a         = " + ECC_p.getA().toString(16));
	  System.out.println("b         = " + ECC_p.getB().toString(16));
	  System.out.println("p         = " + ECC_p.getP().toString(16));
	  System.out.println("g         = " + "("+tate.getBasePoint1().getAffineX().toString(16)+","+
	                                          tate.getBasePoint1().getAffineY().toString(16)+")");
	  System.out.println("order     = " + tate.getM().toString(16));
	  
	  System.out.println();
	  System.out.println("masterkey   s = "+masterKey.toString(16));
	  System.out.println("Pub       s.g = "+"("+pubPoint.getAffineX().toString(16)+","+
                                               pubPoint.getAffineY().toString(16)+")");
	  System.out.println("#####end");
	  System.out.println();
	  System.out.println();
  }
  
  public BF_PKGPublicKey getBF_PKGPubKey(){
	  return new BF_PKGPublicKey(ECCParam,pubPoint);
  }
  
  public ECPoint getPrivateKeyByID(String ID){
	  System.out.println("#####start@PKG分配私钥");
	  ECCp ECC_p      = tate.getECCp();
	  ECPoint IDPoint = ECC_p.message2Point(ID.getBytes());
	  ECPoint P       = ECC_p.multiply(IDPoint,masterKey);
	  System.out.println(ID +"  嵌入椭圆曲线点Qid上Qid = ("+IDPoint.getAffineX().toString(16)+
			                                           ","+IDPoint.getAffineY().toString(16)+")");
	  System.out.println(ID +" 获取私钥为Did = s.Qid = ("+P.getAffineX().toString(16)+
                                                   ","+P.getAffineY().toString(16)+")");
	  System.out.println("#####end");
	  System.out.println();
	  System.out.println();
	  return P;
  }
  
  
}
