package IBE;
import java.math.BigInteger;
import java.security.spec.ECPoint;

import common.Base64;
//jin

public class IBEEncryptBlock {
  byte[]  encryptBlock;
  ECPoint pointBlock;
  public IBEEncryptBlock(byte encryptBlock[],ECPoint pointBlock){
	  this.encryptBlock = encryptBlock;
	  this.pointBlock   = pointBlock;
  }
  public IBEEncryptBlock(String block){
	  String[] enBlock = block.split("&");
	  String[] point   = enBlock[0].split(",");
	  this.encryptBlock = Base64.decode(enBlock[1]);
	  this.pointBlock   = new ECPoint(new BigInteger(point[0],16),
			               new BigInteger(point[1],16));
  }
  public byte[] getEcnryptBlock(){
	  return this.encryptBlock;
  }
  public ECPoint getPointBlock(){
	  return this.pointBlock;
  }
  public String getEncode(){
	  String result;
	  result  = pointBlock.getAffineX().toString(16);
	  result += "," + pointBlock.getAffineY().toString(16);
	  result += "&" + Base64.encode(encryptBlock);
	  return result;
  }
  
}
