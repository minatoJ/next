package IBE;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECPoint;

import common.BigIntegerExtend;
import common.PointShow;

import IatePair.ComplexFieldp;
import IatePair.ECCp;
import IatePair.TatePair;


public class IBE {

	
	public static  IBEEncryptBlock encrypt(String  ID,BF_PKGPublicKey PKGPublicKey,byte[] msgBytes){
		
		
		if(msgBytes.length>20){
			return null;
		}
		byte[] bytes = new byte[msgBytes.length];
		TatePair tate     = new TatePair(PKGPublicKey.getPairParameter());
		ECCp ECC_p        = tate.getECCp();
		ECPoint pubKeyPoint  = ECC_p.message2Point(ID.getBytes());
		ECPoint PKGPubKey    = PKGPublicKey.getPubPoint();
		BigInteger oder   = tate.getM();
		BigInteger random = BigIntegerExtend.getRandom(oder);
		ECPoint tmp = ECC_p.multiply(PKGPubKey,random);
		ComplexFieldp shareValue = tate.getTate(tmp,pubKeyPoint);
		String shareString = shareValue.getR().toString() + shareValue.getI().toString();
		MessageDigest md = null;
	    try {
			 md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	    md.update(shareString.getBytes());
	    byte[] shareBytes = md.digest();
	    
	   for(int i = 0; i < msgBytes.length;i ++){
		   bytes[i] = (byte) (msgBytes[i] ^ shareBytes[i]); 
	   }
	   ECPoint tmp1 = ECC_p.multiply(tate.getBasePoint1(),random);
	    System.out.println("#####start@加密");
	    System.out.println("mail address = " + ID);
	    System.out.println();
	    System.out.println("mail address 嵌入椭圆曲线中点Qid = " + PointShow.show(pubKeyPoint));
	    System.out.println("选取一个随机数                                r  = " + random.toString(16));
	    System.out.println("计算                                               r.Pub ="  + PointShow.show(tmp));
	    System.out.println("计算                                                 r.g =" +PointShow.show(tmp1));
	    
	    System.out.println();
	    System.out.println("计算配对t(rPub,Qid) = " + shareValue);
	    System.out.println("将r.g 和 加密结果发送给"+ID);
	    System.out.println("#####end");
		System.out.println();
		System.out.println();
		return new IBEEncryptBlock(bytes,tmp1);	
	}
	
	public  static byte[] decrypt(IBEEncryptBlock block,BF_PKGPublicKey PKGPublicKey,ECPoint privateKey){
		
		TatePair tate     = new TatePair(PKGPublicKey.getPairParameter());
		ComplexFieldp shareValue = tate.getTate(block.getPointBlock(),privateKey);
		String shareString = shareValue.getR().toString() + shareValue.getI().toString();
		MessageDigest md = null;
	    try {
			 md = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	    md.update(shareString.getBytes());
	    byte[] shareBytes = md.digest();
	    byte[] msgBytes   = block.getEcnryptBlock();
	    for(int i = 0; i < msgBytes.length;i ++){
			   msgBytes[i] ^=shareBytes[i]; 
		   }
	    System.out.println("#####start@解密");
	    System.out.println("计算  t(r.g,Did) = t(r.g,SQid) =" + shareValue);
	    System.out.println("解密结果:"+new String(msgBytes));
	    System.out.println("#####end");
		System.out.println();
		System.out.println();
		return msgBytes;
		
	}
	
	

}
