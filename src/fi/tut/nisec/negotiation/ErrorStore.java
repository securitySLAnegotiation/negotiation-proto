package fi.tut.nisec.negotiation;



import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import org.json.JSONException;
import org.json.JSONObject;

import com.nimbusds.jose.Payload;

// One should serialize this and write to a file
// and return from the file unless expired
public class ErrorStore {
	public static int expiration = 3600;
	public static JSONObject ErrorJSON()  throws JSONException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException{
		
		JSONObject puzzle= new JSONObject().put("zeroes", Negotiate.difficulty);
		puzzle.put("age", (Negotiate.stampMaxAge/1000L));
		JSONObject terms = new JSONObject().put("hashcash", puzzle);
		terms.put("exp", (int) (System.currentTimeMillis()/1000L)+expiration);
		terms.put("nbf", (int) (System.currentTimeMillis()/1000L));
		terms.put("x5t", Identity.getThumbPrint(Identity.ownCert()));
		
		return terms;
	}
	public static String signedError() throws CertificateEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, SignatureException, IOException, ClassNotFoundException, JSONException{
		return Sign.signedJWT(new Payload (ErrorJSON().toString()));
	}
}
