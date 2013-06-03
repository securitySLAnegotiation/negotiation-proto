package fi.tut.nisec.negotiation;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.nettgryppa.security.*;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;


@Path("/negotiate/{stamp}")
public class Negotiate{
public final static String APPLICATION_JWS = "application/jws"; 
public final static MediaType APPLICATION_JWS_TYPE = new MediaType("application","jws"); 
public static final int difficulty= 12;
public static final Boolean confirmtoken=true;
// This can be taken from Sign class, now I'm not sure what would happen
public static final String confirmsecret= "TODO: Save random value somewhere";
// Accept stamps that are 40 seconds old
public static final long stampMaxAge = 40000L;
// Accept stamps that are 20 seconds in the future
public static final long stampFuture = 20000L;
	// If the request is GET, then we only return parameters that are used in the 
	// negotiation
	@GET 
	@Produces(APPLICATION_JWS)
	public String negotiationParameters() throws JSONException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException{
		Payload payload = new Payload(ErrorStore.ErrorJSON().toString());
		return Sign.signedJWT(payload);
	}
	
	@GET 
	@Produces(MediaType.APPLICATION_JSON)
	public String parameterJSON() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JSONException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException {
		return ErrorStore.ErrorJSON().toString();
	}
	@POST
	@Consumes(APPLICATION_JWS)
	@Produces(APPLICATION_JWS)
	public String nextRound(@PathParam("stamp") String stamp, String contract) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, IOException, ClassNotFoundException, JSONException, InvalidKeySpecException, CertificateException, ParseException, JOSEException{
		HashCash leima = new HashCash(stamp);
		if (leima.getValue()< difficulty) {	
			return ErrorStore.signedError();
		}
		// Time validation in stamps is not working
//		else if (leima.getDate().getTimeInMillis() > (System.currentTimeMillis()+stampMaxAge)){
//			return ErrorStore.signedError();
//		}
//		else if (leima.getDate().getTimeInMillis() > System.currentTimeMillis()-stampFuture){
//			return ErrorStore.signedError();
//		}
		// If this stamp is not used, the resource does not 
		// exist yet
		else if (!Session.checkExists(leima.toString())) {
			return contract(stamp, contract);
		}
		else {
			// Let's verify the signature
			String idSPResource = leima.getResource();
			// 
		    String ownId = Identity.getThumbPrint(Identity.ownCert());
		    if (!(ownId.equalsIgnoreCase(idSPResource))){
		    	return ErrorStore.signedError();
		    }
		    JWSObject jwsObject = JWSObject.parse(contract);
			ReadOnlyJWSHeader clientheader = jwsObject.getHeader();
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
			// TODO: We assume here a cert chain of one cert
			Base64 clientcert = clientheader.getX509CertChain()[0];
			InputStream in = new ByteArrayInputStream(clientcert.decode());
			
			X509Certificate UC = (X509Certificate) certFactory.generateCertificate(in);
			PublicKey Ukey = UC.getPublicKey();
			// Better error for this dev case could be made
			if(!Ukey.getAlgorithm().equalsIgnoreCase("EC")){
				return ErrorStore.signedError();
			}
			org.bouncycastle.jce.interfaces.ECPublicKey ECU = (org.bouncycastle.jce.interfaces.ECPublicKey) Ukey;
			org.bouncycastle.math.ec.ECPoint pointU = ECU.getQ();
			BigInteger x = pointU.getX().toBigInteger();
			BigInteger y = pointU.getY().toBigInteger();
				
			
			JWSVerifier verifier =new ECDSAVerifier(x, y);			
			if (!jwsObject.verify(verifier)) {
				return ErrorStore.signedError();
			}
			
			try {
				String previous= Session.readFromStore(leima.toString());
				//JWSObject jwsPrevious = JWSObject.parse(previous);
				JSONObject spSSLA = new JSONObject(previous); 
				spSSLA.remove("jti");
				
				JSONObject proposed = new JSONObject(jwsObject.getPayload().toString());
				proposed.remove("jti");
				if (Match.equalJSONObject(proposed.toString(), spSSLA.toString())){
					Session.writeFinal(contract, "");
					return Sign.signedJWT(new Payload(previous)); 
				}
				else {
					String SSLA = Sign.signedJWT(GetSSLA.processSSLA(new Payload(proposed.toString())));
					
					return SSLA;
				}
				
					
				
			} catch (JSONException e) {
				return "Session exists but cannot be read to JSON, sorry.";
			}	
		}
	}
	
	@POST
	@Consumes(MediaType.TEXT_PLAIN)
	@Produces(MediaType.TEXT_PLAIN)
	public String confirm(@PathParam("stamp") String stamp, String contract) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, SignatureException, IOException, ClassNotFoundException, JSONException, InvalidKeySpecException, CertificateException, ParseException, JOSEException{
		HashCash leima = new HashCash(stamp);
		if (leima.getValue()< difficulty) {	
			return "Stamp difficulty less than "+difficulty+"zeroes";
		}
		// Time comparisons broken
//		if (leima.getDate().getTimeInMillis() > (System.currentTimeMillis()+stampMaxAge)){
//			return "Stamp older than " + stampMaxAge +" seconds";
//		}
//		else if (leima.getDate().getTimeInMillis() > System.currentTimeMillis()-stampFuture){
//			return "You come from the future, or am I in the past? UNIX-time now"+(int)(System.currentTimeMillis()/1000L);
//		}
		// If this stamp is not used, the resource does not 
		// exist yet
		// Cannot return a text response, so return jws anyway
		else if (!Session.checkExists(leima.toString())) {
			return contract(stamp, contract);
		}
		else {
			try {
				String previous= Session.readFromStore(leima.toString());
				//JWSObject jwsObject = JWSObject.parse(previous);
				JSONObject spSSLA = new JSONObject(previous); 
				
					if (spSSLA.has("commit")&& !contract.isEmpty()) {
						String committed =spSSLA.getString("commit");
						JSONObject idU = spSSLA.getJSONObject("idU");
						String userX5t= idU.getString("x5t");
						String seed = DigestUtils.sha1Hex((Negotiate.confirmsecret+userX5t+Negotiate.confirmsecret));
						if (DigestUtils.sha1Hex(seed).toUpperCase().contains(committed.toUpperCase())){
							
							Session.writeFinal(contract, seed);
							return seed;
						}
						else {
							return "Confirm token broken";
						}
					}
					else {
						return "Confirm token empty or unnecessary";
					}
				
			} catch (Exception e) {
				return "Session exists but cannot be read to JSON, sorry."+e.getMessage();
			}
			
		}	
	}
	
    @PUT
	@Consumes(APPLICATION_JWS)
	@Produces(APPLICATION_JWS)
	public String contract( @PathParam("stamp") String stamp, String contract) throws JSONException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IOException, ClassNotFoundException, ParseException, JOSEException, InvalidKeySpecException, InvalidKeyException, IllegalStateException, SignatureException, CertificateException{
		HashCash leima = new HashCash(stamp);
		if (leima.getValue()< difficulty) {	
			return ErrorStore.signedError();
		}
		// This time compare is not working for some reason
		//if (leima.getDate().getTimeInMillis() > (System.currentTimeMillis()+20000L)){
		//	return ErrorStore.signedError();
		//}	
		// Let's create a resource for the stamp
		// and check whether the stamp is used
		else if (!Session.makeStore(leima.toString())) {
			return nextRound(stamp, contract);
		}
		else {
			// How we represent identities? 
		    // I am starting to think that Base58check representation
		    // of the x of EC keys with unique y could be a good id encoding
		    // scheme. Like bitcoin wallets, but sans the hashing. Hashcash is 
		    // really difficult if we want to use it for storing the identity.
		    // There is no separate field for the identities, but we really need 
		    // one. Or actually there is, but the documentation is sparse and the field 
			// is a strange name value pair combo. 
			// What if one would just use jwk in the hashcash? 
		    // Unless... if we are interested only in that the hashcash resource 
		    // which is a hash of our own public key and the resource on the server, 
		    // and has an extension that is unique? Does it have to include the
		    // client ID? Benefit of including the client id is that the jwt 
		    // can be verified with the key from the stamp. 
		    // Is there any other drawback with this? I.e. stamp is destined
		    // for me, and I have not seen it before, and it was generated in 
		    // a timeframe I am willing to accept. 
			// 
			// However, here a Base64 encoding is used instead of any good scheme
			// and the public key is just a point compressed X9.62 encoded version
			// The first part of the hashcash stamp resource should represent
			// the user's identity, if point compression is used it is 
			// 118 octets, encoding is expected to be base64 -> 80 chars 
			
			String idSPResource = leima.getResource();
			// 
			
			X509Certificate ownCert = Identity.ownCert();
		    String ownId = Identity.getThumbPrint(ownCert);
		    if (!(ownId.equalsIgnoreCase(idSPResource))){
		    	Payload payload = new Payload(ErrorStore.ErrorJSON().toString());
		    	return Sign.signedJWT(payload);
		    }
		    else {
		    Security.addProvider(new BouncyCastleProvider());
//		    ECParameterSpec params = ECNamedCurveTable.getParameterSpec("prime256v1");
//		    ECCurve curve = params.getCurve();
////			
//			BigInteger userX= w.getAffineX();
//			BigInteger userY= w.getAffineY();
			
			JWSObject jwsObject = JWSObject.parse(contract);
			ReadOnlyJWSHeader clientheader = jwsObject.getHeader();
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
			Base64 clientcert = clientheader.getX509CertChain()[0];
			InputStream in = new ByteArrayInputStream(clientcert.decode());
			
			X509Certificate UC = (X509Certificate) certFactory.generateCertificate(in);
			PublicKey Ukey = UC.getPublicKey();
			// Better error for this dev case could be made
			if(!Ukey.getAlgorithm().equalsIgnoreCase("EC")){
				return ErrorStore.signedError();
			}
			org.bouncycastle.jce.interfaces.ECPublicKey ECU = (org.bouncycastle.jce.interfaces.ECPublicKey) Ukey;
			org.bouncycastle.math.ec.ECPoint pointU = ECU.getQ();
			BigInteger x = pointU.getX().toBigInteger();
			BigInteger y = pointU.getY().toBigInteger();
				
			
			JWSVerifier verifier =new ECDSAVerifier(x, y);			
			if (jwsObject.verify(verifier)) {
				// here we do the requirement processing
				
				Payload payload =(jwsObject.getPayload());
				Payload accepted=GetSSLA.processSSLA(payload);
				if (accepted.equals("")){
					return ErrorStore.signedError();
				}
				else {
					Session.writeToStore(leima.toString(), accepted.toString());
					return Sign.signedJWT(accepted);
				}
			}
			// If signature does not verify, it may not make sense to send any
			// error reply, but instead abort with a 403 or something
			else {
			 
			 return ErrorStore.signedError();
			}
		}
	}

}
}