package fi.tut.nisec.negotiation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.json.JSONException;

import com.nimbusds.jose.Payload;
@Path("/negotiate/")
public class Parameters {
	public final static String APPLICATION_JWS = "application/jws"; 
	public final static MediaType APPLICATION_JWS_TYPE = new MediaType("application","jws"); 
	public static final int difficulty= 12;
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
	@GET 
	@Produces(MediaType.TEXT_PLAIN)
	public String parameterTEXT() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JSONException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException {
		return ErrorStore.ErrorJSON().toString();
	}
	@GET 
	@Produces(MediaType.TEXT_HTML)
	public String parameterHTML() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, JSONException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException {
		return ErrorStore.ErrorJSON().toString();
	}
}
