package fi.tut.nisec.negotiation;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Iterator;

import org.apache.commons.codec.digest.DigestUtils;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;

import com.nimbusds.jose.Payload;
// Idea of this class is to construct a SSLA proposal that fits the client
// The client has given the functional requirements  
public class GetSSLA {
	public static final int expiration = 3600;
public static Payload processSSLA(Payload userSSLA) throws JSONException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, ClassNotFoundException, IOException {
	
	JSONObject proposed = new JSONObject(userSSLA.toString());
	JSONObject idU = proposed.getJSONObject("idU");
	String userX5t = idU.getString("x5t");
	if (userX5t.isEmpty()) {
		return new Payload("");
	}
	JSONObject idSP = proposed.getJSONObject("idSP");
	String ownX5t = idSP.getString("x5t");
	if (!ownX5t.equalsIgnoreCase(Identity.getThumbPrint(Identity.ownCert()))){
		return normalSSLA(proposed, userX5t);
	}
	JSONArray clientReq = proposed.getJSONArray("req");
	JSONArray supported = supportedReq();
	if (clientReq.length()>supported.length()){
		return normalSSLA(proposed, userX5t);
	}
	else if (!Match.subset(supported, clientReq)){
		return normalSSLA(proposed,userX5t);
	}
	// SSLA requirements match 		
	else {
	JSONObject clientCap = proposed.getJSONObject("cap");
	for (Iterator<?> iterator = clientCap.keys(); iterator.hasNext();) {
		String key = (String) iterator.next();
		JSONArray userMechs = clientCap.getJSONArray(key);
		JSONArray spMechs = spCap().getJSONArray(key);
		if (!Match.containsOneOrMore(spMechs,userMechs)) {
			return normalSSLA(proposed,userX5t);
		}
		
	}
	// IF the checks did not catch, then we'll just sign this one 
	// System.out.println(userSSLA.toString());
	return userSSLA;
}
}
public static JSONObject spCap() throws JSONException {
	JSONArray id2Mechs = new JSONArray().put("mechanism1").put("mechanism2").put("mechanism3");
	JSONObject spCap = new JSONObject().put("id2", id2Mechs);
	JSONArray id4Mechs = new JSONArray().put("mechansim3").put("mechanism5");
	spCap.put("id4", id4Mechs);
	spCap.put("id1", new JSONArray().put("mechanism1"));
	return spCap;
}
public static JSONArray supportedReq(){
	// leave the id3 in test case out
	JSONArray req = new JSONArray().put("id1").put("id2").put("id4");
	return req;
}
public static Payload normalSSLA (JSONObject SSLA,String userThumb) throws JSONException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, ClassNotFoundException, IOException {
	
	SSLA.put("idSP",new JSONObject().put("x5t", Identity.getThumbPrint(Identity.ownCert())));
	//TODO: should really compare these to the time
	if (!SSLA.has("exp")) SSLA.put("exp", (int) (System.currentTimeMillis()/1000L)+expiration);
	if (!SSLA.has("exp")) SSLA.put("nbf", (int) (System.currentTimeMillis()/1000L));
	// Twice hash, when returning seed hash once
	if (Negotiate.confirmtoken) SSLA.put("commit", DigestUtils.sha1Hex(DigestUtils.sha1Hex(Negotiate.confirmsecret+userThumb+Negotiate.confirmsecret)));
	SSLA.put("req", supportedReq());
	SSLA.put("cap", spCap());
	SSLA.remove("trustedKB");
	SSLA.put("idKB", new JSONObject().put("x5t", Identity.getThumbPrint(Identity.ownCert())));
	return new Payload(SSLA.toString());
	
}
	
//DNSSEC functions 	
//	public static final String searchbase = "directory.atm.tut.fi";
//	public static JSONObject SSLA(JSONObject requirements) throws JSONException, TextParseException{
//	JSONObject SSLA = new JSONObject();
//	JSONArray list = requirements.getJSONArray("functional");
//		// For every requirement get list of countermeasures
//		for (int i = 0; i < list.length(); i++) {
//			String requirement=list.get(i).toString();
//			Record [] records = new Lookup(requirement+"."+searchbase,Type.TXT).run();
//			for (int j = 0; j < records.length; j++) {
//				TXTRecord mechanism = (TXTRecord) records[i];
//				String countermeasure =mechanism.rdataToString();
//				if (MechanismStore.checkAvailability(countermeasure)) {
//					SSLA.put(requirement, countermeasure);
//				}
//			}
//		}
//		return SSLA;
//	}
//	
}
