package fi.tut.nisec.negotiation;

import org.json.JSONObject;
import org.json.JSONException;

public class SSLAError {
	public static JSONObject blanketSSLA() throws JSONException {
		JSONObject blanket = new JSONObject().put("Item1", "yes");
		blanket.put("Item2", "no");
		return blanket;
	}
}
