package fi.tut.nisec.negotiation;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.text.ParseException;

import org.json.JSONException;
import org.json.JSONObject;

import com.nimbusds.jose.JWSObject;

public class Session {
	
	public static Boolean checkExists (String fileName) throws IOException {
		try {
			new FileInputStream (fileName);
			return true;
		}
		catch (FileNotFoundException e) {
			return false;
		}
	}
	public static Boolean makeStore(String fileName) throws IOException {
		try {
			new FileInputStream (fileName);
			return false;
		} 
		catch (FileNotFoundException e) {
		OutputStream file = new FileOutputStream( fileName );
	    OutputStream buffer = new BufferedOutputStream( file );
	    ObjectOutput output = new ObjectOutputStream( buffer );
	    output.close();
	    return true;
		}
	}
	public static void writeToStore(String fileName,String contract) throws IOException {
		OutputStream file = new FileOutputStream( fileName );
	    OutputStream buffer = new BufferedOutputStream( file );
	    ObjectOutput output = new ObjectOutputStream( buffer );
	    output.writeObject(contract);
	    output.close();
	}
	public static String readFromStore(String fileName) throws IOException, ClassNotFoundException {
		InputStream file = new FileInputStream(fileName);
		InputStream buffer = new BufferedInputStream(file);
		ObjectInput input = new ObjectInputStream(buffer);
		String stored = (String) input.readObject();
		input.close();
		return stored;
	}
	public static void writeFinal(String contract, String supplementary) throws ParseException, JSONException, IOException {
		JWSObject jwsObject = JWSObject.parse(contract);
		JSONObject temp = new JSONObject(jwsObject.getPayload().toString());
		String fileName= temp.getInt("exp")+temp.getJSONObject("idU").getString("x5t");
		JSONObject tofile = new JSONObject().put("confirm", supplementary).put("SSLA", contract);
		OutputStream file = new FileOutputStream( fileName );
	    OutputStream buffer = new BufferedOutputStream( file );
	    ObjectOutput output = new ObjectOutputStream( buffer );
	    output.writeObject(tofile.toString());
	    output.close();
	}
}
