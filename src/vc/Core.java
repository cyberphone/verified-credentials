package vc;

import java.io.File;

import java.security.PublicKey;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.jose.jws.JWSAsymSignatureValidator;
import org.webpki.jose.jws.JWSDecoder;
import org.webpki.util.IO;
import org.webpki.util.UTF8;

public class Core {
    
    static byte[] readBytes(String fileName) {
        return IO.readFile("testdata" + File.separator + fileName);
    }
    
    static String readWrappedLine(String fileName) {
        return UTF8.decode(readBytes(fileName)).replace("\n", "").replace("\r", "");
    }
    
    static JSONObjectReader readJSON(String fileName) {
        return JSONParser.parse(readBytes(fileName));
    }
    
    static public PublicKey getPublicJWK(String fileName) {
        return readJSON(fileName).getCorePublicKey(AlgorithmPreferences.JOSE);
    }
    
    public static void main(String[] args) {
        PublicKey publicKey = getPublicJWK("sd-jwt-pubkey.json");
        String[] components = readWrappedLine("sd-jwt-presentation.A.2.txt").split("~");
        for (String comp : components) {
            System.out.println(comp);
        }
        System.out.println("Hi=" + publicKey.toString());
        JWSDecoder res = new JWSAsymSignatureValidator(publicKey)
                .validate(new JWSDecoder(components[0]));
        System.out.println("PL=" + res.getPayloadAsJson());
    }

}
