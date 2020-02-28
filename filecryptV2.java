
import java.io.*;
import java.nio.file.*;
import java.util.zip.*;
import java.util.*;

import java.io.FileOutputStream;
import java.io.FileInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Mac;
import javax.crypto.spec.PBEKeySpec;


// Exemple de clé 128 bits : 
// 9AF44FB68A7CDB96D2FE2F5AD686E87A 
	
public class filecryptV2 {
	

    public static void main(String[] args) {
        try {
			if (args.length >= 5) { // teste le nombre d'arguments
			
				
				String KEY = args[2]; 
			    

				if ((args[0]).equals("-enc")){
					System.out.println("Le(s) fichier(s) va(vont) être chiffré(s)");
					
					List<String> srcFiles = new ArrayList<String>();
					
					for(int i=4;i<args.length;++i){
					
						File file_input = new File(args[i]); String data = readFile(file_input.getName()); // data du fichier en input
						
						String cryptedFile = "Chiffre_"+args[i]; File out = new File(cryptedFile); // fichier chiffré
						
						String macFile = "MAC_"+args[i]; File MAC = new File(macFile); // MAC
						
						// création de l'IV
						SecureRandom srandom = new SecureRandom();
						byte[] iv = new byte[16];
						srandom.nextBytes(iv);
						IvParameterSpec ivspec = new IvParameterSpec(iv); 
						String ivFile = "ivFile_"+args[i];
					
						// écriture de l'IV dans un fichier (pour la réutilisation lors du déchiffrement)
						try (FileOutputStream outIV = new FileOutputStream(ivFile)) {
							outIV.write(iv);
						}
						
						
						// chiffrement du fichier en entrée 
						String res = encrypt(KEY,ivspec,file_input, MAC);
						
						// écriture du fichier chiffré en sortie
						FileWriter writer = new FileWriter(out);
						writer.write(res);
						writer.close();
						
						// Add les fichiers dans le zip
						srcFiles.add(cryptedFile);
						
					
					}
					
					
					
					
					// ZIP DES FICHIERS
					FileOutputStream fos = new FileOutputStream("multiCompressed.zip");
					ZipOutputStream zipOut = new ZipOutputStream(fos);
					for (String srcFile : srcFiles) {
						File fileToZip = new File(srcFile);
						FileInputStream fis = new FileInputStream(fileToZip);
						ZipEntry zipEntry = new ZipEntry(fileToZip.getName());
						zipOut.putNextEntry(zipEntry);
			 
						byte[] bytes = new byte[1024];
						int length;
						while((length = fis.read(bytes)) >= 0) {
							zipOut.write(bytes, 0, length);
						}
						fis.close();
					}
					zipOut.close();
					fos.close();
					
				}
				
		    }
		    else { 
		    System.out.println("il n'y a pas le bon nombre d'arguments\n");
		    }
        }
	    catch (Exception e) {
	        System.out.println("Error: " + e.getMessage());
	        System.exit(1);
	    }
    }

   public static void test_fichier_output(String out) throws Exception {
    
		File file_output; file_output = new File(out);
		
    	if(file_output.exists()) { // demande la permission de détruire le fichier output
    	
    		Scanner sc = new Scanner(System.in);
			System.out.println("le fichier output existe, voulez vous le supprimer ? yes/no");
			String str = sc.nextLine();
			
			if (str.equals("yes")) { 
		     	if(file_output.delete()) {  
				System.out.println(file_output.getName() + " supprimé"); 
				}  
			}
			else if (str.equals("no")) { 
			 	System.out.println("Le fichier ne sera pas supprimé\n");
			}
		}
    	else {}
    }
    
    public static String encrypt(String key, IvParameterSpec iv, File inputFile, File MAC) throws Exception {
    	String msg = readFile(inputFile.getName());
    
    	/* ************ MAC ************** */
    	String algo = "HMACSHA256";
		KeyGenerator kgen = KeyGenerator.getInstance(algo);
		SecretKey skey = kgen.generateKey();
	
		try (FileOutputStream out = new FileOutputStream(MAC)) {
			out.write(skey.getEncoded());
			}
			
		Base64.Encoder encoder = Base64.getEncoder();
			
		Mac mac = Mac.getInstance(algo);
		mac.init(skey);
		
		
		try (FileInputStream in = new FileInputStream(inputFile)) {
			byte[] macb = processFile(mac, in);
			System.out.println(inputFile + ": " + encoder.encodeToString(macb)); // affichage du MAC à comparer avec le MAC lors du déchiffrement pour vérifier l'intégrité du fichier
		
		}
		
		/* ********** FIN MAC ********** */
		
		// conversion de la clé en entrée en byte array
        byte[] bytesOfKey = key.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesOfKey);

		// chiffrement AES/CBC/PKCS5Padding
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

		// resultat 
        final byte[] resultBytes = cipher.doFinal(msg.getBytes());
        return Base64.getMimeEncoder().encodeToString(resultBytes);
    }
    
    
    

    public static String readFile(String filename) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(filename));
        try {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String everything = sb.toString();
            return everything;
        } finally {
            br.close();
        }
    }
    
    static private final byte[] processFile(Mac mac,InputStream in)
    throws java.io.IOException
	{
		byte[] ibuf = new byte[1024];
		int len;
		while ((len = in.read(ibuf)) != -1) {
		    mac.update(ibuf, 0, len);
		}
		return mac.doFinal();
	}
	

}


