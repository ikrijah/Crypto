
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
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
	
public class filecrypt {
	

    public static void main(String[] args) {
        try {
			if (args.length == 7) { // teste le nombre d'arguments
			
				// in = fichier en entrée, out = fichier en sortie, key = clé passée en entrée
				String in = args[4]; String out = args[6]; String KEY = args[2]; 
			    File file_input; file_input = new File(in);
			    File file_output; file_output = new File(out);
			    
			    File MAC = new File("MAC.txt"); // fichier pour la clé du MAC (Message Authentication Code)
			    
			    String data = readFile(file_input.getName()); // lecture du message du fichier en entrée
			    
				if(!file_input.exists()) { // si le fichier en entrée n'existe pas
					System.out.println("Impossible de chiffrer un fichier qui n'existe pas !");
					return;
				}
				
				test_fichier_output(out); // test si le fichier de sortie existe + demande de l'écraser


				if ((args[0]).equals("-enc")){
					System.out.println("Le fichier va être chiffré");
					
					// création de l'IV
					SecureRandom srandom = new SecureRandom();
					byte[] iv = new byte[16];
					srandom.nextBytes(iv);
					IvParameterSpec ivspec = new IvParameterSpec(iv); 
					String ivFile = "ivFile.txt";
					
					// écriture de l'IV dans un fichier (pour la réutilisation lors du déchiffrement)
					try (FileOutputStream outIV = new FileOutputStream(ivFile)) {
						outIV.write(iv);
					}
					
					// chiffrement du fichier en entrée 
					String res = encrypt(KEY,ivspec,file_input, MAC);
					// écriture du fichier chiffré en sortie
					PrintWriter writer = new PrintWriter(out, "UTF-8");
					writer.print(res);
					writer.close();
					
				}
				else if ((args[0]).equals("-dec")) {
					System.out.println("Le fichier va être déchiffré");
					
					// récupération de l'IV lors du chiffrement
					String ivFile = "ivFile.txt";
					byte[] iv = Files.readAllBytes(Paths.get(ivFile));
					IvParameterSpec ivspec = new IvParameterSpec(iv);

					// déchiffrement du fichier
					String res2 = decrypt(KEY,ivspec,file_input, MAC);
					// écriture du fichier déchiffré en sortie
					PrintWriter writer2 = new PrintWriter(out, "UTF-8");
					writer2.print(res2);
					writer2.close();
					
					/* ********* MAC ***** */
					// création de la clé secrète pour le MAC
					String algo = "HMACSHA256";
					byte[] keyb = Files.readAllBytes(Paths.get(MAC.getName()));
					SecretKey skey = new SecretKeySpec(keyb, algo);
					
					Base64.Encoder encoder = Base64.getEncoder();
					
					Mac mac = Mac.getInstance(algo);
					mac.init(skey);
	
					// MAC stocké dans un fichier
					try (FileInputStream inMAC = new FileInputStream(file_output)) { 
						byte[] macb = processFile(mac, inMAC);
						System.out.println(file_output + ": " + encoder.encodeToString(macb)); // affichage du MAC à comparer avec le MAC lors du chiffrement pour vérifier l'intégrité du fichier
					}
					/* ******** FIN MAC ******** */
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



    public static String decrypt(String key, IvParameterSpec iv, File encryptedFile, File MAC) throws Exception {
    
    	String msg = readFile(encryptedFile.getName());
    	
    	// conversion de la clé en entrée en byte array
        byte[] bytesOfKey = key.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesOfKey);

		// conversion message chiffré en byte array
        final byte[] encryptedBytes = Base64.getMimeDecoder().decode(msg);

		// déchiffrement
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

		// resultat
        final byte[] resultBytes = cipher.doFinal(encryptedBytes);
        
        // conversion en String
        return new String(resultBytes);
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


