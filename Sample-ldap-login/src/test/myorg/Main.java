package test.myorg;



import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;


public class Main {

    public static final String CONNECTOR_STRING = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String CONFIG_FILENAME = "ldap.properties";

    public static void main(String[] args) {

        Properties properties;
        String ldapSearchbase = null;
        String ldapHostname = null;
        String ldapPort = null;
        String userDN = null;
        DirContext ldap_context = null;

        System.out.println("");
        System.out.println("***sample-ldap-login***");

        try {

            File currentJarFile = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            String jarDirectory = currentJarFile.getParentFile().getPath();

            // Load Properties from file
            properties = new Properties();
            FileInputStream fileInputStream = new FileInputStream(jarDirectory + "/" + CONFIG_FILENAME);
            properties.load(fileInputStream);

            ldapSearchbase = properties.getProperty("ldap.searchbase");
            ldapHostname = properties.getProperty("ldap.hostname");
            ldapPort = properties.getProperty("ldap.port");

            if(ldapSearchbase == null) throw new Exception("Attribute not found: ldapSearchbase");
            if(ldapHostname == null) throw new Exception("Attribute not found: ldapHostname");
            if(ldapPort == null) throw new Exception("Attribute not found: ldapPort");

        }catch (Exception e){

            System.out.println("An error occurred during initialization:");
            System.out.println(e);
            System.exit(1);
        }

        Scanner keyboard = new Scanner(System.in);
        String username = null;
        String password = null;


        boolean authenticationSuccessful = false;
        do {

            while (true) {
                System.out.print("Insert username: ");
                username = keyboard.nextLine();
                if (username == null || username.trim().isEmpty()) {
                    System.out.println("Invalid username. Try again.");
                } else {
                    break;
                }
            }

            Console console = System.console();
            System.out.print("Insert password");
            if (console == null) {
                System.out.print(" (Warning: isn't possible to hide the entered password - Maybe you are using an IDE ?. Make sure you aren't observed): ");
                password = keyboard.nextLine();
            } else {
                System.out.print(": ");
                char[] passwordChars = console.readPassword();
                password = new String(passwordChars);
            }

            userDN = "uid=" + username + "," + ldapSearchbase;


            // Mi preparo per stabilire una nuova connessione
            Properties ldap_properties = new Properties();

            // Configuro il connettore per LDAP
            ldap_properties.put(Context.INITIAL_CONTEXT_FACTORY, Main.CONNECTOR_STRING);

            // Preparo url di connessione
            ldap_properties.put(Context.PROVIDER_URL, "ldap://" + ldapHostname + ":" + ldapPort);

            // User
            ldap_properties.put(Context.SECURITY_PRINCIPAL, userDN);

            // Password
            ldap_properties.put(Context.SECURITY_CREDENTIALS, password);

            // Provo a stabilire la connessione coi parametri passati
            try {
                ldap_context = new InitialDirContext(ldap_properties);
            } catch (AuthenticationException ae) {
                System.out.println("Invalid credentials!");
                continue;
            } catch (Exception e) {
                System.out.println("Unable to establish a connection to LDAP:");
                System.out.println(e);
                System.exit(1);
            }

            authenticationSuccessful = true;

        }while (!authenticationSuccessful);


        // Attributi da cercare su LDAP
        String[] attribute_keys = {"cn","sn"};
        String[] attribute_values = new String[attribute_keys.length];

        Attributes searched_attributes = null;
        try {
            searched_attributes = ldap_context.getAttributes(userDN, attribute_keys);
        }catch (Exception e){
            System.out.println("Error occurred during LDAP search:");
            System.out.println(e);
            System.exit(1);
        }

        if(searched_attributes == null){
            System.out.println("Unable to find user: \"" + username + "\"");
            System.exit(0);
        }



        for (int i = 0; i < attribute_keys.length; i++){
            String key = attribute_keys[i];
            Attribute attr = searched_attributes.get(key);

            // Ottengo il primo valore dell'attributo (potrebbe avere più valori)
            try {
                NamingEnumeration vals = attr.getAll();
                String attr_value = null;
                if (vals.hasMoreElements()) {
                    // Prendo solo il primo valore
                    attribute_values[i] = vals.nextElement().toString();
                }
            }catch(Exception e){
                System.out.println("Unable to obtain \"" + key + "\" attribute for user \"" + username + "\"");
                System.exit(0);
            }
        }

        System.out.println("Welcome " + attribute_values[0] + " " + attribute_values[1] + "!");

        try{
            ldap_context.close();
        }catch (Exception e){
            System.out.println("Error occurred during LDAP disconnection:");
            System.out.println(e);
            System.exit(1);
        }

        /*
        try {
            String algorithm = "HmacSHA256";
            TimeBasedOneTimePasswordGenerator totpGenerator = new TimeBasedOneTimePasswordGenerator(20, TimeUnit.SECONDS, 8, algorithm);

            // decode the base64 encoded string
            byte[] decodedKey = Base64.getDecoder().decode("NNK6EJYQ7GL4X4DZPOVUZIBCR5S2UQS462N7Q5KRATSP2ZQV");
            // rebuild key using SecretKeySpec
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "RAW");
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(totpGenerator.getAlgorithm());

            // SHA-1 and SHA-256 prefer 64-byte (512-bit) keys; SHA512 prefers 128-byte keys
            // keyGenerator.init(512);

            // Key secretKey = keyGenerator.generateKey();

            int totp = totpGenerator.generateOneTimePassword(secretKey, Date.from(Instant.now()));
            System.out.println(Date.from(Instant.now()));
            System.out.println(totp);

        }catch (Exception e){

        }*/


    }
}
