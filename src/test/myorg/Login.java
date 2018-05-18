package test.myorg;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.Scanner;

public class Login {

    public static final String CONNECTOR_STRING = "com.sun.jndi.ldap.LdapCtxFactory";
    public static final String CONFIG_FILENAME = "ldap.properties";


    private final String ldapSearchbase;
    private final String ldapHostname;
    private final String ldapPort;

    public Login(String ldapSearchbase, String ldapHostname, String ldapPort) {
        this.ldapSearchbase = ldapSearchbase;
        this.ldapHostname = ldapHostname;
        this.ldapPort = ldapPort;
    }

    public String authenticate(String username, String password){

        String userDN = "uid=" + username + "," + ldapSearchbase;
        DirContext ldap_context = null;

        // Mi preparo per stabilire una nuova connessione
        Properties ldap_properties = new Properties();

        // Configuro il connettore per LDAP
        ldap_properties.put(Context.INITIAL_CONTEXT_FACTORY, Login.CONNECTOR_STRING);

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
            return "Invalid credentials!";
        } catch (Exception e) {
            return "Unable to establish a connection to LDAP: \n" + e.toString();
        }

        // Attributi da cercare su LDAP
        String[] attribute_keys = {"cn","sn"};
        String[] attribute_values = new String[attribute_keys.length];

        Attributes searched_attributes = null;
        try {
            searched_attributes = ldap_context.getAttributes(userDN, attribute_keys);
        }catch (Exception e){
            return "Error occurred during LDAP search:\n" + e.toString();
        }

        if(searched_attributes == null){
            return "Unable to find user: \"" + username + "\"";
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
                return  "Unable to obtain \"" + key + "\" attribute for user \"" + username + "\"";
            }
        }

        return "Welcome " + attribute_values[0] + " " + attribute_values[1] + "!";

    }

    public static void main(String[] args) {

        Properties properties;
        String ldapSearchbase = null;
        String ldapHostname = null;
        String ldapPort = null;
        String userDN = null;
        DirContext ldap_context = null;

        System.out.println("");
        System.out.println("***sample-ldap-login2***");

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

        System.out.println("Login");
        Login login = new Login(ldapSearchbase, ldapHostname, ldapPort);

        System.out.println("LoginDialog");
        LoginDialog loginDialog = new LoginDialog(login);
        loginDialog.setVisible(true);

        System.out.println("LoginDialog post");

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
