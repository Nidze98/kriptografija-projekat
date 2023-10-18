package user;

import java.io.*;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;

import crypto.*;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import static crypto.Crypto.*;
import static crypto.Crypto.inputAndCheckCert;
import static java.lang.System.in;

public class User {
    private String username;
    private static KeyPair key;
    private String password;
    private X509Certificate cert;
    private int n;

    public User() {

    }

    public User(String username, String password, KeyPair key, X509Certificate cert) {
        this.username = username;
        this.password = password;
        this.key = key;
        this.cert = cert;
        this.n = 0;

    }

    public static User registerUser() {
        KeyPair key1 = null;
        String username = null, password = null;
        X509Certificate cert = null;

        try {
            Crypto cr = new Crypto();
            key1 = cr.generateKeyPair();
            // Create the console object
            Scanner keyboard = new Scanner(in);
            if (keyboard == null) {
                System.out.println("No console available");
                return null;
            }
            System.out.println("Enter username : ");
            username = keyboard.nextLine();
            System.out.println("Username : " + username);
            if (userExists(username)) {
                System.out.println("Korisnik sa ovim imenom vec postoji");
                return null;
            }
            System.out.println("Enter password : ");
            password = keyboard.nextLine();
            cert = issueUserCertificate(key1.getPublic(), username);

            String path, path_podaci;
            path = getProjectPath() + "\\kripto_projekat\\registered users\\" + username;
            path_podaci = path + "/" + username + "_podaci.txt";
            try {

                //System.out.println(path);
                File f = new File(path);
                if (f.mkdir() == true) {
                    // System.out.println("Directory has been created successfully");
                } else {
                    System.out.println("Directory cannot be created");
                }
                File myObj = new File(path_podaci);
                if (myObj.createNewFile()) {
                    // System.out.println("File created: " + myObj.getName());
                } else {
                    System.out.println("Ovaj korisnik vec postoji.");
                }
                FileWriter myWriter = new FileWriter(path_podaci, true);
                BufferedWriter out = new BufferedWriter(myWriter);
                //out.write(this.username);
                //out.write(";");
                password = hashFunction(password);
                out.write(password);
                SaveKeyPair(path, key1);
                out.newLine();
                out.close();
                //System.out.println("Successfully wrote to the file.");
                saveX509CertBase64(cert, username);
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }

        } catch (Exception ex) {
            System.out.println("prazno");
        }

        return new User(username, password, key1, cert);

    }

    public static User login() {
        int brojac = 0;
        boolean bol = false;
        int trg = 0;
        User tmp = null;
        /*File cert1=new File("C:\\Users\\bursa\\Desktop\\etf\\kriptografija\\moj_projekat\\kripto_projekat\\Certificates\\certs\\user_cert.crt");
        X509Certificate cert2 =getCertificateFromFile(cert1);
        reActivate(cert2);*/
        try {
            File certificateFile = inputAndCheckCert();
            if(certificateFile==null) return null;
            X509Certificate cert = getCertificateFromFile(certificateFile);

            String real_username = getCNFromCertificateFile(certificateFile);
            String real_password = getUserInfo(real_username);
            KeyPair real_key = LoadKeyPair(cert, real_username);
            do {
                while (real_username != null && brojac != 3) {
                    Scanner keyboard = new Scanner(in);
                    System.out.println("Enter username : ");
                    String username = keyboard.nextLine();
                    System.out.println("Enter password : ");
                    String password = keyboard.nextLine();

                    if (checkHash(password, real_password) && username.equals(real_username)) {
                        System.out.println("Dobrodosli " + username);
                        if (trg == 1) {
                            reActivate(cert);
                            trg = 0;
                        }
                        moveFile(getProjectPath() + "\\kripto_projekat\\registered users\\" + username + "\\private.key",
                                getProjectPath() + "\\kripto_projekat\\Certificates\\private\\private.key");

                        bol = true;
                        break;
                    } else if (!(username.equals(real_username))) {
                        System.out.println("Pogresan username");
                        bol = false;
                        brojac++;
                    } else if (!(password.equals(real_password))) {
                        System.out.println("Pogresan password");
                        bol = false;
                        brojac++;
                    }
                }
                if (brojac == 3) {
                    try {
                        addToCRL(cert);
                        System.out.println("Sertifikat je suspendovan zbog prevelikog broja pogreski");
                        System.out.println("Izaberite opciju");
                        int input = 0;
                        do {
                            Scanner keyboard = new Scanner(in);

                            System.out.println("1. Registracija novog naloga 2.Reaktivacija  3.Povratak nazad");
                            System.out.println("Unesite broj 1 ili 2 ili 3");
                            // Read line
                            input = keyboard.nextInt();
                        }
                        while (input != 1 && input != 2 && input != 3);

                        if (input == 1) {
                            tmp = registerUser();
                            return tmp;
                        }
                        if (input == 2) {
                            trg = 1;
                            brojac = 0;
                        }
                        if (input == 3) {
                            return null;
                        }

                    } catch (Exception ex) {
                        System.out.println(ex.toString());
                    }
                }
                if (bol)
                    return new User(real_username, real_password, real_key, cert);
            } while (trg == 1);

        } catch (Exception ex) {
            System.out.println("U folderu Upload_certs se ne nalazi sertifikat");
        }
        return null;

    }

    public static boolean upload(KeyPair key, String username) {
        Scanner keyboard = new Scanner(in);
        int input = 0;
        do {
            System.out.println("1.Ubacen 1 fajl u folder Upload_files 2.Povratak");
            input = keyboard.nextInt();
        } while (input != 1 && input != 2);

        // System.out.println(path);
        if (input == 1) {
            String path = getProjectPath() + UPLOAD_FILES + getCertNames(UPLOAD_FILES, "", "")[0];
            crypt(key, path);
            try {
                divideFile(path, key, username);
            } catch (Exception ex) {
                System.out.println(ex.toString());
            }
            return true;
        }
        if (input == 2) {
            return false;
        }

        return false;

    }

    public static void download(KeyPair key, int n, String file, String username) {
        String path = getProjectPath();
        try {
            combineFile(key, file, username);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
        decrypt(key, file);
    }

    public static void reActivate(X509Certificate cert) {

        // boolean check=login();
        if (true) {
            try {
                removeFromCRL(cert);
            } catch (Exception ex) {
                System.out.println(ex.toString());
            }
            System.out.println("Sertifikat je uspjesno reaktiviran");
        }

    }

    public static boolean userExists(String username) {
        File folder = new File(getProjectPath() + "\\kripto_projekat\\registered users\\" + username);
        if (folder.exists() && folder.isDirectory()) {
            return true;
        } else {
            return false;
        }
    }

    public void deleteFiles() {
        {
            // specify the folder path
            String[] paths = new String[3];
            paths[0] = getProjectPath() + UPLOAD_CERT;
            paths[1] = getProjectPath() + UPLOAD_FILES;
            paths[2] = getProjectPath() + DOWNLOADS;
            for (int i = 0; i < 3; i++) {
                File folder = new File(paths[i]);
                // get a list of all the files in the folder
                File[] files = folder.listFiles();
                // loop through the list of files and delete each one
                for (File file : files) {
                    if (!file.delete()) {
                        System.out.println("Failed to delete file: " + file);
                    }
                }
            }
        }
    }

    public String getUsername() {
        return this.username;
    }

    public void setN(int n) {
        this.n = n;
    }

    public int getN() {
        return this.n;
    }

    public KeyPair getKey() {
        return this.key;
    }

    public static void movePrivate(String username) {
        moveFile(getProjectPath() + "\\kripto_projekat\\Certificates\\private\\private.key",
                getProjectPath() + "\\kripto_projekat\\registered users\\" + username + "\\private.key");
    }

}











