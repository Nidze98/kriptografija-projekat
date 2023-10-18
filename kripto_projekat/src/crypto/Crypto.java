package crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.math.BigInteger;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.*;
import java.util.Date;

public class Crypto {
    /* KeyUsage ::= BIT STRING {
        digitalSignature        (0),/
                nonRepudiation          (1),
                keyEncipherment         (2),/
                dataEncipherment        (3),
                keyAgreement            (4),/
                keyCertSign             (5),
                cRLSign                 (6),
                encipherOnly            (7),
                decipherOnly            (8) }*/
    public static final String CERTS = "\\kripto_projekat\\Certificates\\certs\\";
    public static final String CRL_LISTS = "\\kripto_projekat\\Certificates\\crl\\lista1.crl";
    public static final String PRIVATE_KEYS = "\\kripto_projekat\\Certificates\\private\\";

    public static final String UPLOAD_FILES = "\\kripto_projekat\\Upload_files\\";

    public static final String DOWNLOADS = "\\kripto_projekat\\Downloads\\";
    public static final String REPO = "\\kripto_projekat\\Repo\\";
    public static final String UPLOAD_CERT = "\\kripto_projekat\\Upload_cert\\";
    public static final String OLD_UPLOAD_CERT = "\\kripto_projekat\\Old_Upload_cert\\";
    public static final String ROOT = "\\kripto_projekat\\Certificates\\cacert.crt";

    public static boolean[] keyUsages = {true, false, true, true, true, false, false, false, false};

    public static KeyPair generateKeyPair()
            throws GeneralSecurityException {
        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BC");

        keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));

        return keyPair.generateKeyPair();
    }

    public static String getProjectPath() {
        Path currentRelativePath = Paths.get("");
        String s = currentRelativePath.toAbsolutePath().toString();
        //System.out.println("Current absolute path is: " + s);
        return s;
    }

    public static String hashFunction(String planeText) {
        try {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(planeText.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();

            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            // System.out.println("HES: " + hexString.toString());
            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static boolean checkHash(String planeText, String hash) {
        if (hash == null || planeText == null) {
            return false;
        }
        // System.out.println("PASSWORD" + planeText);
        // System.out.println("HASH :" + hash);
        String currentHash = hashFunction(planeText);
        if (hash.equals(currentHash)) {
            // System.out.println("HASH MATCH");
            return true;
        } else {
            //  System.out.println("NO MATCH");
            return false;
        }
    }

    public static X509Certificate issueUserCertificate(PublicKey eePublicKey, String username) throws Exception {
        String path = getProjectPath();

        PrivateKey caPrivateKey = null;
        File f = new File(path + ROOT);
        X509Certificate caCertificate = getCertificateFromFile(f);
        try {
            caPrivateKey = getCAPrivateKey(path + PRIVATE_KEYS);
        } catch (Exception ex) {
            System.out.println("Nije moguce ucitati privatni kljuc");
        }
        Security.addProvider(new BouncyCastleProvider());
        //  System.out.println(caPrivateKey);
        // Generate a certificate request for the User

        PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + username), eePublicKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caPrivateKey);
        PKCS10CertificationRequest request = requestBuilder.build(signer);

        // Generate the User certificate
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCertificate.getSubjectX500Principal(),
                BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
                new Date(System.currentTimeMillis() - 50000),   //Valid from
                new Date((long) (System.currentTimeMillis() + 181 * 8.65 * Math.pow(10, 7))), //valid to //181 days
                new X500Principal("CN=" + username), eePublicKey);
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.keyAgreement | KeyUsage.dataEncipherment));
        ContentSigner certSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(caPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        // Return the User certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate userCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
        return userCert;
    }

    public static void SaveKeyPair(String path, KeyPair keyPair) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        JcePEMEncryptorBuilder encryptorBuilder = new JcePEMEncryptorBuilder("DES-EDE3-CBC");
        PEMEncryptor encryptor = encryptorBuilder.build("sigurnost".toCharArray());
        try (JcaPEMWriter privateKeyWriter = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(path + "/private.key")))) {
            privateKeyWriter.writeObject(keyPair.getPrivate(), encryptor);
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
        // Save the public key to a file
        try (JcaPEMWriter publicKeyWriter = new JcaPEMWriter(new OutputStreamWriter(new FileOutputStream(path + "/public.key")))) {
            publicKeyWriter.writeObject(keyPair.getPublic());
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
    }

    public static KeyPair LoadKeyPair(X509Certificate cert, String real_username)
            throws Exception {

        PublicKey publicKey = cert.getPublicKey();

        PrivateKey privateKey = getPrivateKey(getProjectPath() + "\\kripto_projekat\\registered users\\" + real_username);

        return new KeyPair(publicKey, privateKey);
    }

    public static X509Certificate getCertificateFromFile(File file) {
        try {

            FileInputStream fin = new FileInputStream(file.getPath().toString());
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
            return certificate;
        } catch (Exception ex) {

            System.out.println("Exceptin NEVALIDAN SERTIFIKAT: " + ex.toString());
            //nevalidan sertifikat
            return null;
        }

    }

    public static PublicKey getPublicKey(String path) throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {

        File filePublicKey = new File(path + "/public.key");
        FileInputStream fis = new FileInputStream(path + "/public.key");
        byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
        fis.read(encodedPublicKey);
        fis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return publicKey;

    }

    public static PrivateKey getCAPrivateKey(String path) throws Exception {
        File privateKeyFile = new File(path + "/privateCA.key");
        Reader reader = new BufferedReader(new FileReader(privateKeyFile));
        PemReader pemReader = new PemReader(reader);
        byte[] keyBytes = pemReader.readPemObject().getContent();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);
        return privateKey;
    }

    public static PrivateKey getPrivateKey(String pemFilePath) throws Exception {
        PEMParser pemParser = new PEMParser(new FileReader(pemFilePath + "\\private.key"));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair keyPair;
        if (object instanceof PEMEncryptedKeyPair) {
            PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) object;
            PEMKeyPair pemKeyPair = encryptedKeyPair.decryptKeyPair(
                    new JcePEMDecryptorProviderBuilder().setProvider("BC").build("sigurnost".toCharArray()));
            keyPair = converter.getKeyPair(pemKeyPair);
        } else {
            keyPair = converter.getKeyPair((PEMKeyPair) object);
        }
        pemParser.close();
        return keyPair.getPrivate();
    }


    public static void saveX509CertBase64(final X509Certificate cert, String username) throws IOException {
        String path = getProjectPath();
        try {
            if (null == cert) {
                throw new CertException("cert can't be null");
            }
            if (null == path) {
                throw new CertException(" savePath can't be null");
            }
            JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(new FileWriter(path + CERTS + username + "_cert.crt"));
            jcaPEMWriter.writeObject(cert, null);
            jcaPEMWriter.close();
        } catch (Exception e) {
            System.out.println("save cert failed");
        }

    }

    public static File inputAndCheckCert() {
        String path = null, username = null;
        boolean check = true;
        int input;
        Scanner keyboard = new Scanner(System.in);
        if (keyboard == null) {
            System.out.println("No console available");
            return null;
        }
        System.out.println("Unos sertifikata");
        do {
            System.out.println("1. stavite sertifikat u folder Upload_certs  2. povratak");
            System.out.println("Unesite broj 1 ili 2");
            // Read line
            input = keyboard.nextInt();
        }
        while (input != 1 && input != 2);
        if (input == 1) {
            if (getCertNames(UPLOAD_CERT, "", ".crt")[0] != null) {
                path = getProjectPath() + UPLOAD_CERT + getCertNames(UPLOAD_CERT, "", ".crt")[0];
            } else {
                System.out.println("Nema fajlova u folderu Upload");
                return null;
            }

        }
        if (input == 2) {
            System.out.println("povratak....");
            //Scanner keyboard1 = new Scanner(System.in);
            //path = keyboard.nextLine();
            return null;
        }

        try {
            File selectedCert = new File(path);
            // System.out.println("SELECETD FILE: " + selectedCert.toString());
            String[] certs = getCertNames(UPLOAD_CERT, "", ".crt");
            for (String cert : certs) {

                File realCert = new File(getProjectPath() + CERTS + cert);
                //   System.out.println("USER's CERT: " + realCert.getAbsolutePath());
                byte[] f1 = Files.readAllBytes(Paths.get(selectedCert.getPath()));
                byte[] f2 = Files.readAllBytes(Paths.get(realCert.getAbsolutePath()));
                boolean equalFiles = Arrays.equals(f1, f2);
                if (equalFiles) {
                    //username=getCNFromCertificateFile(realCert);
                    if (checkValidityOfCertitiface(selectedCert)) {
                        System.out.println("Validan sertifikat");
                        // moveFile(path, getProjectPath() + OLD_UPLOAD_CERT + getCertNames(UPLOAD_CERT,"",".crt")[0]);
                        return realCert;
                    } else {
                        System.out.println("Nije validan sertifikat");
                        //check= false;
                    }
                  /*  check = true;
                    break;*/
                }
                //check = false;
            }
            moveFile(path, getProjectPath() + OLD_UPLOAD_CERT + getCertNames(UPLOAD_CERT, "", ".crt")[0]);
        } catch (Exception ex) {
            System.out.println("Exception prilikom utvrdjivanja validnosti digitalnog serifikata-> ");
            return null;
            //check = false;
        }
        return null;
    }

    public static boolean checkValidityOfCertitiface(File fileCert) {

        try {

            X509Certificate certificate = getCertificateFromFile(fileCert);
            if (certificate == null) {
                System.out.println("certificate is null");
                return false;
            }
            //provjera validnosti
            certificate.checkValidity();

            //provjera da li je izdat sertifikat od strane naseg CA tijela

            X509Certificate certificateCA = getCertificateFromFile(new File(getProjectPath() + ROOT));
            if (certificateCA == null) {
                System.out.println("CA nije dostupan");
                return false;
            }
            PublicKey publicKeyCA = certificateCA.getPublicKey();

            certificate.verify(publicKeyCA);

            //provjera da li se nalazi na CRL listi

            File crlListFile = new File(getProjectPath() + CRL_LISTS);
            byte[] crlBytes = Files.readAllBytes(Paths.get(crlListFile.getPath()));

            InputStream inStream = new ByteArrayInputStream(crlBytes);
            CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
            X509CRL crlList = (X509CRL) cf2.generateCRL(inStream);

            //X509CRL crlList;
            if (crlList.isRevoked(certificate)) {
                throw new CertificateException("Certificate revoked");
            }
            if (!(checkKeyUsages(certificate, keyUsages))) {
                throw new CertificateException("Certificate doesn have valid key usage");
            }


            System.out.println("Sertifikat ima potrebne keyUsages");
        } catch (Exception ex) {

            System.out.println("Exceptin NEVALIDAN SERTIFIKAT: " + ex.toString());
            //nevalidan sertifikat
            return false;
        }

        return true;
    }

    public static String[] getCertNames(String s, String prefix, String ext) throws ArrayIndexOutOfBoundsException {
        File upload = new File(getProjectPath() + s);
        if (upload == null) {
            return null;
        }
        try {
            String[] files = upload.list(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    if (prefix.equals("")) {
                        return name.endsWith(ext);
                    } else {
                        return name.endsWith(ext) && name.startsWith(prefix);
                    }
                }

            });
            return files;
        } catch (Exception ex) {
            System.out.println("Nema fajlova u folderu Upload");
        }
        return null;
    }

    public static void moveFile(String sourcePath, String destPath) {
        File sourceFile = new File(sourcePath);
        File destinationFile = new File(destPath);
        if (sourceFile.renameTo(destinationFile)) {
            //System.out.println("File moved successfully.");
        } else {
            //System.out.println("Failed to move the file.");
        }
    }


    public static String getCNFromCertificateFile(File certificateFile) {
        try (FileInputStream inputStream = new FileInputStream(certificateFile)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
            X500Name subject = holder.getSubject();
            String cn = subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
            return cn;
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String readTextFile(String filePath) {
        try {
            byte[] encoded = Files.readAllBytes(Paths.get(filePath));
            return new String(encoded);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getUserInfo(String name) {
        String path = getProjectPath() + "\\kripto_projekat\\registered users\\" + name + "\\" + name + "_podaci.txt";
        String password = readTextFile(path);
        //TODO mora ici hash
        return password.strip();
    }

    public static void crypt(KeyPair keyPair, String path_input) {
        // String path=getProjectPath() + UPLOAD_FILES + "New Text Document.txt";

        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

            FileInputStream fis = new FileInputStream(path_input);
            byte[] input = new byte[(int) new File(path_input).length()];
            fis.read(input);

            byte[] encrypted = cipher.doFinal(input);

            FileOutputStream fos = new FileOutputStream(path_input + ".encrypted");
            fos.write(encrypted);

            fis.close();
            fos.close();
        } catch (Exception ex) {
            System.out.println("greska" + ex.toString());
        }

    }

    public static void decrypt(KeyPair key, String file) {
        String path_crypted_input = getProjectPath() + UPLOAD_FILES + file + "_combined";
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key.getPrivate());

            FileInputStream fis = new FileInputStream(path_crypted_input);
            byte[] input = new byte[(int) new File(path_crypted_input).length()];
            fis.read(input);

            byte[] decrypted = cipher.doFinal(input);

            //FileOutputStream fos = new FileOutputStream(filePath.replace(".encrypted", ""));
            FileOutputStream fos = new FileOutputStream(getProjectPath() + DOWNLOADS + file);
            fos.write(decrypted);

            fis.close();
            fos.close();
        } catch (Exception ex) {
            System.out.println(ex.toString());
        }
    }

    public static void performSigning(KeyPair keyPair, String path_input) throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        PrivateKey privateKey = keyPair.getPrivate();
        sign.initSign(privateKey);
        byte[] data = Files.readAllBytes(Paths.get(path_input));
        sign.update(data);
        byte[] signature = sign.sign();
        Files.write(Paths.get(path_input + ".sig"), signature);
    }

    public static Boolean performVerification(KeyPair key, String path_input, String path_sig)
            throws Exception {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(key.getPublic());
        byte[] data = Files.readAllBytes(Paths.get(path_input));
        sign.update(data);
        byte[] signature = Files.readAllBytes(Paths.get(path_sig));
        return sign.verify(signature);
    }

    public static void divideFile(String f1, KeyPair key, String username) throws IOException {
        String[] filename = getCertNames(UPLOAD_FILES, "", ".encrypted");

        BufferedInputStream in = new BufferedInputStream(new FileInputStream(getProjectPath() + UPLOAD_FILES + filename[0]));//+".encrypted"
        int n = randomNumber(in.available());
        //  System.out.println(n);
        int[] chunkSizes = sumArray(in.available(), n);

        for (int i = 0; i < n; i++) {
            //TODO rijesiti path elegentije
            File f = new File(getProjectPath() + REPO + "repo_" + i);
            // check if the directory can be created
            // using the specified path name
            if (f.mkdir() == true) {
                //System.out.println("Directory has been created successfully");
            }
            f1 = f.getAbsolutePath();
            int chunkSize = chunkSizes[i];
            byte[] chunk = new byte[chunkSize];

            int count = in.read(chunk);
            // chunk=crypt(key,chunk);
            BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(f1 + "//" + username + "_" + filename[0] + "_part_" + i));
            out.write(chunk, 0, count);
            out.close();
            try {
                performSigning(key, f1 + "//" + username + "_" + filename[0] + "_part_" + i);
            } catch (Exception ex) {
                System.out.println("Nije moguce potpisati fajl" + ex.toString());
            }
        }

        in.close();

    }

    public static boolean combineFile(KeyPair key, String file, String username) throws IOException {
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(getProjectPath() + UPLOAD_FILES + file + "_combined"));
        int n = calculateN(key, 10, file, username);
        boolean check = true;
        for (int i = 0; i < n; i++) {
            try {
               /* System.out.println(getProjectPath() + REPO + "repo_" + i
                        + "//"  +username+"_"+file+ ".encrypted_part_" + i);*/
                check = performVerification(key, getProjectPath() + REPO + "repo_" + i
                        + "//" + username + "_" + file + ".encrypted_part_" + i, getProjectPath() + REPO + "repo_" + i
                        + "//" + username + "_" + file + ".encrypted_part_" + i + ".sig");
                if (!check) {
                    break;
                }
            } catch (Exception ex) {
                System.out.println("Nije moguce verifikovati potpis, fajlovi mijenjani");
            }

        }
        if (check) {
            System.out.println("Fajlovi su originalni");
            System.out.println("Uspjesno skidanje sa repozitorijuma");
        }
        else {
            System.out.println("Nije moguce verifikovati potpis, fajlovi mijenjani");
            return false;
        }

        for (int i = 0; i < n && check; i++) {
            ;

            BufferedInputStream in = new BufferedInputStream(new FileInputStream(getProjectPath() + REPO + "repo_" + i
                    + "//" + username + "_" + file + ".encrypted_part_" + i));
            int count;
            byte[] chunk = new byte[4096];

            while ((count = in.read(chunk)) != -1) {
                // chunk=decrypt(key, prefix,chunk);
                out.write(chunk, 0, count);
            }

            in.close();
        }

        out.close();
        return true;
    }

    public static int[] sumArray(int num, int n) {
        int[] result = new int[n];
        int current = num / n;
        int remainder = num % n;

        for (int i = 0; i < n; i++) {
            result[i] = current;
        }

        for (int i = 0; i < remainder; i++) {
            result[i] = result[i] + 1;
        }

        return result;
    }

    public static int randomNumber(int n) {
        Random rand = new Random();
        if (n > 10)
            n = 10;//radi jednostavnosti
        int randomNum;
        do {
            randomNum = rand.nextInt(n);
        }
        while (randomNum < 4);
        return randomNum;
    }

    public static X509Certificate getCaCertificate() {
        File f = new File(getProjectPath() + ROOT);
        X509Certificate caCertificate = getCertificateFromFile(f);
        return caCertificate;
    }

    public static X509CRL getCRL() throws Exception {
        // Load the CRL from file
        String crlFile = getProjectPath() + CRL_LISTS;
        FileInputStream fis = new FileInputStream(crlFile);
        X509CRLHolder crlHolder = new X509CRLHolder(Streams.readAll(fis));
        fis.close();

        // Convert the X509CRLHolder to X509CRL
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlHolder);

        return crl;
    }

    public static void createCRL() throws Exception {
        // Create the CRL builder

        X509Certificate caCertificate = getCaCertificate();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder(caCertificate).getSubject(), new Date());

        // Sign the CRL
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(getCAPrivateKey(getProjectPath() + PRIVATE_KEYS));
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

        // Save the CRL to a file
        FileOutputStream fos = new FileOutputStream(getProjectPath() + CRL_LISTS);
        fos.write(crl.getEncoded());
        fos.close();
    }

    public static void addToCRL(X509Certificate certificateToRevoke) throws Exception {
        // Load the existing CRL from file

        X509Certificate caCert = getCaCertificate();
        X509CRL crl = getCRL();
        // Create a list of revoked certificates
        List<X509Certificate> revokedCertificates = new ArrayList<>();
        revokedCertificates.add(certificateToRevoke);

        // Create the CRL builder
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder(caCert).getSubject(), new Date());

        // Add the revoked certificates to the CRL
        for (X509Certificate revokedCertificate : revokedCertificates) {
            crlBuilder.addCRLEntry(revokedCertificate.getSerialNumber(), new Date(), CRLReason.CERTIFICATE_HOLD.ordinal());
        }

        // Sign the CRL
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(getCAPrivateKey(getProjectPath() + PRIVATE_KEYS));
        X509CRL newCRL = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

        // Save the new CRL to a file
        FileOutputStream fos = new FileOutputStream(getProjectPath() + CRL_LISTS);
        fos.write(newCRL.getEncoded());
        fos.close();
    }

    public static void removeFromCRL(X509Certificate certificateToRemove) throws Exception {
        X509Certificate caCert = getCaCertificate();
        X509CRL crl = getCRL();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder(caCert).getSubject(), crl.getThisUpdate());
        for (X509CRLEntry entry : crl.getRevokedCertificates()) {
            if (!entry.getSerialNumber().equals(certificateToRemove.getSerialNumber())) {
                crlBuilder.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(), null);
                if (entry.hasExtensions()) {
                    Set<String> criticalExtensionOIDs = entry.getCriticalExtensionOIDs();
                    if (criticalExtensionOIDs != null) {
                        for (String oid : criticalExtensionOIDs) {
                            byte[] extValue = entry.getExtensionValue(oid);
                            ASN1InputStream asn1In = new ASN1InputStream(extValue);
                            ASN1Encodable extensionValue = asn1In.readObject();
                            asn1In.close();
                            crlBuilder.addExtension(new ASN1ObjectIdentifier(oid), true, extensionValue);
                        }
                    }
                }
            }
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(getCAPrivateKey(getProjectPath() + PRIVATE_KEYS));
        X509CRL newCRL = new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));

        FileOutputStream fos = new FileOutputStream(getProjectPath() + CRL_LISTS);
        fos.write(newCRL.getEncoded());
        fos.close();
    }

    public static boolean isRevoked(X509Certificate certificate) throws Exception {
        // Load the CRL from file
        X509CRL crl = getCRL();
        // Check if the certificate is revoked
        return crl.isRevoked(certificate);
    }

    public static boolean checkKeyUsages(X509Certificate certificate, boolean[] keyUsages) {
        boolean[] keyUsageCurrentCertificate = certificate.getKeyUsage();


       /* for(int i = 0;i < keyUsages.length;i++){
            System.out.println("Vrijednost " + i + " = " + keyUsageCurrentCertificate[i]);
        }*/
        for (int i = 0; i < keyUsages.length; i++) {
            if (keyUsages[i] == true && keyUsageCurrentCertificate[i] == false) {
                System.out.println("Sertifikat nema potrebane keyUsages");
                return false;
            }
        }
        return true;
    }

    public static String[] printDocs(String username) throws Exception {

        String path = REPO + "repo_0\\";
        String[] files = getCertNames(path, username + "_", ".encrypted_part_0");

        System.out.println("#################################################################");
        for (int i = 0; i < files.length; i++) {
            files[i] = removePrefixSuffix(files[i], username + "_", ".encrypted_part_0");
            System.out.println(i + ". " + files[i]);
        }
        System.out.println("#################################################################");
        if (files[0] == "") {
            throw new NullPointerException();
        }
        return files;

    }

    public static String removePrefixSuffix(String str, String prefix, String suffix) {
        if (str.startsWith(prefix)) {
            str = str.substring(prefix.length());
        }
        if (str.endsWith(suffix)) {
            str = str.substring(0, str.length() - suffix.length());
        }
        return str;
    }

    public static int calculateN(KeyPair key, int n, String file, String username) {
        boolean check;

        for (int i = 0; i < n; i++) {
            try {
               /* System.out.println(getProjectPath() + REPO + "repo_" + i
                        + "//" + username + "_" + file + ".encrypted_part_" + i);*/
                check = performVerification(key, getProjectPath() + REPO + "repo_" + i
                        + "//" + username + "_" + file + ".encrypted_part_" + i, getProjectPath() + REPO + "repo_" + i
                        + "//" + username + "_" + file + ".encrypted_part_" + i + ".sig");
            } catch (NoSuchFileException ex) {
                return i;
            } catch (Exception ex) {
                System.out.println("Greska");
            }
        }
        return n;
    }
}



