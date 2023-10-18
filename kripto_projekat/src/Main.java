import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.Security;

import crypto.Crypto;
import user.*;

import static crypto.Crypto.*;
import static crypto.Crypto.performSigning;
import static user.User.*;


import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Scanner keyboard = new Scanner(System.in);
        User current;
        int input = 0, input1 = 0, input2 = 0, input3 = 0;
        int trg = 0;
        int break1 = 0, break2 = 0, break3 = 0;
        if (keyboard == null) {
            System.out.println("No console available");
            System.exit(0);
        }
        System.out.println("Dobrodosli");
        System.out.println("Izaberite opciju");
        do {
            do {
                break1 = 0;
                System.out.println("1. Registracija novog naloga 2.Prijavljivanje  3.Kraj rada");
                System.out.println("Unesite broj 1 ili 2 ili 3");
                // Read line
                input = keyboard.nextInt();
            }
            while (input != 1 && input != 2 && input != 3);
            if (input == 1) {
                current = registerUser();
            }
            if (input == 2) {
                current = login();
                if (current == null);
                else {
                    movePrivate(current.getUsername());
                   // movePrivate(current.getUsername());
                    do {
                        break2 = 0;
                        System.out.println("Izaberite opciju");
                        do {
                            System.out.println("1. Pregled svih fajlova 2.Download fajlova  3.Upload fajlova 4.LogOut");
                            System.out.println("Unesite broj 1 ili 2 ili 3 ili 4");
                            // Read line
                            input1 = keyboard.nextInt();
                        }
                        while (input1 != 1 && input1 != 2 && input1 != 3 && input1 != 4);
                        if (input1 == 1) {
                            System.out.println("Spisak vasih fajlova " + current.getUsername() + ":");
                            try {
                                printDocs(current.getUsername());
                            } catch (NullPointerException ex) {
                                System.out.println("Ovaj korisnik nema fajlova");
                                // trg = 1;
                                // break;
                            } catch (Exception ex) {
                                System.out.println("Ovaj korisnik nema fajlova");
                                // da je nevalidan unos broja za fajl
                                //break;
                            }
                        }
                        if (input1 == 2) {
                            trg = 0;
                            do {
                                String[] files = null;
                                System.out.println("Izaberite koji fajl zelite skinuti");
                                try {
                                    files = printDocs(current.getUsername());
                                    System.out.println("Unesite broj ispred fajla:");
                                    input2 = keyboard.nextInt();
                                    if (files[input2] != null) {
                                        trg = 1;
                                    } else {
                                        System.out.println("Broj izvan opsega");
                                    }
                                    download(current.getKey(), current.getN(), files[input2], current.getUsername());
                                } catch (NullPointerException ex) {
                                    System.out.println("Ovaj korisnik nema fajlova");
                                    trg = 1;
                                    // break;
                                } catch (Exception ex) {
                                    System.out.println("Ovaj korisnik nema fajlova");
                                    trg = 1;
                                    // break;
                                }


                            } while (trg != 1);
                        }
                        if (input1 == 3) {
                            do {
                                break3 = 0;
                                System.out.println("Izaberite opciju");
                                do {
                                    System.out.println("1.Upload novog fajla 2.Povratak");
                                    input3 = keyboard.nextInt();
                                }
                                while (input3 != 1 && input3 != 2);
                                if (input3 == 1) {
                                    if (upload(current.getKey(), current.getUsername())) {
                                        System.out.println("Uspjesan upload fajla");
                                    } else System.out.println("Neuspjesan upload");
                                }
                                if (input3 == 2) {
                                    break3 = 1;
                                }
                            } while (break3 == 0);
                        }
                        if (input1 == 4) {
                            break2 = 1;
                            current.deleteFiles();
                        }

                    } while (break2 == 0);
                }
            }
            if (input == 3) {
                System.out.println("Kraj..");
                break1 = 1;
            }

        } while (break1 == 0);
        System.exit(0);
    }
}
