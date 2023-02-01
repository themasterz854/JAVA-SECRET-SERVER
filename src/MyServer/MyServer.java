package MyServer;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static MyServer.MyServer.*;
import static java.lang.Character.toLowerCase;

class rsa {
    KeyPairGenerator generator;
    KeyPair pair;
    PrivateKey privateKey;
    PublicKey publicKey;
    KeyFactory keyFactory;


    rsa() {
        try {
            generator = KeyPairGenerator.getInstance("RSA");
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        generator.initialize(2048);
        pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        FileOutputStream fos;
        try {
            fos = new FileOutputStream("public.key");
            fos.write(publicKey.getEncoded());
            fos.close();
            fos = new FileOutputStream("private.key");
            fos.write(privateKey.getEncoded());
            fos.close();

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        privateKey = null;
        publicKey = null;
        System.out.println("Keys generated");
    }

    public void getPublickey() {
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes;
        try {
            publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            this.publicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }


    }

    public void getPrivatekey() {
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes;
        try {
            privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            this.privateKey = keyFactory.generatePrivate(privateKeySpec);

        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public String encrypt(String message, PublicKey publicKey) {
        Cipher encryptCipher;
        try {
            encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretMessageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
            String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
            System.out.println(encodedMessage);
            return encodedMessage;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public String decrypt(String encryptedmessage, PrivateKey privateKey) {
        Cipher decryptCipher;
        String decryptedMessage;
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedmessage);

        try {
            decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
            decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        return decryptedMessage;
    }

}

class AES {

    protected String encryptionKey;
    private static final String characterEncoding = "UTF-8";
    private static final String cipherTransformation = "AES/CBC/PKCS5PADDING";
    private static final String aesEncryptionAlgorithm = "AES";

    public AES() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[12];
        random.nextBytes(bytes);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        encryptionKey = encoder.encodeToString(bytes);

        System.out.println(encryptionKey.length() + "\n" + encryptionKey);
    }

    public String encrypt(String plainText) {

        String encryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);

            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithm);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder encoder = Base64.getEncoder();
            encryptedText = encoder.encodeToString(cipherText);

        } catch (Exception E) {
            System.err.println("Encrypt Exception : " + E.getMessage());
        }
        return encryptedText;
    }

    public byte[] encrypt(byte[] plainText) {
        byte[] encryptedBytes = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithm);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec);
            byte[] cipherText = cipher.doFinal(plainText);
            Base64.Encoder encoder = Base64.getEncoder();
            encryptedBytes = encoder.encode(cipherText);

        } catch (Exception E) {
            System.err.println("Encrypt Exception : " + E.getMessage());
        }
        return encryptedBytes;
    }

    public String decrypt(String encryptedText) {
        String decryptedText = "";
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithm);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] cipherText = decoder.decode(encryptedText);
            decryptedText = new String(cipher.doFinal(cipherText), StandardCharsets.UTF_8);

        } catch (Exception E) {
            System.err.println("Decrypt Exception : " + E.getMessage());
        }
        return decryptedText;
    }

    public byte[] decrypt(byte[] encryptedText) {
        byte[] decryptedText = new byte[0];
        try {
            Cipher cipher = Cipher.getInstance(cipherTransformation);
            byte[] key = encryptionKey.getBytes(characterEncoding);
            SecretKeySpec secretKey = new SecretKeySpec(key, aesEncryptionAlgorithm);
            IvParameterSpec ivparameterspec = new IvParameterSpec(key);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec);
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] cipherText = decoder.decode(encryptedText);
            decryptedText = cipher.doFinal(cipherText);

        } catch (Exception E) {
            System.err.println("Decrypt Exception : " + E.getMessage());
        }
        return decryptedText;
    }


}

class CustomSocket {
    private Socket s;
    private int id;

    CustomSocket() {
        id = -1;
    }

    private String username;

    public void setSocket(Socket s) {
        this.s = s;
    }

    public void setid(int id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Socket getSocket() {
        return s;
    }

    public int getid() {
        return id;
    }

    public String getusername() {
        return username;
    }
}
class Encryptor{

    public String encrypt(String data){
        String random1 = "!%*#(}]";
        String random2 = "@$^&)[\\";
        String random3 = "<>?:;_{|`";
        char[] encrypteddata;
        Random random = new Random();
        IntStream randomint = random.ints(10,0,9);
        int[] randomarray = randomint.toArray();
        int randomiterator = 0;
        encrypteddata = new char[900];
        int i,j=0,n,f;
        char c,en = 'a';
        n = data.length();
        for(i =0; i<n; i++) {
            c = data.charAt(i);
            if (c >= '0' && c <= '9') {
                switch (c) {
                    case '1' -> en = 'u';
                    case '2' -> en = 'L';
                    case '3' -> en = 'z';
                    case '4' -> en = 'A';
                    case '5' -> en = 'n';
                    case '6' -> en = 'P';
                    case '7' -> en = 's';
                    case '8' -> en = 'G';
                    case '9' -> en = 'w';
                    case '0' -> en = 'I';
                }
            } else if (c == ' ') {
                en = '\"';
            } else if (c == '\n') {
                en = '~';
            } else if (c == '.') {
                en = '/';
            } else if (c == ',') {
                en = '=';
            } else {
                if (c >= 'a' && c <= 'z') {

                    encrypteddata[j++] = random3.charAt(randomarray[randomiterator++ % 10] % 8);

                }
                if (c >= 'a' && c <= 'z') {
                    f = Character.toUpperCase(c) - 16;
                } else {
                    f = c - 16;
                }
                if(f >= 58  && f <67) {

                    encrypteddata[j++] = random1.charAt(randomarray[randomiterator++ % 10] % 7);
                    en = (char)(f-9);
                } else if(f >= 67 && f <=74) {

                    encrypteddata[j++] = random2.charAt(randomarray[randomiterator++ % 10] % 7);
                    en = (char)(f - 18);
                } else
                    en = (char)f;
            }
            encrypteddata[j++] = en;
        }
        String encryptedstr = new String(encrypteddata);
        encryptedstr = encryptedstr.trim();
        return encryptedstr;
    }
}
class Decryptor{
    public String decrypt(String data){
        char[] decrypteddata = new char[900];
        int i,j,n,flag ,f;
        char c;
        n = data.length();
        j =0;
        for(i=0; i<n; i++) {
            flag = 0;
            c = data.charAt(i);
            if (c == '~') {
                decrypteddata[j++] = '\n';
                continue;
            }
            if (c == '\"') {
                decrypteddata[j++] = ' ';
                continue;
            }
            if (c == '/') {
                decrypteddata[j++] = '.';
                continue;
            }
            if (c == '=') {
                decrypteddata[j++] = ',';
                continue;
            }

            if (c == '<' || c == '>' || c == '?' || c == ':' || c == ';' || c == '_' || c == '{' || c == '|' || c == '`') {
                flag = 1;
                c = data.charAt(++i);
            }
            if (c == '@' || c == '$' || c == '^' || c == '&' || c == ')' || c == '[' || c == '\\') {
                c = data.charAt(++i);
                f = c + 16;
                c = (char) (f + 18);

            } else if(c == '!' || c == '#' || c == '%' || c == '*' || c == '(' || c == '}' || c == ']') {
                c = data.charAt(++i);
                f = c + 16;
                c = (char)(f+9);
            } else if(c >= '0' && c <= '9') {
                f = c +16;
                c = (char)f;
            } else {
                switch (c) {
                    case 'u' -> c = '1';
                    case 'L' -> c = '2';
                    case 'z' -> c = '3';
                    case 'A' -> c = '4';
                    case 'n' -> c = '5';
                    case 'P' -> c = '6';
                    case 's' -> c = '7';
                    case 'G' -> c = '8';
                    case 'w' -> c = '9';
                    case 'I' -> c = '0';
                    default -> {
                    }
                }
            }
            if (flag == 1 && (c >= 'A' && c <= 'Z')) {
                c  = toLowerCase(c);
            }
            decrypteddata[j++] = c;
        }
        data = new String(decrypteddata);
        data = data.trim();
        return data;
    }

}
class Sync{
    Sync(){

    }
}
class Manager extends Thread {


    private final CustomSocket sc;
    private final CustomSocket[] so;
    private final int[] numberofsockets ;
    private final String[] onlineusers ;
    private final Decryptor dec = new Decryptor();
    private final Encryptor en = new Encryptor();


    Manager(CustomSocket sc, int id, CustomSocket[] so,int[] numberofsockets,String[] onlineusers){
        this.sc = sc;
        this.so = so;
        this.sc.setid(id);
        this.numberofsockets = numberofsockets;
        this.onlineusers = onlineusers;
    }

    public void run() {
        try {
            int i;
            int count;
            int chatid;
            String str = null;
            DataInputStream din = new DataInputStream(sc.getSocket().getInputStream());
            DataOutputStream dout = new DataOutputStream(sc.getSocket().getOutputStream());
            DataOutputStream[] RSdout = new DataOutputStream[10] ;
            DataOutputStream curr_RSdout = dout;
            String FileName;
            StringBuilder NASfilelist;
            boolean p;
            long FileSize;

            for (i = 0; i < 10; i++) {
                RSdout[i] = null;
            }
            String[] data;
            int encryptflag = 0;
            StringBuilder hash;
            int exitflag = 0;
            while (true) {

                if (exitflag == 0) {
                    str = aes.decrypt(din.readUTF());
                }
                p = Pattern.matches("%[a-zA-Z]*%", str);
                System.out.println("client " + sc.getid() + " says: " + str);
                if (p) {
                    if (str.equals("%enableencryption%")) {
                        encryptflag = 1;
                        continue;
                    }
                    if (str.equals("%disableencryption%")) {
                        encryptflag = 0;
                        continue;
                    }
                    if (str.equals("%decrypt%")) {
                        str = aes.decrypt(din.readUTF());
                        dout.writeUTF(aes.encrypt(dec.decrypt(str)));
                        dout.flush();
                        continue;
                    }

                    if (str.equals("%exit%")) {
                        dout.writeUTF(aes.encrypt("exit"));
                        synchronized (synchronizer) {
                            for (i = 0; i < 10; i++) {
                                if (so[i].getid() == sc.getid()) {
                                    System.out.println("exitting " + sc.getid());
                                    System.out.println("number of sockets is " + numberofsockets[0]);
                                    RSdout[i] = null;
                                    so[i].setid(-1);
                                    so[i].setSocket(null);
                                    so[i].setUsername(null);
                                    numberofsockets[0]--;
                                    onlineusers[i] = null;
                                    System.out.println("number of sockets is " + numberofsockets[0]);
                                    break;
                                }
                            }
                            break;
                        }
                    } else if (str.equals("%NAS%")) {
                        NASfilelist = new StringBuilder("%NAS%");
                        File[] contents = new File[0];
                        while (NASfilelist.toString().equals("%NAS%")) {
                            contents = NASSource.listFiles();
                            NASfilelist = new StringBuilder();
                            assert contents != null;
                            for (File f : contents) {
                                if (f.getName().equals("System Volume Information")) {
                                    continue;
                                }
                                NASfilelist.append(f.getName()).append("\n");
                            }
                            System.out.println(NASfilelist);
                            dout.writeUTF(aes.encrypt(NASfilelist.toString()));
                            dout.flush();
                            NASfilelist = new StringBuilder(aes.decrypt(din.readUTF()));
                        }
                        if (NASfilelist.toString().equals("%exit%")) {
                            str = "%exit%";
                            exitflag = 1;
                            continue;

                        }
                        String command = aes.decrypt(din.readUTF());
                        if (command.equals("%receive%")) {
                            System.out.println(NASfilelist);
                            String[] NASFileArray = NASfilelist.toString().split("\n");
                            File[] NASFileObjects = new File[NASFileArray.length];
                            int j;
                            j = 0;
                            for (String s : NASFileArray) {
                                File f;
                                for (File file : contents) {
                                    if (file.getName().equals(s)) {
                                        f = new File(file.getAbsolutePath());
                                        NASFileObjects[j++] = f;
                                        break;
                                    }
                                }
                            }
                            long totalsize;
                            totalsize = 0;

                            for (File f : NASFileObjects) {
                                totalsize += f.length();
                            }
                            dout.writeUTF(aes.encrypt(Long.toString(totalsize)));
                            dout.flush();
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            for (File f : NASFileObjects) {
                                FileSize = f.length();
                                FileInputStream fis = new FileInputStream(f);
                                dout.writeUTF(aes.encrypt("%NASFile%"));
                                dout.flush();
                                dout.writeUTF(aes.encrypt(f.getName()));
                                dout.flush();
                                int read;
                                byte[] sendData = new byte[FileBufferSize];
                                byte[] readbytes;
                                byte[] encryptedSendData;
                                while ((read = fis.read(sendData)) > 0) {
                                    readbytes = new byte[read];
                                    System.arraycopy(sendData, 0, readbytes, 0, read);
                                    md.update(readbytes);
                                    encryptedSendData = aes.encrypt(readbytes);
                                    int encryptedsize = encryptedSendData.length;
                                    dout.writeUTF(aes.encrypt(Integer.toString(read)));
                                    dout.flush();
                                    dout.writeUTF(aes.encrypt(Integer.toString(encryptedsize)));
                                    dout.flush();
                                    dout.write(encryptedSendData, 0, encryptedsize);
                                    dout.flush();
                                    System.out.println("sent bytes " + read);
                                    System.out.println(aes.decrypt(din.readUTF()));
                                }
                                dout.writeUTF(aes.encrypt(Integer.toString(read)));
                                dout.flush();
                                System.out.println("sent the file");
                                byte[] digest = md.digest();
                                hash = new StringBuilder();
                                for (byte x : digest) {
                                    hash.append(String.format("%02x", x));
                                }
                                dout.writeUTF(aes.encrypt(hash.toString()));
                                dout.flush();
                                sendData = readbytes = encryptedSendData = null;
                                System.gc();
                            }
                        } else if (command.equals("%delete%")) {
                            String[] NASFileArray = NASfilelist.toString().split("\n");
                            for (String s : NASFileArray) {
                                File f = null;
                                for (File file : contents) {
                                    if (file.getName().equals(s)) {
                                        f = new File(file.getAbsolutePath());
                                        break;
                                    }
                                }
                                synchronized (filesynchronizer) {
                                    f.delete();
                                    if (!SourceDown) {
                                        f = new File(NASBunker + "/" + f.getName());
                                        f.delete();
                                    }
                                    dout.writeUTF(aes.encrypt("Deleted file " + f.getName()));
                                    dout.flush();
                                }
                                f = null;
                            }
                            dout.writeUTF(aes.encrypt("All the Files have been DELETED"));
                            dout.flush();
                        }
                    } else if (str.equals("%file%")) {
                        int n = Integer.parseInt(aes.decrypt(din.readUTF()));
                        for (i = 0; i < n; i++) {
                            synchronized (synchronizer) {
                                dout.writeUTF(aes.encrypt("READ filessize"));
                                dout.flush();
                                FileName = aes.decrypt(din.readUTF());
                                byte[] receivedData;
                                int received;
                                int actualreceived;
                                curr_RSdout.writeUTF(aes.encrypt("%file%"));
                                curr_RSdout.flush();
                                curr_RSdout.writeUTF(aes.encrypt(FileName));
                                curr_RSdout.flush();
                                while (true) {
                                    actualreceived = Integer.parseInt(aes.decrypt(din.readUTF()));
                                    if (actualreceived < 0) {
                                        break;
                                    }
                                    received = Integer.parseInt(aes.decrypt(din.readUTF()));
                                    receivedData = new byte[received];
                                    System.gc();
                                    din.readFully(receivedData);
                                    curr_RSdout.writeUTF(aes.encrypt(Integer.toString(actualreceived)));
                                    curr_RSdout.flush();
                                    curr_RSdout.writeUTF(aes.encrypt(Integer.toString(received)));
                                    curr_RSdout.flush();
                                    curr_RSdout.write(receivedData, 0, received);
                                    curr_RSdout.flush();
                                    System.out.println("sent partial bytes" + actualreceived);
                                    dout.writeUTF(aes.encrypt("ACK"));
                                    dout.flush();
                                }

                                curr_RSdout.writeUTF(aes.encrypt(Integer.toString(actualreceived)));
                                curr_RSdout.flush();
                                hash = new StringBuilder(din.readUTF());
                                curr_RSdout.writeUTF(hash.toString());
                                curr_RSdout.flush();
                                receivedData = null;
                            }
                        }
                    } else if (str.equals("%NASupload%")) {
                        synchronized (filesynchronizer) {
                            int n = Integer.parseInt(aes.decrypt(din.readUTF()));
                            for (i = 0; i < n; i++) {
                                dout.writeUTF(aes.encrypt("READ filessize"));
                                dout.flush();
                                String filename = aes.decrypt(din.readUTF());
                                File f = new File(NASSource + filename);
                                File g = new File(NASBunker + filename);
                                FileOutputStream fos = new FileOutputStream(f);
                                FileOutputStream gos = new FileOutputStream(g);

                                byte[] receivedData;
                                int received;
                                int actualreceived;
                                while (true) {
                                    actualreceived = Integer.parseInt(aes.decrypt(din.readUTF()));
                                    if (actualreceived < 0) {
                                        break;
                                    }
                                    received = Integer.parseInt(aes.decrypt(din.readUTF()));
                                    receivedData = new byte[received];
                                    din.readFully(receivedData);
                                    receivedData = aes.decrypt(receivedData);
                                    fos.write(receivedData);
                                    gos.write(receivedData);
                                    System.out.println("received partial bytes" + actualreceived);
                                    dout.writeUTF(aes.encrypt("ACK"));
                                    dout.flush();
                                }
                                System.out.println("receiving hash " + aes.decrypt(din.readUTF()));
                                fos.close();
                                gos.close();
                                receivedData = null;
                                f = g = null;
                                fos = gos = null;
                                System.out.println("received the file " + filename);
                                System.gc();
                            }
                        }

                    } else if (str.equals("%list%")) {
                        count = 0;
                        for (i = 0; count < numberofsockets[0]; i++) {

                            if ((so[i].getid() == sc.getid())) {
                                count++;
                                continue;
                            }
                            if (so[i].getid() == -1) {
                                continue;
                            }
                            if (RSdout[i] == null) {
                                synchronized (synchronizer) {
                                    RSdout[i] = new DataOutputStream(so[i].getSocket().getOutputStream());
                                }

                            }
                            dout.writeUTF(aes.encrypt((so[i].getusername() + " " + so[i].getid())));
                            dout.flush();
                            count++;
                        }
                        System.out.println("end of list");
                        dout.writeUTF(aes.encrypt("end of list"));
                        dout.flush();
                    } } else {
                    synchronized (synchronizer) {
                        data = str.split(" ");
                        if (data[0].equals("%chat%")) {
                            chatid = Integer.parseInt(data[1]);
                            curr_RSdout = RSdout[chatid];
                        } else if (data[0].equals("%others%")) {
                            data = str.split("%others% ");
                            dout.writeUTF(aes.encrypt(data[1]));
                            dout.flush();
                        } else {
                            if (encryptflag == 1)
                                curr_RSdout.writeUTF(aes.encrypt((sc.getid() + " " + en.encrypt(str))));
                            else
                                curr_RSdout.writeUTF(aes.encrypt((sc.getid() + " " + str)));
                            curr_RSdout.flush();
                        }
                    }
                }
                System.gc();
            }
            din.close();
            dout.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
class Connector extends Thread{
    private final ServerSocket ss;
    private final CustomSocket[] so;
    private final File passfile = new File(System.getProperty("user.home").replace('\\', '/') + "/Desktop/uspass.txt");
    private final int[] numberofsockets = new int[1];
    private String[] filedata;

    Connector(ServerSocket ss, CustomSocket[] so) {
        this.ss = ss;
        this.so = so;
    }

    public void run() {
        Socket testsocket;
        String data;
        String[] userdata;
        DataOutputStream dout;
        DataInputStream din;
        Scanner filereader ;
        int i ;
        int j;
        numberofsockets[0] = 0;
        int n = so.length;

        int flag = 1;
        String str,newusername,newpassword;
        String[] onlineusers = new String[10];
        Decryptor dec = new Decryptor();
        Encryptor enc = new Encryptor();
        while(true) {

            try {
                testsocket = ss.accept();
                for (i = 0; i < n; i++) {
                    if (so[i].getid() == -1) {
                        so[i].setSocket(testsocket);
                        System.out.println("id assigned " + i);
                        break;
                    }
                }

                dout = new DataOutputStream(so[i].getSocket().getOutputStream());
                din = new DataInputStream(so[i].getSocket().getInputStream());


                File publicKeyFile = new File("public.key");
                byte[] publicKeyBytes;
                publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                dout.writeInt(publicKeyBytes.length);
                dout.flush();
                dout.write(publicKeyBytes);
                System.out.println("sent public key\n");
                dout.flush();

                int keylength;
                keylength = din.readInt();
                byte[] publickeyBytes = new byte[keylength];
                din.read(publickeyBytes, 0, keylength);
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publickeyBytes);
                System.out.println("receive public key\n");
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey publickey = keyFactory.generatePublic(publicKeySpec);
                    dout.writeUTF(rsaobj.encrypt(aes.encryptionKey, publickey));
                    dout.flush();
                    System.out.println("sent aes key\n");
                } catch (IOException e) {
                    e.printStackTrace();
                    System.exit(-1);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    throw new RuntimeException(e);
                }
                str = aes.decrypt(din.readUTF());
                if (str.equals("%exit%")) {
                    System.out.println("Client exited");
                    continue;
                }
                if (str.equals("%newaccount%")) {
                    int existflag = 0;
                    System.out.println("new account");
                    FileWriter filewriter = new FileWriter(passfile, true);
                    newusername = aes.decrypt(din.readUTF());
                    newpassword = aes.decrypt(din.readUTF());
                    filereader = new Scanner(passfile);
                    while (filereader.hasNextLine()) {
                        data = filereader.nextLine();
                        data = dec.decrypt(data);
                        filedata = data.split(" ");
                        if (filedata[0].equals(newusername)) {
                            System.out.println("EXISTS");
                            dout.writeUTF(aes.encrypt("exists"));
                            dout.flush();
                            existflag = 1;
                            break;
                        }
                    }
                    filereader.close();
                    if (existflag == 1) {
                        filewriter.close();
                        continue;
                    }
                    filewriter.write(enc.encrypt(newusername + " " + newpassword) + "\n");
                    filewriter.flush();
                    filewriter.close();
                    dout.writeUTF(aes.encrypt("account created"));
                    dout.flush();
                    System.gc();
                } else {
                    userdata = str.split(" ");
                    filereader = new Scanner(passfile);
                    while (filereader.hasNextLine()) {
                        data = filereader.nextLine();
                        data = dec.decrypt(data);
                        filedata = data.split(" ");
                        if (filedata[0].equals(userdata[0]) && filedata[1].equals(userdata[1]) ) {
                            flag = 1;
                            for(j=0; j<numberofsockets[0] ; j++) {
                                if (filedata[0].equals(onlineusers[j])) {
                                    dout.writeUTF(aes.encrypt("User already logged in"));
                                    dout.flush();
                                    flag = 0;
                                    break;
                                }
                            }
                            break;
                        } else {
                            flag =0;
                        }
                    }
                    filereader.close();
                    if (flag == 1) {
                        synchronized (synchronizer) {
                            numberofsockets[0]++;
                            onlineusers[numberofsockets[0] - 1] = filedata[0];
                        }
                        so[i].setUsername(filedata[0]);
                        Manager res = new Manager(so[i], i, so, numberofsockets,onlineusers);
                        dout.writeUTF(aes.encrypt("ok"));

                        res.start();
                        System.out.println("Client connected");
                    } else {
                        dout.writeUTF(aes.encrypt("wrong username or password"));
                        dout.flush();
                    }
                    flag = 1;
                    System.gc();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}

class AsyncUploader extends Thread {

    AsyncUploader() {

    }

    public void run() {
        File[] sourcecontents;
        File[] targetcontents;
        File file;

        StringBuilder hashsource = new StringBuilder(), hashtarget = new StringBuilder();
        while (true) {
            try {
                Thread.sleep(1000 * 10);
                synchronized (filesynchronizer) {
                    sourcecontents = NASSource.listFiles();
                    targetcontents = NASTarget.listFiles();
                    System.out.println("Synchronizing files now");
                    assert sourcecontents != null;
                    for (File f : sourcecontents) {

                        if (!f.exists() || f.getName().equals("System Volume Information")) {
                            continue;
                        }
                        FileInputStream fis = new FileInputStream(f.getAbsolutePath());
                        byte[] FileData = new byte[(int) f.length()];
                        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
                        if (fis.read(FileData) != -1) {

                            md1.update(FileData);
                            byte[] digest = md1.digest();
                            hashsource = new StringBuilder();
                            for (byte x : digest) {
                                hashsource.append(String.format("%02x", x));
                            }
                        }
                        fis.close();
                        file = new File(NASTarget + "/" + f.getName());

                        if (!file.exists()) {
                            Files.copy(f.toPath(), file.toPath());
                            System.out.println("Copying new file " + f.getName());
                        }
                        FileData = new byte[(int) file.length()];
                        md1 = MessageDigest.getInstance("SHA-256");
                        fis = new FileInputStream(file.getAbsolutePath());
                        if (fis.read(FileData) != -1) {
                            md1.update(FileData);
                            byte[] digest = md1.digest();
                            hashtarget = new StringBuilder();
                            for (byte x : digest) {
                                hashtarget.append(String.format("%02x", x));
                            }
                        }
                        fis.close();
                        if (!hashsource.toString().equals(hashtarget.toString())) {
                            System.out.println("Hashes not matching " + f.getName());
                            file.delete();
                            Files.copy(f.toPath(), file.toPath());
                        }
                        md1 = null;
                    }

                    assert targetcontents != null;
                    for (File f : targetcontents) {
                        if (f.getName().equals("System Volume Information")) {
                            continue;
                        }
                        file = new File(NASSource + "/" + f.getName());
                        if (f.exists() && !file.exists()) {
                            System.out.println("Deleting file " + f.getName());
                            f.delete();
                        }
                    }
                }
                System.out.println("Synchronization done");
                sourcecontents = null;
                targetcontents = null;
                file = null;
                System.gc();
            } catch (InterruptedException | NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }

    }
}


class MyServer {
    public final static Sync synchronizer = new Sync();
    public final static Sync filesynchronizer = new Sync();
    public final static AES aes;
    public final static rsa rsaobj = new rsa();
    public static File NASSource = new File("E:/");
    public static File NASBunker = new File("F:/");
    public static File NASTarget = new File("H:/");

    public static int FileBufferSize = 1024 * 1024 * 75;
    public static boolean SourceDown = false, BunkerDown = false, TargetDown = false;

    static {
        try {
            aes = new AES();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws Exception {

        if (!NASSource.exists()) {
            SourceDown = true;
            NASSource = NASBunker;
            System.out.println("Source down, switching to Bunker");
        }

        CustomSocket[] so = new CustomSocket[10];
        String exitstr = "start";
        rsaobj.getPublickey();
        rsaobj.getPrivatekey();
        System.out.println(rsaobj.decrypt(rsaobj.encrypt("ABCDEFGHIJKLMNOP", rsaobj.publicKey), rsaobj.privateKey));
        int i;
        for (i = 0; i < 10; i++) {
            so[i] = new CustomSocket();
        }
        ServerSocket ss = new ServerSocket(4949);
        System.out.println("Server has started");
        System.out.printf("The current download folder is: %s/Downloads.%n", System.getProperty("user.home").replace('\\', '/'));

       /* File[] contents = NASSource.listFiles();
        assert contents != null;
        for (File f : contents) {
            System.out.println(f.getName());
        }
        contents = null;
        System.gc();*/
        Connector con = new Connector(ss, so);
        con.start();
        AsyncUploader async = new AsyncUploader();
        async.start();
        Scanner in = new Scanner(System.in);
        while (!exitstr.equals("exit")) {
            exitstr = in.nextLine();
        }
        in.close();
        System.exit(0);
    }
}