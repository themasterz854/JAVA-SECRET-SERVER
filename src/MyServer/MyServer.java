package MyServer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static MyServer.MyServer.*;
import static java.lang.Character.toLowerCase;

class NASReceiverDeleter extends Thread {
    DataOutputStream DownloadDout;
    DataInputStream DownloadDin;
    String command, NASfilelist;
    File[] contents;

    NASReceiverDeleter(File[] contents, String NASfilelist, String command, DataOutputStream DownloadDout, DataInputStream DownloadDin) {

        this.DownloadDout = DownloadDout;
        this.DownloadDin = DownloadDin;
        this.command = command;
        this.NASfilelist = NASfilelist;
        this.contents = contents;

    }

    public void run() {
        synchronized (CloseSync) {
            if (command.equals("%receive%")) {
                String[] NASFileArray = NASfilelist.split("\n");
                File[] NASFileObjects = new File[NASFileArray.length];
                int j;
                long totalsize = 0;
                j = 0;
                for (String s : NASFileArray) {

                    for (File file : contents) {

                        if (file.getName().equals(s)) {
                            try {
                                FileInputStream fis = new FileInputStream(file);
                                readlock.lock();
                                totalsize += file.length();
                                NASFileObjects[j++] = file;

                                fis.close();
                                break;
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }
                }

                try {
                    DownloadDout.writeUTF(aes.encrypt(Long.toString(totalsize)));
                    DownloadDout.flush();
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    for (File f : NASFileObjects) {

                        int read;
                        byte[] sendData;
                        byte[] readbytes;
                        byte[] encryptedSendData;

                        try (FileInputStream fis = new FileInputStream(f)) {
                            DownloadDout.writeUTF(aes.encrypt("%NASFile%"));
                            DownloadDout.flush();
                            DownloadDout.writeUTF(aes.encrypt(f.getName()));
                            DownloadDout.flush();
                            sendData = new byte[FileBufferSize];
                            while ((read = fis.read(sendData)) > 0) {
                                readbytes = new byte[read];
                                System.arraycopy(sendData, 0, readbytes, 0, read);
                                md.update(readbytes);
                                encryptedSendData = aes.encrypt(readbytes);
                                int encryptedsize = encryptedSendData.length;
                                DownloadDout.writeUTF(aes.encrypt(Integer.toString(read)));
                                DownloadDout.flush();
                                DownloadDout.writeUTF(aes.encrypt(Integer.toString(encryptedsize)));
                                DownloadDout.flush();
                                DownloadDout.write(encryptedSendData, 0, encryptedsize);
                                DownloadDout.flush();
                                System.out.println("sent bytes " + read);
                                System.out.println(aes.decrypt(DownloadDin.readUTF()));
                            }

                        }

                        DownloadDout.writeUTF(aes.encrypt(Integer.toString(read)));
                        DownloadDout.flush();
                        System.out.println("sent the file");
                        byte[] digest = md.digest();
                        StringBuilder hash = new StringBuilder();
                        for (byte x : digest) {
                            hash.append(String.format("%02x", x));
                        }
                        DownloadDout.writeUTF(aes.encrypt(hash.toString()));
                        DownloadDout.flush();
                        readlock.unlock();
                        System.gc();
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }


            } else if (command.equals("%delete%")) {
                try {
                    String[] NASFileArray = NASfilelist.split("\n");
                    for (String s : NASFileArray) {
                        File f = null;
                        for (File file : contents) {
                            if (file.getName().equals(s)) {
                                f = new File(file.getAbsolutePath());
                                break;
                            }
                        }
                        assert f != null;

                        writelock.lock();
                        f.delete();
                        if (!(NASSource.equals(NASBunker))) {
                            f = new File(NASBunker + "/" + f.getName());
                            f.delete();
                        }
                        writelock.unlock();


                        DownloadDout.writeUTF(aes.encrypt("Deleted file " + f.getName() + "\n"));
                        DownloadDout.flush();

                    }
                    DownloadDout.writeUTF(aes.encrypt("All the Files have been DELETED \n"));
                    DownloadDout.flush();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}

class NASUploader extends Thread {
    private final DataOutputStream UploadDout;
    private final DataInputStream UploadDin;

    NASUploader(DataOutputStream dout, DataInputStream din) {
        UploadDout = dout;
        UploadDin = din;
    }

    public void run() {
        int i;

        int n;
        try {
            synchronized (CloseSync) {
                n = Integer.parseInt(aes.decrypt(UploadDin.readUTF()));

                for (i = 0; i < n; i++) {
                    UploadDout.writeUTF(aes.encrypt("READ filessize"));
                    UploadDout.flush();
                    String filename = aes.decrypt(UploadDin.readUTF());

                    File f = new File(NASSource + "/" + filename);
                    File g;
                    FileOutputStream gos = null;
                    if (!(NASSource.equals(NASBunker))) {
                        g = new File(NASBunker + "/" + filename);
                        gos = new FileOutputStream(g);
                    }
                    FileOutputStream fos = new FileOutputStream(f);

                    byte[] receivedData;
                    int received;
                    int actualreceived;
                    while (true) {
                        actualreceived = Integer.parseInt(aes.decrypt(UploadDin.readUTF()));
                        if (actualreceived < 0) {
                            break;
                        }
                        received = Integer.parseInt(aes.decrypt(UploadDin.readUTF()));
                        receivedData = new byte[received];
                        UploadDin.readFully(receivedData);
                        receivedData = aes.decrypt(receivedData);
                        System.gc();
                        fos.write(receivedData);
                        if (!(NASSource.equals(NASBunker))) {
                            assert gos != null;
                            gos.write(receivedData);
                        }
                        System.out.println("received partial bytes" + actualreceived);
                        UploadDout.writeUTF(aes.encrypt("ACK"));
                        UploadDout.flush();
                    }
                    System.out.println("receiving hash " + aes.decrypt(UploadDin.readUTF()));
                    fos.close();
                    if (!(NASSource.equals(NASBunker))) {
                        assert gos != null;
                        gos.close();
                    }
                    System.gc();
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
}

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

    public String encrypt(String message, Key publicKey) {
        Cipher encryptCipher;
        try {
            encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] secretMessageBytes = message.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
            return Base64.getEncoder().encodeToString(encryptedMessageBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public byte[] encrypt(byte[] secretMessageBytes, Key publicKey) {
        Cipher encryptCipher;
        try {
            encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);
            return Base64.getEncoder().encode(encryptedMessageBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    public String decrypt(String encryptedmessage, Key privateKey) {
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

    public byte[] decrypt(byte[] MessageBytes, Key privateKey) {
        Cipher decryptCipher;
        byte[] decryptedMessageBytes;
        byte[] encryptedMessageBytes = Base64.getDecoder().decode(MessageBytes);
        try {
            decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        return decryptedMessageBytes;
    }

}


class CustomSocket {
    private Socket s, cs, ds, us;
    private int id;
    private String username;

    CustomSocket() {
        id = -1;
    }

    public void setCommSocket(Socket s) {
        this.s = s;
    }

    public Socket getChatSocket() {
        return cs;
    }

    public void setChatSocket(Socket s) {
        cs = s;
    }

    public Socket getUploadSocket() {
        return us;
    }

    public void setUploadSocket(Socket s) {
        us = s;
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

    public Socket getDownloadSocket() {
        return ds;
    }

    public void setDownloadSocket(Socket s) {
        ds = s;
    }


    public int getid() {
        return id;
    }

    public String getusername() {
        return username;
    }
}

class Encryptor {

    public String encrypt(String data) {
        String random1 = "!%*#(}]";
        String random2 = "@$^&)[\\";
        String random3 = "<>?:;_{|`";
        char[] encrypteddata;
        Random random = new Random();
        IntStream randomint = random.ints(10, 0, 9);
        int[] randomarray = randomint.toArray();
        int randomiterator = 0;
        encrypteddata = new char[900];
        int i, j = 0, n, f;
        char c, en = 'a';
        n = data.length();
        for (i = 0; i < n; i++) {
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
                if (f >= 58 && f < 67) {

                    encrypteddata[j++] = random1.charAt(randomarray[randomiterator++ % 10] % 7);
                    en = (char) (f - 9);
                } else if (f >= 67 && f <= 74) {

                    encrypteddata[j++] = random2.charAt(randomarray[randomiterator++ % 10] % 7);
                    en = (char) (f - 18);
                } else
                    en = (char) f;
            }
            encrypteddata[j++] = en;
        }
        String encryptedstr = new String(encrypteddata);
        encryptedstr = encryptedstr.trim();
        return encryptedstr;
    }
}

class Decryptor {
    public String decrypt(String data) {
        char[] decrypteddata = new char[900];
        int i, j, n, flag, f;
        char c;
        n = data.length();
        j = 0;
        for (i = 0; i < n; i++) {
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

            } else if (c == '!' || c == '#' || c == '%' || c == '*' || c == '(' || c == '}' || c == ']') {
                c = data.charAt(++i);
                f = c + 16;
                c = (char) (f + 9);
            } else if (c >= '0' && c <= '9') {
                f = c + 16;
                c = (char) f;
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
                c = toLowerCase(c);
            }
            decrypteddata[j++] = c;
        }
        data = new String(decrypteddata);
        data = data.trim();
        return data;
    }

}

class Sync {
    Sync() {

    }
}

class Manager extends Thread {


    private final CustomSocket sc;
    private final CustomSocket[] so;
    private final int[] numberofsockets;
    private final String[] onlineusers;
    private final Decryptor dec = new Decryptor();
    private final Encryptor en = new Encryptor();


    Manager(CustomSocket sc, int id, CustomSocket[] so, int[] numberofsockets, String[] onlineusers) {
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

            DataInputStream chatdin = new DataInputStream(sc.getChatSocket().getInputStream());
            DataOutputStream chatdout = new DataOutputStream(sc.getChatSocket().getOutputStream());

            DataOutputStream UploadDout = new DataOutputStream(sc.getUploadSocket().getOutputStream());
            DataInputStream UploadDin = new DataInputStream(sc.getUploadSocket().getInputStream());

            DataOutputStream DownloadDout = new DataOutputStream(sc.getDownloadSocket().getOutputStream());
            DataInputStream DownloadDin = new DataInputStream(sc.getDownloadSocket().getInputStream());

            NASUploader nasuploader;
            NASReceiverDeleter nasreceiverdeleter;

            DataOutputStream[] RSdout = new DataOutputStream[10];
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
                                    so[i].setCommSocket(null);
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
                                if (f.getName().equals("System Volume Information") || f.getName().equals(".Trash-1000") || f.getName().equals("lost+found")) {
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

                        } else if (NASfilelist.toString().equals("%NASupload%")) {
                            nasuploader = new NASUploader(UploadDout, UploadDin);
                            nasuploader.start();
                            continue;
                        }
                        String command = aes.decrypt(din.readUTF());
                        nasreceiverdeleter = new NASReceiverDeleter(contents, NASfilelist.toString(), command, DownloadDout, DownloadDin);
                        nasreceiverdeleter.start();

                    } else if (str.equals("%file%")) {
                        synchronized (CloseSync) {
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
                                }
                            }
                        }
                    } else if (str.equals("%NASupload%")) {
                        nasuploader = new NASUploader(UploadDout, UploadDin);
                        nasuploader.start();
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
                                    RSdout[i] = new DataOutputStream(so[i].getChatSocket().getOutputStream());
                                }

                            }
                            dout.writeUTF(aes.encrypt((so[i].getusername() + " " + so[i].getid())));
                            dout.flush();
                            count++;
                        }
                        dout.writeUTF(aes.encrypt("end of list"));
                        dout.flush();
                    }
                } else {
                    chatter chat = new chatter(curr_RSdout, sc, RSdout);
                    chat.start();
                   /* synchronized (synchronizer) {
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
                    }*/
                }
                System.gc();
            }
            din.close();
            dout.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

class Connector extends Thread {
    private final ServerSocket ss;
    private final CustomSocket[] so;
    private final File passfile = new File(System.getProperty("user.home").replace('\\', '/') + "/Desktop/uspass.txt");
    private final int[] numberofsockets = new int[1];
    private String[] filedata;

    Connector(ServerSocket ss, CustomSocket[] so) {
        this.ss = ss;
        this.so = so;
    }

    public void digitalsignature(CustomSocket sc, Key clientpublickey) throws Exception {

        DataInputStream din = new DataInputStream(sc.getSocket().getInputStream());
        DataOutputStream dout = new DataOutputStream(sc.getSocket().getOutputStream());
        MessageDigest keyhash = MessageDigest.getInstance("SHA-256");
        keyhash.update(aes.encryptionKey.getBytes());
        byte[] digest = keyhash.digest();
        StringBuilder hashsource = new StringBuilder();
        for (byte x : digest) {
            hashsource.append(String.format("%02x", x));
        }
        String privatestring = rsaobj.encrypt(hashsource.toString(), rsaobj.privateKey);
        System.out.println("aes hash " + new String(rsaobj.decrypt(privatestring.getBytes(), rsaobj.publicKey)));
        byte[] privateencryptedhashbytes = rsaobj.encrypt(hashsource.toString(), rsaobj.privateKey).getBytes(StandardCharsets.UTF_8);
        int length = privateencryptedhashbytes.length;
        int acceptablelength = 245;

        int i1 = length % acceptablelength == 0 ? length / acceptablelength : (length / acceptablelength) + 1;
        byte[][] privateencryptedhashbytesarray = new byte[i1][acceptablelength];
        byte[][] publicencryptedbytesarray = new byte[i1][];
        int i, j = 0;
        for (i = 0; i < privateencryptedhashbytes.length; i += acceptablelength) {

            System.arraycopy(privateencryptedhashbytes, i, privateencryptedhashbytesarray[j], 0, Math.min(acceptablelength, privateencryptedhashbytes.length - i));
            j++;
        }
        byte[] temp = new byte[acceptablelength - (i - privateencryptedhashbytes.length)];
        System.arraycopy(privateencryptedhashbytesarray[j - 1], 0, temp, 0, acceptablelength - (i - privateencryptedhashbytes.length));
        privateencryptedhashbytesarray[j - 1] = temp;

        int numberofhash = j;
        dout.writeUTF(rsaobj.encrypt(String.valueOf(numberofhash), clientpublickey));
        dout.flush();
        StringBuilder hash;
        for (i = 0; i < numberofhash; i++) {
            hash = new StringBuilder();
            publicencryptedbytesarray[i] = rsaobj.encrypt(privateencryptedhashbytesarray[i], clientpublickey);
            for (byte x : publicencryptedbytesarray[i]) {
                hash.append(String.format("%02x", x));
            }
            System.out.println("PUblic encrypted hash " + hash);
            dout.writeInt(publicencryptedbytesarray[i].length);
            dout.flush();
            din.readUTF();
            dout.write(publicencryptedbytesarray[i], 0, publicencryptedbytesarray[i].length);
            dout.flush();
            din.readUTF();
            dout.writeUTF(hash.toString());
            dout.flush();
            din.readUTF();
        }
    }

    public void run() {
        Socket testsocket;
        String data;
        String[] userdata;
        DataOutputStream dout;
        DataInputStream din;
        Scanner filereader;
        int i;
        int j;
        numberofsockets[0] = 0;
        int n = so.length;

        int flag = 1;
        String str, newusername, newpassword;
        String[] onlineusers = new String[10];
        Decryptor dec = new Decryptor();
        Encryptor enc = new Encryptor();
        while (true) {

            try {
                testsocket = ss.accept();
                for (i = 0; i < n; i++) {
                    if (so[i].getid() == -1) {
                        break;
                    }
                }
                so[i].setCommSocket(testsocket);
                testsocket = ss.accept();
                so[i].setChatSocket(testsocket);
                testsocket = ss.accept();
                so[i].setDownloadSocket(testsocket);
                testsocket = ss.accept();
                so[i].setUploadSocket(testsocket);
                System.out.println("id assigned " + i);
                dout = new DataOutputStream(so[i].getSocket().getOutputStream());
                din = new DataInputStream(so[i].getSocket().getInputStream());


                File publicKeyFile = new File("public.key");
                byte[] publicKeyBytes;
                publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
                dout.writeInt(publicKeyBytes.length);
                dout.flush();
                dout.write(publicKeyBytes);
                System.out.println("sent the public key");
                dout.flush();

                int keylength;
                keylength = din.readInt();
                byte[] publickeyBytes = new byte[keylength];
                din.read(publickeyBytes, 0, keylength);
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publickeyBytes);
                System.out.println("received client public key");
                try {
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    PublicKey clientpublickey = keyFactory.generatePublic(publicKeySpec);
                    dout.writeUTF(rsaobj.encrypt(aes.encryptionKey, clientpublickey));
                    dout.flush();
                    System.out.println("sent aes key");
                    digitalsignature(so[i], clientpublickey);
                    dout.writeUTF(aes.encrypt(NAS_Status));
                    dout.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                    System.exit(-1);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                str = aes.decrypt(din.readUTF());
                System.out.println("here" + str);
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
                        if (filedata[0].equals(userdata[0]) && filedata[1].equals(userdata[1])) {
                            flag = 1;
                            for (j = 0; j < numberofsockets[0]; j++) {
                                if (filedata[0].equals(onlineusers[j])) {
                                    dout.writeUTF(aes.encrypt("User already logged in"));
                                    dout.flush();
                                    flag = 0;
                                    break;
                                }
                            }
                            break;
                        } else {
                            flag = 0;
                        }
                    }
                    filereader.close();
                    if (flag == 1) {
                        synchronized (synchronizer) {
                            numberofsockets[0]++;
                            onlineusers[numberofsockets[0] - 1] = filedata[0];
                        }
                        so[i].setUsername(filedata[0]);
                        Manager res = new Manager(so[i], i, so, numberofsockets, onlineusers);
                        dout.writeUTF(aes.encrypt("ok"));

                        res.start();
                        System.out.println("Client " + i + " connected");
                    } else {
                        dout.writeUTF(aes.encrypt("wrong username or password"));
                        dout.flush();
                    }
                    flag = 1;
                    System.gc();
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                throw new RuntimeException(e);
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

        StringBuilder hashsource, hashtarget;
        while (true) {
            try {
                Thread.sleep(1000 * 10);
                synchronized (CloseSync) {
                    synchronized (DRSync) {
                        sourcecontents = NASSource.listFiles();
                        targetcontents = NASTarget.listFiles();

                        System.out.println("Synchronizing files now");

                        assert sourcecontents != null;
                        for (File f : sourcecontents) {

                            if (!f.exists() || f.getName().equals("System Volume Information") || f.getName().equals(".Trash-1000") || f.getName().equals("lost+found")) {
                                continue;
                            }
                            FileInputStream fis = new FileInputStream(f.getAbsolutePath());
                            readlock.lock();
                            byte[] FileData = new byte[f.length() > 512 * 1024 * 1024 ? 512 * 1024 * 1024 : (int) f.length()];
                            MessageDigest md1 = MessageDigest.getInstance("SHA-256");
                            hashsource = new StringBuilder();
                            while (fis.read(FileData) != -1) {
                                md1.update(FileData);
                            }
                            byte[] digest = md1.digest();
                            for (byte x : digest) {
                                hashsource.append(String.format("%02x", x));
                            }

                            fis.close();
                            file = new File(NASTarget + "/" + f.getName());

                            if (!file.exists()) {
                                Files.copy(f.toPath(), file.toPath());
                                System.out.println("Copying new file " + f.getName());
                            }
                            FileData = new byte[file.length() > 512 * 1024 * 1024 ? 512 * 1024 * 1024 : (int) file.length()];
                            md1 = MessageDigest.getInstance("SHA-256");
                            fis = new FileInputStream(file.getAbsolutePath());
                            hashtarget = new StringBuilder();
                            while (fis.read(FileData) != -1) {
                                md1.update(FileData);

                            }
                            digest = md1.digest();
                            for (byte x : digest) {
                                hashtarget.append(String.format("%02x", x));
                            }
                            fis.close();

                            if (!hashsource.toString().contentEquals(hashtarget)) {
                                System.out.println("Hashes not matching " + f.getName());
                                file.delete();
                                Files.copy(f.toPath(), file.toPath());
                            }
                        }

                        assert targetcontents != null;
                        for (File f : targetcontents) {
                            if (f.getName().equals("System Volume Information") || f.getName().equals(".Trash-1000") || f.getName().equals("lost+found")) {
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
                    System.gc();
                }
            } catch (InterruptedException | NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }

    }
}


//TEST ZONE

class chatter extends Thread {
    private final DataOutputStream cdout;
    private final DataInputStream cdin;
    private final CustomSocket sc;
    private final DataOutputStream[] rsdout;
    private DataOutputStream currchatdout;

    chatter(DataOutputStream currdout, CustomSocket socket, DataOutputStream[] rsdout) throws IOException {
        this.currchatdout = currdout;
        this.sc = socket;
        Socket cs = sc.getChatSocket();

        this.cdin = new DataInputStream(cs.getInputStream());
        this.cdout = new DataOutputStream(cs.getOutputStream());
        this.rsdout = rsdout;
    }

    public void run() {
        try {
            String str;
            label:
            while (true) {
                str = aes.decrypt(cdin.readUTF());
                System.out.println(str);
                synchronized (synchronizer) {
                    String[] data = str.split(" ");
                    switch (data[0]) {
                        case "%chat%":
                            int chatid = Integer.parseInt(data[1]);
                            currchatdout = rsdout[chatid];
                            break;
                        case "%others%":
                            data = str.split("%others% ");
                            cdout.writeUTF(aes.encrypt(data[1]));
                            cdout.flush();
                            break;
                        case "%exit%":
                            break label;
                        default:
                    /*if (encryptflag == 1)
                        currchatdout.writeUTF(aes.encrypt((sc.getid() + " " + en.encrypt(str))));
                    else*/
                            currchatdout.writeUTF(aes.encrypt((sc.getid() + " " + str)));
                            currchatdout.flush();
                            break;
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}


class AES256 {
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 16;
    public static final int GCM_TAG_LENGTH = 16;
    protected String encryptionKey;
    public AES256() throws Exception {

        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[(AES_KEY_SIZE / 8)];
        System.out.println("key size " + bytes.length * 8);
        random.nextBytes(bytes);
        encryptionKey = Base64.getEncoder().withoutPadding().encodeToString(bytes);

    }

    public byte[] encrypt(byte[] plaintext) {
        //Generate IV
        System.out.println("encrypt byte executing");

        try {
            byte[] IV = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();                                                        // Get Cipher Instance
            random.nextBytes(IV);

            System.out.println("IV generated : " + Base64.getEncoder().withoutPadding().encodeToString(IV));
            // Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
            // Initialize Cipher for ENCRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            // Perform Encryption
            byte[] CipherText = cipher.doFinal(plaintext);
            byte[] CipherTextFinal = new byte[GCM_IV_LENGTH + CipherText.length];
            System.arraycopy(IV, 0, CipherTextFinal, 0, GCM_TAG_LENGTH);
            System.arraycopy(CipherText, 0, CipherTextFinal, GCM_IV_LENGTH, CipherText.length);
            System.out.println("Cipher text generated " + Base64.getEncoder().withoutPadding().encodeToString(CipherTextFinal));
            return CipherTextFinal;
        } catch (Exception E) {
            System.err.println("byte Encrypt exception" + E.getMessage());
        }
        System.out.println("NULL");
        return null;
    }

    public String encrypt(String plaintext) {
        //Generate IV
        System.out.println("Encrypt string executing");
        try {
            byte[] IV = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();                                                        // Get Cipher Instance
            random.nextBytes(IV);

            System.out.println("IV generated : " + Base64.getEncoder().withoutPadding().encodeToString(IV));
            // Create SecretKeySpec
            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");
            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
            // Initialize Cipher for ENCRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            // Perform Encryption
            byte[] CipherText = cipher.doFinal(plaintext.getBytes());
            byte[] CipherTextFinal = new byte[GCM_IV_LENGTH + CipherText.length];
            System.arraycopy(IV, 0, CipherTextFinal, 0, GCM_TAG_LENGTH);
            System.arraycopy(CipherText, 0, CipherTextFinal, GCM_IV_LENGTH, CipherText.length);
            System.out.println("plain text " + plaintext);
            System.out.println("cipher text byte length " + CipherTextFinal.length);
            System.out.println("Cipher text generated " + Base64.getEncoder().withoutPadding().encodeToString(CipherTextFinal));
            System.out.println("decrypt in encrypt " + this.decrypt(Base64.getEncoder().withoutPadding().encodeToString(CipherTextFinal)));
            System.out.println("derypt done");
            return Base64.getEncoder().withoutPadding().encodeToString(CipherTextFinal);
        } catch (Exception E) {
            System.err.println("String Encrypt Exception : " + E.getMessage());
        }
        System.out.println("NULL");
        return null;

    }

    public byte[] decrypt(byte[] cipherTextString) {
        System.out.println("decrypt byte executing");
        try {
            byte[] IV = new byte[GCM_IV_LENGTH];
            System.arraycopy(cipherTextString, 0, IV, 0, GCM_IV_LENGTH);
            System.out.println("IV " + Base64.getEncoder().encodeToString(IV));
            System.out.println("cipher text received : " + Base64.getEncoder().withoutPadding().encodeToString(cipherTextString));

            byte[] ciphertextonly = new byte[cipherTextString.length - GCM_IV_LENGTH];
            System.arraycopy(cipherTextString, GCM_IV_LENGTH, ciphertextonly, 0, cipherTextString.length - GCM_IV_LENGTH);
            // Create SecretKeySpec

            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

            // Initialize Cipher for DECRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
            return cipher.doFinal(ciphertextonly);
        } catch (Exception E) {
            System.err.println("byte Decrypt Exception : " + E.getMessage());
        }

        return null;
    }


    public String decrypt(String cipherTextString) throws Exception {
        // Get Cipher Instance
        System.out.println("decrypt string executing");
        byte[] decryptedText;
        try {
            byte[] IV = new byte[GCM_IV_LENGTH];

            byte[] cipherTextStringbytes = Base64.getDecoder().decode(cipherTextString);
            System.arraycopy(cipherTextStringbytes, 0, IV, 0, GCM_IV_LENGTH);
            System.out.println("IV " + Base64.getEncoder().encodeToString(IV));
            System.out.println("cipher text received : " + cipherTextString);

            byte[] ciphertextonly = new byte[cipherTextStringbytes.length - GCM_IV_LENGTH];
            System.arraycopy(cipherTextStringbytes, GCM_IV_LENGTH, ciphertextonly, 0, cipherTextStringbytes.length - GCM_IV_LENGTH);
            // Create SecretKeySpec

            SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(encryptionKey), "AES");

            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

            // Initialize Cipher for DECRYPT_MODE
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

            // Perform Decryption
            decryptedText = cipher.doFinal(ciphertextonly);
            System.out.println("Decrytped text" + new String(decryptedText));
            return new String(decryptedText, StandardCharsets.UTF_8);
        } catch (Exception E) {
            System.err.println("string Decrypt Exception : " + E.getMessage());
        }
        return null;
    }
}

class MyServer {

    public final static Sync synchronizer = new Sync();
    public final static Sync DRSync = new Sync();
    public final static Sync CloseSync = new Sync();
    //public final static AES aes;
    public final static rsa rsaobj = new rsa();
    public final static AES256 aes;
    private static final ReentrantReadWriteLock RLock = new ReentrantReadWriteLock();
    public static Lock writelock = RLock.writeLock();
    public static Lock readlock = RLock.readLock();
    public static String NAS_Status;
    public static File NASSource;
    public static File NASBunker;
    public static File NASTarget;
    public static int FileBufferSize = 1024 * 1024 * 375;
    public static boolean SourceDown = false, BunkerDown = false, TargetDown = false;

    /*static {
        try {
            aes = new AES();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }   */

    static {
        try {
            aes = new AES256();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static void RecoveryMode(String reason) throws IOException {

        if (reason.equals("Source down")) {

            System.out.println("Source is down.\n1.Reconstruct Source from Bunker\n2.Reconstruct Source from Target\n3.Switch to Bunker\nPress any other key to exit");
        } else
            System.out.println("Entering Forced Recovery.\n1.Reconstruct Source from Bunker\n2.Reconstruct Source from Target\n3.Switch to Bunker\nPress any other key to exit");
        Scanner in = new Scanner(System.in);
        int choice = in.nextInt();
            switch (choice) {
                case 1:
                    DisasterRecovery(NASBunker, reason);
                    break;
                case 2:
                    DisasterRecovery(NASTarget, reason);
                    break;
                case 3:
                    SourceDown = true;
                    NASSource = NASBunker;
                    System.out.println("Source down, switching to Bunker");
                    break;
                default:
                    System.exit(0);
            }

    }

    static boolean SearchMounts() throws FileNotFoundException {
        boolean result = false;
        Scanner scan = new Scanner(new File("/proc/mounts"));
        while (scan.hasNext()) {
            String line = scan.nextLine();
            if (line.contains(NASSource.getAbsolutePath())) {
                result = true;
                break;
            }
        }
        scan.close();
        return result;
    }

    static void copyDirectoryCompatibityMode(File source, File destination) throws IOException {
        if (source.isDirectory()) {
            copyDirectory(source, destination);
        } else {
            Files.copy(source.toPath(), destination.toPath());
        }
    }

    static void copyDirectory(File sourceDirectory, File destinationDirectory) throws IOException {
        if (!destinationDirectory.exists()) {
            destinationDirectory.mkdir();
        }
        for (String f : Objects.requireNonNull(sourceDirectory.list())) {
            copyDirectoryCompatibityMode(new File(sourceDirectory, f), new File(destinationDirectory, f));
        }
    }

    static void DisasterRecovery(File RecoverFrom, String reason) throws IOException {
        System.out.println("RECOVERY PROCESS INITIATED");
        System.out.println("RECOVERING FROM " + RecoverFrom.getAbsolutePath());
        File[] contents;
        if (reason.equals("Source down")) {
            System.out.println("Enter path of new Source");
            Scanner in = new Scanner(System.in);
            NASSource = new File(in.nextLine());
        }

        System.out.println("Deleting files currently in Source");
        contents = NASSource.listFiles();
        assert contents != null;
        for (File f : contents) {
            if (f.getName().equals("System Volume Information") || f.getName().equals(".Trash-1000") || f.getName().equals("lost+found")) {
                continue;
            }
            f.delete();
        }

        contents = RecoverFrom.listFiles();
        assert contents != null;
        for (File f : contents) {
            if (f.isDirectory()) {
                copyDirectory(f.getAbsoluteFile(), new File(NASSource.getAbsolutePath() + "/" + f.getName()));
            } else {
                Files.copy(f.toPath(), Path.of(NASSource + "/" + f.getName()));
            }
            System.out.println(f.getName() + " RECOVERED");
        }
        System.out.println("SOURCE RECONSTRUCTED");
    }

    public static void main(String[] args) throws Exception {


        CustomSocket[] so = new CustomSocket[10];
        String exitstr = "start";
        rsaobj.getPublickey();
        rsaobj.getPrivatekey();
        System.out.println(rsaobj.decrypt(rsaobj.encrypt("RSA TEST : ABCDEFGHIJKLMNOP", rsaobj.publicKey), rsaobj.privateKey));

        int i;
        for (i = 0; i < 10; i++) {
            so[i] = new CustomSocket();
        }
        ServerSocket ss = new ServerSocket(Integer.parseInt(args[0]));
        System.out.println("Server has started on port " + args[0]);
        System.out.printf("The current download folder is: %s/Downloads.%n", System.getProperty("user.home").replace('\\', '/'));

        System.out.println(aes.decrypt(aes.encrypt("hello there")));
        System.out.println(aes.decrypt(aes.encrypt("general kenobi")));
        Connector con = new Connector(ss, so);
        con.start();
        AsyncUploader async = new AsyncUploader();
        Scanner in = new Scanner(System.in);
        if (args.length > 1 && args[1].equals("NAS")) {
            System.out.println(args[2] + " " + args[3] + " " + args[4]);
            NASSource = new File(args[2]);
            NASBunker = new File(args[3]);
            NASTarget = new File(args[4]);
            NAS_Status = "%NAS_ONLINE%";

            System.out.println("Starting NAS server");
            String OS = System.getProperty("os.name").split(" ")[0];
            System.out.println(OS);
            if (OS.equals("Windows") ? !NASSource.exists() : !SearchMounts()) {
                RecoveryMode("Source down");
            }
            async.start();
            System.gc();
        } else {
            NAS_Status = "%NAS_OFFLINE%";
        }
        while (!exitstr.equals("exit")) {
            System.out.println("Type DR for Forced Recovery");
            exitstr = in.nextLine();
            if (exitstr.equals("DR")) {
                synchronized (DRSync) {
                RecoveryMode("Forced Recovery");
            }
            }
        }
        synchronized (CloseSync) {
            in.close();
            System.exit(0);
        }
    }
}