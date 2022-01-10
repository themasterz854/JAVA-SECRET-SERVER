import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import static java.lang.Character.toLowerCase;

class CustomSocket{
    private Socket s;
    private int id;
    CustomSocket(){
        id = -1;
    }
    private String username;
    public void setSocket(Socket s)
    {
        this.s = s;
    }
    public void setid(int id)
    {
        this.id = id;
    }
    public void setUsername(String username)
    {
        this.username = username;
    }
    public Socket getSocket()
    {
        return s;
    }
    public int getid()
    {
        return id;
    }
    public String getusername()
    {
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
      for(i =0;i<n;i++)
      {
          c = data.charAt(i);
          if (c >= '0' && c <= '9')
          {
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
          }
          else if (c == ' ')
          {
              en = '\"';
          }
          else if(c == '\n' )
          {
              en = c;
          }
          else
          {
              if(c >= 'a' && c <= 'z')
              {

                  encrypteddata[j++] = random3.charAt(randomarray[randomiterator++ % 10] % 8);

              }
              if(c >= 'a' && c <= 'z')
              {
                  f = Character.toUpperCase(c) - 16;
              }
              else
              {
                  f = c - 16;
              }
              if(f >= 58  && f <67)
              {

                  encrypteddata[j++] = random1.charAt(randomarray[randomiterator++ % 10] % 7);
                  en = (char)(f-9);
              }
              else if(f >= 67 && f <=74)
              {

                  encrypteddata[j++] = random2.charAt(randomarray[randomiterator++ % 10] % 7);
                  en = (char)(f - 18);
              }
              else
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
        for(i=0;i<n;i++)
        {
            flag = 0;
            c = data.charAt(i);
            if (c == '\n')
            {
                decrypteddata[j++] = '\n';
                continue;
            }
            if(c == '\"')
            {
                decrypteddata[j++] = ' ';
                continue;
            }
            if(c == '<' || c == '>' || c == '?' || c == ':' || c == ';' || c == '_' || c == '{' || c == '|' || c == '`')
            {
                flag = 1;
                c = data.charAt(++i);
            }
            if(c == '@' || c == '$' || c == '^' || c == '&' || c == ')' || c == '[' || c == '\\')
            {
                c = data.charAt(++i);
                f = c + 16;
                c = (char)(f + 18);

            }
            else if(c == '!' || c == '#' || c == '%' || c == '*' || c == '(' || c == '}' || c == ']')
            {
                c = data.charAt(++i);
                f = c + 16;
                c = (char)(f+9);
            }
            else if(c >= '0' && c <= '9')
            {
                f = c +16;
                c = (char)f;
            }
            else
            {
                switch (c)
                {
                    case 'u': c = '1';
                        break;
                    case 'L': c = '2';
                        break;
                    case 'z': c = '3';
                        break;
                    case 'A': c = '4';
                        break;
                    case 'n': c = '5';
                        break;
                    case 'P': c = '6';
                        break;
                    case 's': c = '7';
                        break;
                    case 'G': c = '8';
                        break;
                    case 'w': c = '9';
                        break;
                    case 'I': c = '0';
                        break;
                    default:
                        break;
                }
            }
            if (flag == 1 && (c >= 'A' && c <= 'Z'))
            {
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
            String str ;
            DataInputStream din = new DataInputStream(sc.getSocket().getInputStream());
            DataOutputStream dout = new DataOutputStream(sc.getSocket().getOutputStream());
            DataOutputStream[] RSdout = new DataOutputStream[10] ;
            DataOutputStream curr_RSdout = dout;
            String FileName;

            boolean p ;
            int FileSize;
            byte[] ReceivedData;
            for(i=0;i<10;i++)
            {
                RSdout[i] = null;
            }
            String[] data;
            int encryptflag = 0;
            while (true) {
                    str = din.readUTF();
                    p = Pattern.matches("%[a-z]*%", str);
                    System.out.println("client " + sc.getid() + " says: " + str);
                    if(p)
                    {
                    if(str.equals("%enableencryption%"))
                    {
                        encryptflag = 1;
                        continue;
                    }
                    else if(str.equals("%disableencryption%"))
                    {
                        encryptflag = 0;
                        continue;
                    }
                    if(str.equals("%decrypt%"))
                    {
                        str = din.readUTF();
                        System.out.println(dec.decrypt(str));
                        dout.writeUTF(dec.decrypt(str));
                        dout.flush();
                        continue;
                    }
                    if (str.equals("%exit%")) {
                        dout.writeUTF("exit");
                        synchronized (MyServer.synchronizer) {
                            for (i = 0; i < 10; i++) {
                                if (so[i].getid() == sc.getid()) {
                                    System.out.println("exitting "+sc.getid());
                                    System.out.println("number of sockets is "+numberofsockets[0]);
                                    RSdout[i] = null;
                                    so[i].setid(-1);
                                    so[i].setSocket(null);
                                    so[i].setUsername(null);
                                    numberofsockets[0]--;
                                    onlineusers[i] = null;
                                    System.out.println("number of sockets is "+numberofsockets[0]);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    String hash;
                    if(str.equals("%file%"))
                    {
                        hash = din.readUTF();
                        System.out.println("HASH " + hash);
                        FileName = din.readUTF();
                        FileSize = Integer.parseInt(din.readUTF());
                        System.out.println(FileSize);
                        ReceivedData = new byte[FileSize];
                        System.out.println(ReceivedData.length);
                        din.readFully(ReceivedData);
                        synchronized (MyServer.synchronizer) {
                            curr_RSdout.writeUTF("%file%");
                            curr_RSdout.writeUTF(hash);
                            curr_RSdout.writeUTF(FileName);
                            curr_RSdout.writeUTF(Integer.toString(ReceivedData.length));
                            curr_RSdout.write(ReceivedData, 0, ReceivedData.length);
                            curr_RSdout.flush();
                        }
                    }
                    else if (str.equals("%list%")) {
                        count  =0;
                        for (i = 0; count<numberofsockets[0]; i++) {

                            if ((so[i].getid() == sc.getid())) {
                                count++;
                                continue;
                            }
                            if(so[i].getid() == -1)
                            {
                                continue;
                            }
                            if (RSdout[i] == null) {
                                synchronized (MyServer.synchronizer) {
                                    RSdout[i] = new DataOutputStream(so[i].getSocket().getOutputStream());
                                }

                            }
                            dout.writeUTF(so[i].getusername() +" "+so[i].getid());
                            dout.flush();
                            count++;
                        }
                        System.out.println("end of list");
                        dout.writeUTF("end of list");
                        dout.flush();
                    } }
                    else {
                        synchronized (MyServer.synchronizer) {
                            data = str.split(" ");
                            if (data[0].equals("%chat%")) {
                                chatid = Integer.parseInt(data[1]);
                                curr_RSdout = RSdout[chatid];
                            } else if (data[0].equals("%others%")) {
                                data = str.split("%others% ");
                                dout.writeUTF(data[1]);
                                dout.flush();
                            } else {
                                if (encryptflag == 1)
                                    curr_RSdout.writeUTF(sc.getid() + " " + en.encrypt(str));
                                else
                                    curr_RSdout.writeUTF(sc.getid() + " " + str);
                                curr_RSdout.flush();
                            }
                        }
                    }
                }
            din.close();
            dout.close();
        } catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
class Connector extends Thread{
    private final ServerSocket ss;
    private final CustomSocket[] so ;
    private final File passfile = new File("C:\\Users\\Zaid\\Desktop\\uspass.txt");
    private final FileWriter filewriter = new FileWriter(passfile,true);
    private final int[] numberofsockets = new int[1];
    private String[] filedata;
    Connector(ServerSocket ss,CustomSocket[] so) throws IOException {
        this.ss = ss;
        this.so = so;
    }

    public void run()
    {
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
                for(i=0;i<n;i++)
                {
                   if(so[i].getid() == -1) {
                       so[i].setSocket(testsocket);
                       System.out.println("id assigned "+ i);
                       break;
                   }
                }

                dout = new DataOutputStream(so[i].getSocket().getOutputStream());
                din = new DataInputStream(so[i].getSocket().getInputStream());
                str = din.readUTF();
                if(str.equals("%exit%"))
                {
                    System.out.println("Client exited");
                    continue;
                }
                if(str.equals("newaccount"))
                {
                    newusername = din.readUTF();
                    newpassword = din.readUTF();

                    filewriter.write(enc.encrypt(newusername+" "+newpassword)+"\n");
                    filewriter.flush();
                    filewriter.close();
                }
                else {
                    userdata = str.split(" ");
                    filereader = new Scanner(passfile);
                    while (filereader.hasNextLine()) {
                        data = filereader.nextLine();
                        data = dec.decrypt(data);
                        filedata = data.split(" ");
                        if (filedata[0].equals(userdata[0]) && filedata[1].equals(userdata[1]) ) {
                            flag = 1;
                            for(j=0;j<numberofsockets[0] ;j++) {
                                if (filedata[0].equals(onlineusers[j])) {
                                    dout.writeUTF("User already logged in");
                                    dout.flush();
                                    flag = 0;
                                    break;
                                }
                            }
                            break;
                        }
                        else
                        {
                            flag =0;
                        }
                    }
                    if (flag == 1) {
                        synchronized (MyServer.synchronizer) {
                            numberofsockets[0]++;
                            onlineusers[numberofsockets[0] - 1] = filedata[0];
                        }
                        so[i].setUsername(filedata[0]);
                        Manager res = new Manager(so[i], i, so, numberofsockets,onlineusers);
                        dout.writeUTF("ok");

                        res.start();
                        System.out.println("Client connected");
                    } else {
                        dout.writeUTF("wrong username or password");
                        dout.flush();
                    }
                    flag = 1;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}

class MyServer {
    public final static Sync synchronizer = new Sync();
    public static void main(String[] args) throws Exception {
        CustomSocket[] so = new CustomSocket[10];
        String exitstr = "start";
        int i;
        for(i=0;i<10;i++)
        {
            so[i] = new CustomSocket();
        }
        ServerSocket ss = new ServerSocket(4949);
        System.out.println("Server has started");
        Connector con = new Connector(ss,so);
        con.start();
        Scanner in = new Scanner(System.in);
        while(!exitstr.equals("exit") )
        {
           exitstr = in.nextLine();
        }
        System.exit(0);

    }
}