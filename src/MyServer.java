import org.jetbrains.annotations.NotNull;

import java.net.*;
import java.io.*;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Scanner;
import java.util.Date;
import static java.lang.Character.toLowerCase;

class CustomSocket{
    Socket s;
    int id;
    CustomSocket(){
        id = -1;
    }
    String username;
}
class Encryptor{

    String random1 = "!%*#(}]";
    String random2 = "@$^&)[\\";
    String random3 = "<>?:;_{|`";
    Calendar c1 = Calendar.getInstance();
    Date date = c1.getTime();
    long time ;
    char[] encrypteddata = new char[900];

    public String encrypt(String data){
      time = date.getTime();
      int i,j=0,n,f;
      char c,en = 'a';
      n = data.length();
      for(i =0;i<n;i++)
      {
          c = data.charAt(i);
          if (c >= '0' && c <= '9')
          {
              switch (c)
              {
                  case '1': en = 'u';
                      break;
                  case '2': en = 'L';
                      break;
                  case '3': en = 'z';
                      break;
                  case '4': en = 'A';
                      break;
                  case '5': en = 'n';
                      break;
                  case '6': en = 'P';
                      break;
                  case '7': en = 's';
                      break;
                  case '8': en = 'G';
                      break;
                  case '9': en = 'w';
                      break;
                  case '0': en = 'I';
                      break;
              }
          }
          else if (c == ' ')
          {
              en = '\"';
          }
          else
          {
              if(c >= 'a' && c <= 'z')
              {
                  encrypteddata[j++] = random3.charAt((int) (time % 9));
                  time++;
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
                  encrypteddata[j++] = random1.charAt((int) time % 7);
                  en = (char)(f-9);
                  time++;
              }
              else if(f >= 67 && f <=74)
              {
                  encrypteddata[j++] = random2.charAt((int)time %7);
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
    public String decrypt(@NotNull String data){
        char[] decrypteddata = new char[300];
        int i,j,n,flag ,f;
        char c;
        n = data.length();
        j =0;
        for(i=0;i<n;i++)
        {
            flag = 0;
            c = data.charAt(i);
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
class Manager extends Thread {
    CustomSocket sc;
    CustomSocket[] so;
    int[] numberofsockets = new int[1];

    Manager(CustomSocket sc, int id, CustomSocket[] so,int[] numberofsockets){
        this.sc = sc;
        this.so = so;
        this.sc.id = id;
        this.numberofsockets = numberofsockets;

    }
    public void run() {
        try {
            int i;
            int count;
            int chatid;
            String str ;
            DataInputStream din = new DataInputStream(sc.s.getInputStream());
            DataOutputStream dout = new DataOutputStream(sc.s.getOutputStream());
            DataOutputStream[] RSdout = new DataOutputStream[10] ;
            DataOutputStream curr_RSdout = null;
            FileOutputStream fos;
            String FileName;
            int FileSize;
            byte[] ReceivedData;
            for(i=0;i<10;i++)
            {
                RSdout[i] = null;
            }
            String[] data;
            while (true) {
                synchronized (din) {
                    str = din.readUTF();
                    System.out.println("client " + sc.id + " says: " + str);
                    if (str.equals("exit")) {
                        dout.writeUTF("exit");
                        synchronized (numberofsockets) {
                            for (i = 0; i < numberofsockets[0]; i++) {
                                if (so[i].id == sc.id) {
                                    so[i].id = -1;
                                    so[i].s = null;
                                    RSdout[i] = null;
                                    numberofsockets[0]--;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    if(str.equals("file"))
                    {
                        FileName = din.readUTF();
                        FileSize = Integer.parseInt(din.readUTF());
                        System.out.println(FileSize);
                        ReceivedData = new byte[FileSize];
                        System.out.println(ReceivedData.length);
                        din.readFully(ReceivedData);
                        curr_RSdout.writeUTF("file");
                        curr_RSdout.writeUTF(FileName);
                        curr_RSdout.writeUTF(Integer.toString(ReceivedData.length));
                        curr_RSdout.write(ReceivedData,0,ReceivedData.length);
                        curr_RSdout.flush();
                    }
                    else if (str.equals("list")) {
                        count  =0;
                        for (i = 0; count<numberofsockets[0]; i++) {

                            if ((so[i].id == sc.id)) {
                                count++;
                                continue;
                            }
                            if(so[i].id == -1)
                            {
                                continue;
                            }
                            if (RSdout[i] == null) {
                                RSdout[i] = new DataOutputStream(so[i].s.getOutputStream());

                            }
                            dout.writeUTF(so[i].username +" "+Integer.toString(so[i].id));
                            dout.flush();
                            count++;
                        }
                        System.out.println("end of list");
                        dout.writeUTF("end of list");
                        dout.flush();
                        count = 0;
                    } else {
                        data = str.split(" ");
                        if (data[0].equals("chat")) {
                            chatid = Integer.parseInt(data[1]);
                            curr_RSdout = RSdout[chatid];
                        } else if (data[0].equals("others")) {
                            data = str.split("others ");
                            System.out.println(data[1]);
                            dout.writeUTF(data[1]);
                            dout.flush();
                        } else {
                            curr_RSdout.writeUTF(sc.id + " " + str);
                            curr_RSdout.flush();
                        }

                    }
                }
            }
            din.close();
        }
        catch (SocketException e)
        {
            System.out.println(e);
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
class Connector extends Thread{
    ServerSocket ss;
    CustomSocket[] so ;
    File passfile = new File("C:\\Users\\Zaid\\Desktop\\uspass.txt");
    Scanner filereader ;
    FileWriter filewriter = new FileWriter(passfile,true);
    String data;
    String[] filedata;
    String[] userdata;
    DataOutputStream dout;
    DataInputStream din;
    Socket testsocket;
    int[] numberofsockets = new int[1];
    Connector(ServerSocket ss,CustomSocket[] so) throws IOException {
        this.ss = ss;
        this.so = so;
    }

    public void run()
    {   int i =0;
        numberofsockets[0] = 0;
        int n = so.length;
        Decryptor dec = new Decryptor();
        Encryptor enc = new Encryptor();
        int flag = 0;
        String str,newusername,newpassword;
        while(true) {

            try {
                testsocket = ss.accept();
                for(i=0;i<n;i++)
                {
                   if(so[i].id == -1) {
                       so[i].s = testsocket;
                       break;
                   }
                }

                dout = new DataOutputStream(so[i].s.getOutputStream());
                din = new DataInputStream(so[i].s.getInputStream());
                str = din.readUTF();
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
                        if (filedata[0].equals(userdata[0]) && filedata[1].equals(userdata[1])) {
                            dout.writeUTF("ok");
                            dout.flush();
                            flag = 1;
                            break;
                        }
                    }
                    if (flag == 1) {
                        synchronized (numberofsockets) {
                            numberofsockets[0]++;
                        }
                        so[i].username = filedata[0];
                        Manager res = new Manager(so[i], i, so, numberofsockets);

                        res.start();
                        System.out.println("Client connected");
                        i++;
                    } else {
                        dout.writeUTF("not ok");
                        dout.flush();
                    }
                    flag = 0;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}

class MyServer {
    public static void main(String[] args) throws Exception {
        CustomSocket[] so = new CustomSocket[10];
        int i;
        for(i=0;i<10;i++)
        {
            so[i] = new CustomSocket();
        }
        ServerSocket ss = new ServerSocket(4949);
        Connector con = new Connector(ss,so);
        con.start();
        con.join();
    }
}