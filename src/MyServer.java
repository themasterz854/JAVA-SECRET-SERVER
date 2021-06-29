import java.net.*;
import java.io.*;

class CustomSocket{
    Socket s;
    int id;
    CustomSocket(){
        id = -1;
    }
}
class Sender extends Thread{
    Socket ReceiverSocket;
    Socket SenderSocket;

    Sender(Socket ReceiverSocket,Socket SenderSocket)
    {
        this.SenderSocket= SenderSocket;
        this.ReceiverSocket = ReceiverSocket;

    }
    public void run(){
        String stro ;
        DataOutputStream dout;
        DataInputStream din;
        System.out.println("ready to chat");
        try {
            dout = new DataOutputStream(ReceiverSocket.getOutputStream());
            din = new DataInputStream(SenderSocket.getInputStream());
            while(true) {
                stro = din.readUTF();
                if(stro.equals("exit"))
                {
                    dout = new DataOutputStream(SenderSocket.getOutputStream());
                    dout.writeUTF("exit");
                    dout.flush();
                    dout.close();
                    din.close();
                    break;
                }
                dout.writeUTF(stro);
                dout.flush();
            }
        }catch (IOException e) {
            e.printStackTrace();
        }
    }
}
class Receiver extends Thread {
    CustomSocket sc;
    CustomSocket[] so;

    Receiver(CustomSocket sc,int id,CustomSocket[] so){
        this.sc = sc;
        this.so = so;
        this.sc.id = id;
    }
    public void run() {
        try {
            int i;
            int chatid;
            String str ;
            DataInputStream din = new DataInputStream(sc.s.getInputStream());
            DataOutputStream dout = new DataOutputStream(sc.s.getOutputStream());
            DataOutputStream[] RSdout = new DataOutputStream[10] ;
            DataOutputStream curr_RSdout = null;
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
                        break;
                    }
                    if (str.equals("list")) {
                        for (i = 0; so[i].id != -1; i++) {
                            if (so[i].id == sc.id)
                                continue;
                            if (RSdout[i] == null) {
                                RSdout[i] = new DataOutputStream(so[i].s.getOutputStream());
                            }
                            dout.writeUTF(Integer.toString(so[i].id));
                            dout.flush();
                        }
                        System.out.println("end of list");
                        dout.writeUTF("end of list");
                        dout.flush();
                    } else {
                        data = str.split(" ");
                        if (data[0].equals("chat")) {
                            chatid = Integer.parseInt(data[1]);
                            curr_RSdout = RSdout[chatid];
                        } else if (data[0].equals("others")) {
                            data = str.split("others");
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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
class Connector extends Thread{
    ServerSocket ss;
    CustomSocket[] so ;

    Connector(ServerSocket ss,CustomSocket[] so)
    {
        this.ss = ss;
        this.so = so;
    }
    public void run()
    {   int i =0;

        while(true) {

            try {

                so[i].s = ss.accept();
            } catch (IOException e) {
                e.printStackTrace();
            }
            Receiver res = new Receiver(so[i],i,so);
            res.start();
            System.out.println("Client connected");
            i++;
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