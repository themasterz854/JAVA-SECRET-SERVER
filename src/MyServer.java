import java.net.*;
import java.io.*;
import java.awt.*;
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
        String stro = " ";
        DataOutputStream dout;
        DataInputStream din;
        System.out.println("ready to chat");
        try {
            dout = new DataOutputStream(ReceiverSocket.getOutputStream());
            din = new DataInputStream(SenderSocket.getInputStream());
            while(!stro.equals("exit")) {

                stro = din.readUTF();
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
            String str = "a";
            DataInputStream din = new DataInputStream(sc.s.getInputStream());
            DataOutputStream dout = new DataOutputStream(sc.s.getOutputStream());
            dout.writeUTF("Your id is "+ Integer.toString(sc.id));
            dout.flush();
            String[] data;
            while (!str.equals("exit")) {
                str = din.readUTF();
                System.out.println("client "+ sc.id+" says: " + str);
                if(str.equals("list"))
                {
                    for(i=0;so[i].id != -1;i++) {
                        if(so[i].id == sc.id)
                            continue;
                        dout.writeUTF(Integer.toString(so[i].id)+" ");
                        dout.flush();
                    }
                }
                else {
                    data = str.split(" ");
                    if(data[0].equals("chat"))
                    {
                        chatid = Integer.parseInt(data[1]);
                        for(i=0;so[i].id != -1 && i< so.length;i++)
                        {
                            if(so[i].id == chatid)
                            {
                                Sender sen = new Sender(so[i].s,sc.s);
                                sen.start();
                                sen.join();
                            }
                        }
                    }
                }
                sleep(2000);
            }
            din.close();
        } catch (IOException | InterruptedException e) {
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
        ServerSocket ss = new ServerSocket(4545);
        Connector con = new Connector(ss,so);
        con.start();
    }
}