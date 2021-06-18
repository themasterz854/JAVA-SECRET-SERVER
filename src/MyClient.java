import java.net.*;
import java.io.*;
import java.util.Scanner;
class Sender1 extends Thread{
    Socket s;
    Sender1(Socket s)
    {
        this.s = s;
    }
    public void run()
    {       try {
        DataOutputStream dout = new DataOutputStream(s.getOutputStream());
        BufferedReader br=new BufferedReader(new InputStreamReader(System.in));
        String str ;
        while(true)
        {
            str=br.readLine();
            dout.writeUTF(str);
            dout.flush();
            if(str.equals("exit"))
            {   dout = new DataOutputStream(s.getOutputStream());
                dout.writeUTF("exit");
                sleep(3000);
                dout.close();
                break;
            }
        }

    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
    }
    }
}
class Receiver1 extends Thread{
    Socket s;
    Receiver1(Socket s){
        this.s = s;
    }
    public void run() {
        try {
            String str ;
            DataInputStream din = new DataInputStream(s.getInputStream());
            while (true) {
                str = din.readUTF();
                if(str.equals("exit"))
                {
                    break;
                }
                System.out.println("server says: " + str);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class MyClient {
    public static void main(String[] args) throws Exception {
        int ch;
        Scanner in = new Scanner(System.in);
        Socket s = new Socket("localhost", 4545);
        Sender1 sen = new Sender1(s);
        Receiver1 res = new Receiver1(s);
        System.out.println("1.Start chatting\nAny other key to exit");
        ch = in.nextInt();
        switch(ch) {
            case 1:
                sen.start();
                res.start();
                System.out.println("type list to get list of available chatters ");
                System.out.println("chat <user_id> to chat with that user");
                sen.join();
                res.join();
                s.close();
            default:
                System.exit(0);
        }
    }
}