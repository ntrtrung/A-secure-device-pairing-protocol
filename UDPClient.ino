#include <ecc.h>
#include <string.h>
#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <sha1.h>

//client information
byte mac[] =  {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xEB };
IPAddress client_ip(192,168,1,2);
unsigned int client_port = 9998;

//An EthernetUDP instance
EthernetUDP Udp;

//server information
IPAddress server_ip(192,168,1,1);
unsigned int server_port = 9999;

//client ECC key
EccPoint l_Q2;
uint8_t l_secret_server[NUM_ECC_DIGITS + 1];
uint8_t l_secret_client[NUM_ECC_DIGITS + 1];
uint8_t l_shared2[NUM_ECC_DIGITS +1];
uint8_t l_random2[NUM_ECC_DIGITS +1];
uint8_t l_shared1[NUM_ECC_DIGITS +1];// shared key from server, debugging purpose

//random of server
byte random_server[4];
//random of client
byte random_client[4];
//commitment from client
byte client_commit[20];
//decommitment from client
byte client_decommit[4];
//client say request
byte say = 0;

byte packetBuffer[UDP_TX_PACKET_MAX_SIZE +1]; //buffer to hold incoming packet,

//setup LED for visible light communication
const int ledPin = 9;      // the pin that the LED is attached to
byte byteOn = 150; //the brightness of 1
byte byteOff = 10; //the brightness of 0

unsigned long gtime1,gtime2;

//--------------------begin setup--------------------------------//
void init_key()
{
  memset(l_secret_server,0,NUM_ECC_DIGITS  + 1);
  memset(l_secret_client,0,NUM_ECC_DIGITS  + 1);
  memset(l_shared2,0,NUM_ECC_DIGITS  + 1);
  memset(l_random2,0,NUM_ECC_DIGITS  + 1);

}
void setup()
{
    //start the Ethernet UDP
   Ethernet.begin(mac,client_ip);
   Udp.begin(client_port);
   
   Serial.begin(9600);
   
   unsigned long time1,time2;
   time1 = millis();
   //generate ECC key
   randomSeed(analogRead(0));
   getRandomBytes(l_secret_client, NUM_ECC_DIGITS * sizeof(uint8_t));
   getRandomBytes(l_random2, NUM_ECC_DIGITS * sizeof(uint8_t));
   ecc_make_key(&l_Q2, l_secret_client, l_secret_client);
   
    time2 = millis();
    Serial.print("Key generation ms:");
    Serial.println(time2-time1);
   
    //generate a client random 
    getRandomBytes(random_client, 4 * sizeof(uint8_t));
    printDebug("random client",random_client,4);
   
    calculate_commit();
    
    //setup for VLC
    pinMode(ledPin, OUTPUT);
   delay(500);

   
}
//--------------------end setup--------------------------------//

int isRequestOne = 0;

//------------------begin loop-----------------------//
void loop()
{
   //send hello 99 to server until receiving the request 1 from server
   if(isRequestOne == 0)
   {
      say = 99;
      sndMsg(&say,1);
      isRequestOne =1;
   }
   //when receive a message from client
   int packetSize = Udp.parsePacket();
   if(Udp.available())
   {
     Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
    // Serial.println("Contents:");
     //printHex(packetBuffer,packetSize);
   }
   
   //if it is a request
   if(packetSize == 1) 
   {
     //process request from client
     byte request;
     request = packetBuffer[0];
     Serial.print("Received request:");
     Serial.println(request);
     processRequestedMsg(request);
   }
   //when receive a data from client
   if(packetSize > 1)
   {
     receiveData(packetBuffer,packetSize);
   }
   if(packetSize == 0) delay(200);
}
//------------------end loop-----------------------//


//send a message
void sndMsg(byte *buf, int len)
{
    Udp.beginPacket(server_ip,server_port);
    Udp.write(buf,len);
    Udp.endPacket();
    delay(300);
}
//-----------------------begin processing request---------------------------------//
//process request from server
void processRequestedMsg(int request)
{
    if(request == 1) 
    {
      //send client key
      sndMsg(l_secret_client,NUM_ECC_DIGITS);
      //stop send hello to server
      isRequestOne = 1;
      //for debug
      printDebug("send client key",l_secret_client,NUM_ECC_DIGITS);
    }
    if(request == 2)
    {
      //send client commit
       sndMsg(client_commit,20);
      //for debug
      printDebug("send client commit",client_commit,20);
    }
    if(request == 21)
    {
      //send request 3
      say  = 3;
      sndMsg(&say,1);
      //for debug
      Serial.println("Send request 3");
    }
    if(request == 5)
    {
      unsigned long time1,time2;
       time1 = millis();
      //send decommit
       //padding random_server into 20byte hash key
       byte hashKey[20];
       memset(hashKey,0,20);
       memcpy(hashKey,random_server,4);
       //calculate SHA1 with key
       Sha1.initHmac(hashKey,20);
       byte hmacInput[49];
       memset(hmacInput,0,49);
       memcpy(hmacInput,l_secret_client,NUM_ECC_DIGITS);
       memcpy(hmacInput + NUM_ECC_DIGITS,l_secret_server,NUM_ECC_DIGITS);
       hmacInput[48]='\n';
       Sha1.print((char*)hmacInput);

       //take 4-frist byte of HMAC
       byte hashMac[4];
       memcpy(hashMac,Sha1.resultHmac(),4);

       //calculate decommit 
       int i;
       for(i = 0;i<4;i++)
          client_decommit[i]= random_client[i]^hashMac[i]; 
       
       time2 = millis();
       Serial.print("Generating decommit value spends ms:");
       Serial.println(time2-time1);
       //send 32-bits decommit on VLC channel
       delay(1000);
       sndMsgtoLED(ledPin,client_decommit);

       printDebug("client decommit",client_decommit,4);
    }
    //request for debug key
    if(request == 51)
    {
      //send request 6
      say = 6;
      sndMsg(&say,1);
      Serial.println("Send request 6");
    }
}

//process received data from server
void receiveData(const byte *buf,int packetSize)
{
  
  if(say == 3)
  {
    //accept l_secret_server, check if the data is a key or not - based on size
     if(packetSize == NUM_ECC_DIGITS){
        memcpy(l_secret_server,buf, NUM_ECC_DIGITS);
        //for debug
        printDebug("Received server key",l_secret_server,NUM_ECC_DIGITS);
            
    // send say = 4
      say = 4;
      sndMsg(&say,1);
      Serial.println("Send request 4");  
     }
     else
      Serial.println("Cannot parse client key");
  }
  else
  if(say == 4)
  {
    //accept server random
    if(packetSize == 4){
       memcpy(random_server,buf,4);
       //for debug
      printDebug("Received server random",random_server,4);
     }
     else
      Serial.println("Cannot parse server random value");
      
    //send ACK 41
    byte ACK = 41;
    sndMsg(&ACK,1);
    Serial.println("Send request 41");
       
  }
  //for debug only
  if(say == 6)
  {
    //generate shared key

     if(packetSize == 2)
     { 
       if(buf[0] == 1 && buf[1] == 1)
         {
           Serial.println("Server accepts the connection");
            generate_sharedkey();
         }
       else if(buf[0] == 0 && buf[1] == 0)
         {
            Serial.println("Server rejects the connection");
         }
     }
     
  }
}

//-----------------------tools-------------------------//
void getRandomBytes(uint8_t *arr,int arrLen)
{
  int i;
  for(i =0;i<arrLen;i++)
    arr[i]=random(0,256);  
}

void printHex(const byte* arr,int len)
{
  int i;
  char ptr1[10];
  char ptr2[10];
  String mystring;
  for (i=0; i<len; i++) {
      sprintf(ptr1,"%x",arr[i]>>4);
      sprintf(ptr2,"%x",arr[i]&0xf);
      mystring += ptr1;
      mystring += ptr2;
      Serial.print(mystring);
      mystring.remove(0,mystring.length());
  }
  Serial.println("");
}

//generate a shared key
void generate_sharedkey(){       
       //generate a shared key
   unsigned long time1,time2;
   time1 = millis();
   if (!ecdh_shared_secret(l_shared2, &l_Q2, l_secret_server,l_random2))
    {
        Serial.println("shared_secret() failed (2)\n");
           return ;
    }
    time2 = millis();
    Serial.print("Generating shared key spends ms:");
    Serial.println(time2-time1);
    Serial.print("shared_secret:");  
    printHex(l_shared2,NUM_ECC_DIGITS);
}

void printDebug(char *text,const byte *arr, int len)
{
   Serial.println(text);
   printHex(arr,len);
}

//----------------------send LED to server----------------------
void sndMsgtoLED(int LedPin,byte *rnd)
{
  Serial.println("Send message via LED");
   unsigned long time1,time2;
   time1 = millis();
  int i,j;
  byte temp[4];
  memset(temp,0,4);
  
  byte isOn =0;
  for(j =0;j<4;j++)
  {
    temp[j] =1;
    for(i=0;i<8;i++)
    {
        isOn = temp[j] & rnd[j];
        if(isOn > 0)
        {
          analogWrite(LedPin, byteOn);
          Serial.print("1");
          delay(100);
        }
        else
        {
          analogWrite(LedPin, byteOff);
          Serial.print("0");
          delay(100);   
   
        }
        temp[j] = temp[j] << 1;  
    }
    Serial.print(" ");
  }
  Serial.println("");
  analogWrite(LedPin, 0);
  time2 = millis();
  Serial.print("Sending 32-bits via VLC spends ms:");
  Serial.println(time2-time1);
}

void calculate_commit()
{
   unsigned long time1,time2;
   time1 = millis();
   unsigned char hashKey = 0;
   Sha1.init();
   Sha1.initHmac(&hashKey,1);
   char input[29];
   memset(input,0,29);
   memcpy(input,l_secret_client,24);
   input[24] = random_client[0];
   input[25] = random_client[1];
   input[26] = random_client[2];
   input[27] = random_client[3];
   Sha1.print(input);     
   memcpy(client_commit,Sha1.resultHmac(),20);
   time2 = millis();
   Serial.print("Calculating commitment spends ms:");
   Serial.println(time2-time1);
}
