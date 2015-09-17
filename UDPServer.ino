#include <ecc.h>
#include <SPI.h>
#include <Ethernet.h>
#include <EthernetUdp.h>
#include <string.h>
#include <sha1.h>


//EEC Keys
EccPoint l_Q1;
uint8_t l_secret_server[NUM_ECC_DIGITS  + 1];
uint8_t l_secret_client[NUM_ECC_DIGITS + 1];
uint8_t l_shared1[NUM_ECC_DIGITS + 1];
uint8_t l_random1[NUM_ECC_DIGITS +1 ];

//server information
byte mac[] =  {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xEA };
IPAddress server_ip(192,168,1,1);
unsigned int server_port = 9999;

//An EthernetUDP instance
EthernetUDP Udp;

//random of server
byte random_server[4];
//random of client
byte random_client[4];
//commitment from client
byte client_commit[20];
//decommitment from client
byte client_decommit[4];

byte ACK = 0;

byte packetBuffer[UDP_TX_PACKET_MAX_SIZE + 1]; //buffer to hold incoming packet,

//visible light communication 
int photocellPin = 0;     // the cell and 10K pulldown are connected to a0
int brightZero = 600;
int brightOne = 900;
int  photocellReading; //photocell value
byte vlcBuffer[4];

byte isAccept = 0;

//--------------------begin setup--------------------------------//
void init_key()
{
  memset(l_secret_server,0,NUM_ECC_DIGITS  + 1);
  memset(l_secret_client,0,NUM_ECC_DIGITS  + 1);
  memset(l_shared1,0,NUM_ECC_DIGITS  + 1);
  memset(l_random1,0,NUM_ECC_DIGITS  + 1);
}
void setup()
{
   //start the Ethernet UDP
   Ethernet.begin(mac,server_ip);
   Udp.begin(server_port);
   Serial.begin(9600);
   init_key();
   //generate ECC random and key
   randomSeed(analogRead(0));
   getRandomBytes(l_secret_server, NUM_ECC_DIGITS * sizeof(uint8_t));
   getRandomBytes(l_random1, NUM_ECC_DIGITS * sizeof(uint8_t));
   ecc_make_key(&l_Q1, l_secret_server, l_secret_server);
   
   //generate a random RA
    getRandomBytes(random_server, 4 * sizeof(uint8_t));
    //setup for VLC
    memset(vlcBuffer,0,4);
    delay(500);
}
//--------------------end setup--------------------------------//
//-----------------------------------------------------------------//
byte say = 0;

//send a message
void sndMsg(byte *buf, int len)
{
    Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
    Udp.write(buf,len);
    Udp.endPacket();
    delay(300);
}

//process request from client
void processRequestedMsg(int request)
{
    if(request == 99) 
    {
      //send say = 1
      if(say == 0)
      {
        say =1;
        Serial.println("Send ACK = 1");
        sndMsg(&say,1);
        isAccept = 0;
      }
    }
    if(request == 3)
    {
      //send l_secret_server
      if(say == 21)
      {
         Serial.println("Send server key");
         sndMsg(l_secret_server,NUM_ECC_DIGITS);
      }
    }
    if(request == 4)
    {
      //send ra
        Serial.println("Send server's random ");
        sndMsg(random_server,4);
    }
    if(request == 41)
    {
      //send say = 5
         say = 5;
         sndMsg(&say,1);
         photoReading();
         //---received client decommit then extract ra
         memcpy(client_decommit,vlcBuffer,4);
         printDebug("Received client decommit",client_decommit,4);
          extract_client_random();
         
          //send ACK 51
          ACK = 51;
          Serial.println("Send ACK = 51");
          sndMsg(&ACK,1);
          //generate random key when commitment is checked
          //commitment_check();
          if(commitment_check() == 0)
          {
             generate_sharedkey(); 
             isAccept = 1;
          }
          else
            isAccept = 0;
          
    }
    //request for debug shared key
    if(request == 6)
    {
       byte OK[2];
       if(isAccept == 1)
       {
         OK[0] =1;
         OK[1] = 1;
         sndMsg(OK,2);
       }
       else
       {
         OK[0] = 0;
         OK[1] = 0;
         sndMsg(OK,2);
       }
      
       say =0;
    }

}

//process received data from client
void receiveData(const byte *buf, int packetSize)
{ 
  if(say == 1)
  {
    //accept l_secret_client, check if the data is a key or not - based on size
     if(packetSize == NUM_ECC_DIGITS){
       
        memcpy(l_secret_client,buf,NUM_ECC_DIGITS);
        printDebug("Received client key",l_secret_client,NUM_ECC_DIGITS);
            // send say = 2
        say = 2;
        sndMsg(&say,1);
        Serial.println("Send request 2");
     }
     else
      Serial.println("Cannot parse client key");    
  }
  else
  if(say == 2)
  {
    //accept commit h(l_client_secret,random_client)
    if(packetSize == 20){
       memcpy(client_commit,buf,20);
       printDebug("Received client commit",client_commit,20);         
      //send ACK 21
       say = 21;
       sndMsg(&say,1);
       Serial.println("Send request 21");
     }
     else
      Serial.println("Cannot parse client commit value");

  }
}

//------------------begin loop-----------------------//


void loop()
{
  
   int packetSize = Udp.parsePacket();
  
   if(Udp.available())
   {
     Udp.read(packetBuffer,UDP_TX_PACKET_MAX_SIZE);
     //Serial.println("Contents:");
     //printHex(packetBuffer,packetSize);
   }
   
   //when receive a request from client
  
   if(packetSize == 1) 
   {
     //process request from client
     byte request;
     request = packetBuffer[0] ;
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
   if (!ecdh_shared_secret(l_shared1, &l_Q1, l_secret_client,l_random1))
    {
        Serial.println("shared_secret() failed (2)\n");
           return ;
    }
    Serial.print("shared_secret:");
    printHex(l_shared1,NUM_ECC_DIGITS);
}
void printDebug(char *text,const byte *arr, int len)
{
   Serial.println(text);
   printHex(arr,len);
}

//----------------receive decommit value on VLC channel
void photoReading()
{
   int loop_count =0;
   int index = 0;
   memset(vlcBuffer,0,4);
   while(loop_count <1000)
   {
       photocellReading = analogRead(photocellPin); 
       if(photocellReading < brightZero)
       {
          //Serial.println(" - ");
          //index = 0;
          delay(10); 
       }
      else{
          delay(45);
          for(index = 1;index <=32;index ++)
          {
             if(photocellReading < brightZero)
             {
                 delay(5);
                 index = index -1;
             }
             if(photocellReading <= brightOne && photocellReading > brightZero)
             {
                 //if(index <= 32)
                 //   VLCBuffer[index-1] = 0;
                 delay(100);
             }else
            if(photocellReading >= brightOne)
            {
                 //Serial.print("1");
                 if(index <= 32){
                  vlcBuffer[(index-1)/8] = vlcBuffer[(index-1)/8] | ((byte)1<<((index-1)%8)); 
                 delay(98);
                 }
             }
             photocellReading = analogRead(photocellPin); 
          }
           //print_arr();
           break;
      }
      loop_count++;  
   }
  
}

void extract_client_random()
{
       //calculate hmac 
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
       //calculate random_client by xor client_decommit with hashMac
       int i;
       for(i = 0;i<4;i++)
        random_client[i]= client_decommit[i]^hashMac[i]; 
       //print debug
       printDebug("extracting random_client:",random_client,4);
}


int commitment_check()
{
    unsigned char hashKey = 0;
    char hashResult[20];
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
   memcpy(hashResult,Sha1.resultHmac(),20);
   printDebug("hashResult:",(byte*)hashResult,20);
    if(memcmp(hashResult,client_commit,20) == 0)
    {
        Serial.println("commitment checked successfully");
        return 0;
    }
    else
      Serial.println("commitment checked fail");
      return 1;
}
