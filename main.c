#include<stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>

#include "sharefun.h"

#define PORT 54321
#define MAX_SIZE FD_SETSIZE //最大可用已连接套接字的个数
#define LISTEN_MAX 5
#define BUF_SIZE 10240

fd_set fds;

void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
 
    for (i = 0; i < sourceLen; i++)
    {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f ;
 
        highByte += 0x30;
 
        if (highByte > 0x39)
                dest[i * 2] = highByte + 0x07;
        else
                dest[i * 2] = highByte;
 
        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return ;
}
 
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[3];
 
    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 2], szTmp, 2 );
    }
    return ;
}
 
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)
{
    short i;
    unsigned char highByte, lowByte;
    
    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);
 
        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;
 
        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;
 
        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}

static void PrintMesg(int i , char buf[])
{
	printf("fd : %d, msg: %s\n", i , buf);
}

void dump_data(unsigned char* data, int len) {

int i = 0;
printf("\n");
	for(i=0;i<len;++i)
		printf("%02x ",data[i]);
printf("\n");

}

unsigned char x[31]={0};

void *TCP_Send(void *pPara)
{
        char Buf[BUF_SIZE] = {0};
        ssize_t Size  = 0;
        int *pConnfd = 0;
        unsigned char *pReceiveData = NULL;
        int ReceiveLen = 0;

    if (NULL == pPara)
    {
        VOS_PRINTF_LOG("TCP_Send: TCP_Send Failed!\n");
        return NULL;
    }

        pConnfd = (int *)pPara;
        if(*pConnfd < 0)
        {
                VOS_PRINTF_LOG("TCP_Send:Get pConnfd Failed \n" );
                return NULL;
        }

	int X=10;
	int Y=20;
#define BUFLEN 255   

char tmpBuf[BUFLEN];   

        while(1)
        {

time_t t = time( 0 );   
memset(tmpBuf,0x00,sizeof(tmpBuf));
strftime(tmpBuf, BUFLEN, "%Y%m%d%H%M%S", localtime(&t)); //format date and time. 
printf("%s\n",tmpBuf);

unsigned char dt[7];
HexStrToByte(tmpBuf,dt,14);

int i = 0;
for(i=8;i<15;++i)
	x[i]=dt[i-8];

		if(access("/tmp/010101",F_OK)==0)
			x[7]=0x01;
		else
			x[7]=0x02;
        		
		if(*pConnfd<1) break;

		write(*pConnfd, x, 31);
		dump_data(x,31);

    		sleep(rand()%(Y-X+1)+X);
	}

        return NULL;
}

void *TCP_Analyzer(void *pPara)
{
	char Buf[BUF_SIZE] = {0};
	ssize_t Size  = 0;
	int *pConnfd = 0;
	unsigned char *pReceiveData = NULL;
	int ReceiveLen = 0;

    if (NULL == pPara)
    {
        VOS_PRINTF_LOG("TCP_Analyzer: TCP_Analyzer Failed!\n");
        return NULL;
    }

	pConnfd = (int *)pPara;
	if(*pConnfd < 0)
	{
		VOS_PRINTF_LOG("TCP_Analyzer:Get pConnfd Failed \n" );
		return NULL;
	}

	while(1)
	{
		memset(Buf, '\0', sizeof(Buf));
		Size = read(*pConnfd, Buf,sizeof(Buf) );
		if (Size <= 0) //没有接收到数据，关闭描述符，释放在TCPServer申请的空间
		{
			VOS_PRINTF_LOG("TCP_Analyzer:remote client close\n" );
			close(*pConnfd);
			VOS_FREE(pConnfd);
			return NULL;
		}
		else
		{
			dump_data(Buf,(int)Size);
			//printf("TCP_Analyzer:%s,%d\n",Buf,(int)Size);
		}
	}
	close(*pConnfd);
	VOS_FREE(pConnfd);

	return NULL;
}

void *TCPServer()
{
	pthread_t threadID = 0;
	struct sockaddr_in Server;
	struct sockaddr_in Client;
	int Listenfd = 0;
	int *pConnectfd = NULL;
	int i = 0;
	int j = 0;
	int yes = 0;
	int index = 0;
	int Connfd = 0;
	int ret = 0;
	socklen_t len = 0;
	char logMessage[128] = {0};
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	Listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (Listenfd < 0)
	{
		perror("socket");
		exit(1);
	}
	VOS_PRINTF_LOG("TCPServer:create socket success\n");

 	int opt = 1;
	if(setsockopt(Listenfd, SOL_SOCKET,SO_REUSEADDR, (const void *) &opt, sizeof(opt)))
	{
		perror("setsockopt");
		close(Listenfd);
		exit(11);
	}
/*
	if(setsockopt(Listenfd, SOL_SOCKET, SO_REUSEADDR, &yes ,sizeof(int)))
	{
		perror("setsockopt");
		close(Listenfd);
		exit(11);
	}
*/
	bzero(&Server, sizeof(Server));
	Server.sin_family = AF_INET;
	Server.sin_port = htons(PORT );
	Server.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(Listenfd, (struct sockaddr*)&Server, sizeof(Server)) < 0)
	{
		perror("bind");
		close(Listenfd);
		exit(2);
	}
	VOS_PRINTF_LOG("TCPServer:bind socket success\n");

	if (listen(Listenfd, LISTEN_MAX) < 0)
	{
		perror("listen error");
		close(Listenfd);
		exit(3);
	}
	VOS_PRINTF_LOG("TCPServer:listen socket success\n");

	while (1)
	{
		FD_ZERO(&fds);//描述符集合初始化
		FD_SET(Listenfd,&fds);

		struct timeval timeout = {30, 0};

		switch(select(Listenfd + 1, &fds,NULL, NULL, &timeout ))
		{
			case -1:
				memset(logMessage, 0, 128);
	            sprintf(logMessage,"main: create TCP server select fail(%d) %s.\n", errno, strerror(errno));
	            VOS_PRINTF_LOG(logMessage);
				return NULL;

			case 0:
				VOS_PRINTF_LOG("TCPServer:TCP receiving nothing......\n");
				break;

			default:
			{
				if (FD_ISSET(Listenfd, &fds))
				{
					len = sizeof(Client);
					bzero(&Client, len);

					Connfd = accept(Listenfd, (struct sockaddr*)&Client,&len );
					//若有新的连接
					if (Connfd != -1)
					{
						pConnectfd = (int *)malloc(sizeof(int));
		                if (NULL == pConnectfd)
                        {
                            VOS_PRINTF_LOG("TCPServer: pConnectfd malloc Failed.\n");
                            break;
                        }

						memset(pConnectfd,0,sizeof(int));
						*pConnectfd = Connfd;

						VOS_PRINTF_LOG("TCPServer:get a new request!\n");
						printf("TCPServer:the connect fd is %d\n",Connfd);


						ret = pthread_create(&threadID, &attr, TCP_Analyzer, (void *)pConnectfd);
						if(0 != ret)
						{
							VOS_PRINTF_LOG("TCPServer: TCP_Analyzer build Fail!\n");
							FD_CLR(Listenfd, &fds);// 清除 fds中相应的文件描述符
							VOS_FREE(pConnectfd);
							return NULL;
						}


						pthread_create(&threadID, &attr, TCP_Send, (void *)pConnectfd);
					}
				}
			}
		}
	}
	close(Listenfd);
	FD_CLR(Listenfd, &fds);// 清除 fds中相应的文件描述符
	pthread_attr_destroy(&attr);//线程属性销毁
	VOS_FREE(pConnectfd);
	return NULL;
}

int main()
{
	int ret = 0;
	pthread_t threadID = 0;

    VOS_PRINTF_ENABLE();

	VOS_PRINTF_LOG("Main Init OK!\n");

x[0]=0x23;
x[1]=0x23;
x[2]=0xAA;
x[3]=0x01;
x[4]=0xA0;
x[5]=0x00;
x[6]=0x1D;
x[7]=0x01;
x[8]=0x00;
x[9]=0x01;
x[10]=0x02;
x[11]=0x03;
x[12]=0x04;
x[13]=0x05;
x[14]=0x06;
x[15]=0x07;
x[16]=0x00;
x[17]=0x00;
x[18]=0x00;
x[19]=0x00;
x[20]=0x00;
x[21]=0x00;
x[22]=0x00;
x[23]=0x00;
x[24]=0x00;
x[25]=0x00;
x[26]=0xFF;
x[27]=0x01;
x[28]=0x02;
x[29]=0x73;
x[30]=0x73;


	ret = pthread_create(&threadID, NULL, TCPServer, NULL);
	if(0 != ret)
	{
		(void)VOS_PRINTF_LOG("TCPServer: TCPServer build Fail!\n");
		return VOS_ERR;
	}

    while(1)
    {
        sleep(10);
    }

	return 0;
}

