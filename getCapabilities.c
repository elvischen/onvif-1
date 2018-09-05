#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <openssl/sha.h>


#include "SearchBinding.nsmap"
#include "soapH.h"
#include "soapStub.h"
#include "stdsoap2.h"


 
static const char base64digits[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 
#define BAD     -1
static const signed char base64val[] = { 
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63, 
    52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
    BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14, 
    15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
    BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40, 
    41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD
};
#define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)
void base64_bits_to_64(unsigned char *out, const unsigned char *in, int inlen)
{
    for (; inlen >= 3; inlen -= 3)
    {   
        *out++ = base64digits[in[0] >> 2]; 
        *out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
        *out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
        *out++ = base64digits[in[2] & 0x3f];
        in += 3;
    }   
 
    if (inlen > 0)
    {   
        unsigned char fragment;
 
        *out++ = base64digits[in[0] >> 2]; 
        fragment = (in[0] << 4) & 0x30;
 
        if (inlen > 1)
            fragment |= in[1] >> 4;
 
        *out++ = base64digits[fragment];
        *out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
        *out++ = '=';
    }
 
    *out = '\0';
}
int base64_64_to_bits(char *out, const char *in)
{
    int len = 0;
    register unsigned char digit1, digit2, digit3, digit4;
 
    if (in[0] == '+' && in[1] == ' ')
        in += 2;
    if (*in == '\r')
        return(0);
 
    do {
        digit1 = in[0];
        if (DECODE64(digit1) == BAD)
            return(-1);
        digit2 = in[1];
        if (DECODE64(digit2) == BAD)
            return(-1);
        digit3 = in[2];
        if (digit3 != '=' && DECODE64(digit3) == BAD)
            return(-1);
        digit4 = in[3];
        if (digit4 != '=' && DECODE64(digit4) == BAD)
            return(-1);
        in += 4;
        *out++ = (DECODE64(digit1) << 2) | (DECODE64(digit2) >> 4);
        ++len;
        if (digit3 != '=')
        {
            *out++ = ((DECODE64(digit2) << 4) & 0xf0) | (DECODE64(digit3) >> 2);
            ++len;
            if (digit4 != '=')
            {
                *out++ = ((DECODE64(digit3) << 6) & 0xc0) | DECODE64(digit4);
                ++len;
            }
        }
    } while (*in && *in != '\r' && digit4 != '=');
 
    return (len);
}
 //简单的demo测试程序，实际可以不需要下面这个，只要上面两个函数接口就好！
/* int main(void)
{
    char p[] = "I Love You, Forever!";
    char test[48] = {0};
    base64_bits_to_64(test, p, sizeof("I Love You, Forever!"));
 
    printf("p = %s , test = %s \n", p, test);
    char a[48]= {0};
    base64_64_to_bits( a, test);
    printf("a = %s , test = %s \n", a, test);
    return 0;
}

*/


typedef struct
{
    char username[64];
    char password[32];
}UserInfo_S;
 
static void ONVIF_GenrateDigest(unsigned char *pwddigest_out, unsigned char *pwd, char *nonc, char *time)
{
    const unsigned char *tdist;
    unsigned char dist[1024] = {0};
    char tmp[1024] = {0};
    unsigned char bout[1024] = {0};
    strcpy(tmp,nonc);
    base64_64_to_bits((char*)bout, tmp);
    sprintf(tmp,"%s%s%s",bout,time,pwd);
    SHA1((const unsigned char*)tmp,strlen((const char*)tmp),dist);
    tdist = dist;
    memset(bout,0x0,1024);
    base64_bits_to_64(bout,tdist,(int)strlen((const char*)tdist));
    strcpy((char *)pwddigest_out,(const char*)bout);
	
}
 //鉴权操作函数，以及上面的用到了openssl接口
static struct soap* ONVIF_Initsoap(struct SOAP_ENV__Header *header, const char *was_To, const char *was_Action, int timeout, UserInfo_S *pUserInfo)
{
    struct soap *soap = NULL;
    unsigned char macaddr[6];
    char _HwId[1024];
    unsigned int Flagrand;
    soap = soap_new();
    if(soap == NULL)
    {
        printf("[%d]soap = NULL\n", __LINE__);
        return NULL;
    }
     soap_set_namespaces( soap, namespaces);
    //超过5秒钟没有数据就退出
    if (timeout > 0)
    {
        soap->recv_timeout = timeout;
        soap->send_timeout = timeout;
        soap->connect_timeout = timeout;
    }
    else
    {
        //如果外部接口没有设备默认超时时间的话，我这里给了一个默认值10s
        soap->recv_timeout    = 10;
        soap->send_timeout    = 10;
        soap->connect_timeout = 10;
    }
    soap_default_SOAP_ENV__Header(soap, header);
 
    // 为了保证每次搜索的时候MessageID都是不相同的！因为简单，直接取了随机值
    srand((int)time(0));
    Flagrand = rand()%9000 + 1000; //保证四位整数
    macaddr[0] = 0x1; macaddr[1] = 0x2; macaddr[2] = 0x3; macaddr[3] = 0x4; macaddr[4] = 0x5; macaddr[5] = 0x6;
    sprintf(_HwId,"urn:uuid:%ud68a-1dd2-11b2-a105-%02X%02X%02X%02X%02X%02X",
            Flagrand, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);
    header->wsa__MessageID =(char *)malloc( 100);
    memset(header->wsa__MessageID, 0, 100);
    strncpy(header->wsa__MessageID, _HwId, strlen(_HwId));
 
    // 这里开始作鉴权处理了，如果有用户信息的话，就会处理鉴权问题
    //如果设备端不需要鉴权的话，在外层调用此接口的时候把User信息填空就可以了 
    if( pUserInfo != NULL )
    {
        header->wsse__Security = (struct _wsse__Security *)malloc(sizeof(struct _wsse__Security));
        memset(header->wsse__Security, 0 , sizeof(struct _wsse__Security));
 
        header->wsse__Security->UsernameToken = (struct _wsse__UsernameToken *)calloc(1,sizeof(struct _wsse__UsernameToken));
        header->wsse__Security->UsernameToken->Username = (char *)malloc(64);
        memset(header->wsse__Security->UsernameToken->Username, '\0', 64);
 
        header->wsse__Security->UsernameToken->Nonce = (char *)malloc(64);
		
        strcpy((char *)header->wsse__Security->UsernameToken->Nonce,"LKqI6G/AikKCQrN0zqZFlg=="); //注意这里
		
 
        header->wsse__Security->UsernameToken->wsu__Created = (char*)malloc(64);
        memset(header->wsse__Security->UsernameToken->wsu__Created, '\0', 64);
        strcpy(header->wsse__Security->UsernameToken->wsu__Created,"2018-09-1T07:50:45Z");
 
        strcpy(header->wsse__Security->UsernameToken->Username, pUserInfo->username);
        header->wsse__Security->UsernameToken->Password = (struct _wsse__Password *)malloc(sizeof(struct _wsse__Password));
        header->wsse__Security->UsernameToken->Password->Type = (char*)malloc(128);
        memset(header->wsse__Security->UsernameToken->Password->Type, '\0', 128);
        strcpy(header->wsse__Security->UsernameToken->Password->Type,\
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest");
        header->wsse__Security->UsernameToken->Password->__item = (char*)malloc(128);
		memset(header->wsse__Security->UsernameToken->Password->__item, '\0', 128);
        ONVIF_GenrateDigest((unsigned char*)header->wsse__Security->UsernameToken->Password->__item,\
                (unsigned char*)pUserInfo->password,(char *)header->wsse__Security->UsernameToken->Nonce,header->wsse__Security->UsernameToken->wsu__Created);
				
		//printf("username:%s passwd:%s Nonce:%s Created:%s",header->wsse__Security->UsernameToken->Username,header->wsse__Security->UsernameToken->Password->__item,header->wsse__Security->UsernameToken->Nonce,header->wsse__Security->UsernameToken->wsu__Created);
 
    }
    if (was_Action != NULL)
    {
        header->wsa__Action =(char *)malloc(1024);
        memset(header->wsa__Action, '\0', 1024);
        strncpy(header->wsa__Action, was_Action, 1024);//"http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";
    }
    if (was_To != NULL)
    {
        header->wsa__To =(char *)malloc(1024);
        memset(header->wsa__To, '\0', 1024);
        strncpy(header->wsa__To,  was_To, 1024);//"urn:schemas-xmlsoap-org:ws:2005:04:discovery";   
    }
    soap->header = header;
    return soap;
}



int ONVIF_Capabilities()  //获取设备能力接口
{
        
    int retval = 0;
    struct soap *soap = NULL;
    struct _tds__GetCapabilities capa_req;
    struct _tds__GetCapabilitiesResponse capa_resp;
        
    struct SOAP_ENV__Header header;
 
    UserInfo_S stUserInfo;
    memset(&stUserInfo, 0, sizeof(UserInfo_S));
 
    //正确的用户名和错误的密码
    strcpy(stUserInfo.username, "admin");
    strcpy(stUserInfo.password, "admin123");
	
	capa_resp.Capabilities = (struct tt__Capabilities*)soap_malloc(soap,sizeof(struct tt__Capabilities)) ;
        
    //此接口中作验证处理， 如果不需要验证的话，stUserInfo填空即可
    soap = ONVIF_Initsoap(&header, NULL, NULL, 5, &stUserInfo);
    char *soap_endpoint = (char *)malloc(256);
    memset(soap_endpoint, '\0', 256);
    //海康的设备，固定ip连接设备获取能力值 ,实际开发的时候，"172.18.14.22"地址以及80端口号需要填写在动态搜索到的具体信息
    sprintf(soap_endpoint, "http://192.168.0.192/onvif/device_service");

    capa_req.Category = (enum tt__CapabilityCategory *)soap_malloc(soap, sizeof(int));
    capa_req.__sizeCategory = 1;
    *(capa_req.Category) = (enum tt__CapabilityCategory)0;
    //此句也可以不要，因为在接口soap_call___tds__GetCapabilities中判断了，如果此值为NULL,则会给它赋值
    const char *soap_action = "http://www.onvif.org/ver10/device/wsdl/GetCapabilities";


    do
    {
        soap_call___tds__GetCapabilities(soap, soap_endpoint, soap_action, &capa_req, &capa_resp);

        if (soap->error)
        {
                printf("[%s][%d]--->>> soap error: %d, %s, %s\n", __func__, __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
                retval = soap->error;
                break;
        }
        else   //获取参数成功
        {
            // 走到这里的时候，已经就是验证成功了，可以获取到参数了，
            // 在实际开发的时候，可以把capa_resp结构体的那些需要的值匹配到自己的私有协议中去，简单的赋值操作就好   
            	
            	printf("url:%s\n",capa_resp.Capabilities->Media->XAddr);
              printf("[%s][%d] Get capabilities success !\n", __func__, __LINE__);
        }
    }while(0);

    free(soap_endpoint);
    soap_endpoint = NULL;
    soap_destroy(soap);
    return retval;
}


int ONVIF_GetProfiles(){

	
    struct soap *soap;            //soap对象
    char soap_endpoint[256];    //能力集
    char *soap_action = NULL;      //接口地址,一一对应,留空会自动赋值
    struct _trt__GetProfiles media_GetProfiles;  //发送内容
    struct _trt__GetProfilesResponse media_GetProfilesResponse;  //接收内容

	int retval = 0;
        
    struct SOAP_ENV__Header header;
 
    UserInfo_S stUserInfo;
    memset(&stUserInfo, 0, sizeof(UserInfo_S));
 
    //正确的用户名和错误的密码
    strcpy(stUserInfo.username, "admin");
    strcpy(stUserInfo.password, "admin123");
        
    //此接口中作验证处理， 如果不需要验证的话，stUserInfo填空即可
    soap = ONVIF_Initsoap(&header, NULL, NULL, 5, &stUserInfo);
	
	/* 1 GetProfiles */
	memset(soap_endpoint, '\0', 256);
	sprintf(soap_endpoint, "http://192.168.0.192/onvif/Media");

	
	do
	{
		soap_call___trt__GetProfiles(soap, soap_endpoint, soap_action, &media_GetProfiles, &media_GetProfilesResponse);
		if (soap->error)
		{
			printf("[%s][%d]--->>> soap error: %d, %s, %s\n", __func__, __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
			retval = soap->error;
			break;
		}
		else
		{
			printf("==== [ Media Profiles Response ] ====\n"
				"> Name  :	%s\n"
				"> token :	%s\n\n", \
				media_GetProfilesResponse.Profiles->Name, \
				media_GetProfilesResponse.Profiles->token );
				//printf("profile url:%s\n",media_GetProfilesResponse.Profiles[0].VideoSourceConfiguration.);
		}
	}while(0);
}


int ONVIF_GetStreamUri(){

	int retval = 0;
	struct soap *soap; 
	char soap_endpoint[256];    //能力集
    char *soap_action = NULL;      //接口地址,一一对应,留空会自动赋值
	struct _trt__GetStreamUri media_GetStreamUri;
	struct _trt__GetStreamUriResponse media_GetStreamUriResponse;

	struct SOAP_ENV__Header header;

	char token[64] = {'\0'};
	strcpy(token,"Profile_1");
 
    UserInfo_S stUserInfo;
    memset(&stUserInfo, 0, sizeof(UserInfo_S));
 
    //正确的用户名和错误的密码
    strcpy(stUserInfo.username, "admin");
    strcpy(stUserInfo.password, "admin123");
        
    //此接口中作验证处理， 如果不需要验证的话，stUserInfo填空即可
    soap = ONVIF_Initsoap(&header, NULL, NULL, 5, &stUserInfo);
	/* 2 GetStreamUri */
	memset(soap_endpoint, '\0', 256);
	sprintf(soap_endpoint, "http://192.168.0.192/onvif/Media");
	 
	media_GetStreamUri.StreamSetup = (struct tt__StreamSetup *)soap_malloc(soap, sizeof(struct tt__StreamSetup));
	media_GetStreamUri.StreamSetup->Transport = (struct tt__Transport *)soap_malloc(soap, sizeof(struct tt__Transport));
	 
	media_GetStreamUri.StreamSetup->Stream = (enum tt__StreamType)0;
	media_GetStreamUri.StreamSetup->Transport->Protocol = (enum tt__TransportProtocol)0;
	media_GetStreamUri.StreamSetup->Transport->Tunnel = NULL;
	media_GetStreamUri.StreamSetup->__size = 1;
	media_GetStreamUri.StreamSetup->__any = NULL;
	media_GetStreamUri.StreamSetup->__anyAttribute = NULL;
	media_GetStreamUri.ProfileToken = token;
	 
	do
	{
		soap_call___trt__GetStreamUri(soap, soap_endpoint, soap_action, &media_GetStreamUri, &media_GetStreamUriResponse);
		if (soap->error)
		{
			printf("[%s][%d]--->>> soap error: %d, %s, %s\n", __func__, __LINE__, soap->error, *soap_faultcode(soap), *soap_faultstring(soap));
			retval = soap->error;
			break;
		}
		else
		{
			printf("==== [ Media Stream Uri Response ] ====\n"
				   "> MediaUri :\n\t%s\n", \
				   media_GetStreamUriResponse.MediaUri->Uri);
		}
	}while(0);
}

