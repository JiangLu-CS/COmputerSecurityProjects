#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define KEYLENGTH  0x00800000
void HandleError(char* s);
#define ENCRYPT_ALGORITHM CALG_RC4 
#define ENCRYPT_BLOCK_SIZE 8 
#define MAX_FILE_SIZE 4000000
#define SIGNATURE_SIZE 500
BYTE* pbKeyBlob;  //用来保存导出的公钥
DWORD dwBlobLen;
BOOL VerifyFile(
    PCHAR szSource,
    PCHAR szDestination);
BOOL SignFile(
    PCHAR szSource,
    PCHAR szDestination);
BOOL DecryptFile(
    PCHAR szSource,
    PCHAR szDestination,
    PCHAR szPassword);
BOOL EncryptFile(
    PCHAR szSource,
    PCHAR szDestination,
    PCHAR szPassword);
void main(void)
{
    CHAR szSource[100];
    CHAR szDestination[100];
    CHAR szPassword[100];
    int way[1];
    printf("输入1：进行加密。\n 输入2：进行解密 \n 输入3：签名\n 输入4：验证签名\n\n");
    scanf("%d", way);

    if (way[0] == 1) {
        printf("\n-----------------------加密一个文件---------------------------------\n");
        printf("");
        printf("输入要加密的文件的名称: ");
        scanf("%s", szSource);
        printf("输入加密后生成的文件的名称 ");
        scanf("%s", szDestination);
        printf("输入密码:");
        scanf("%s", szPassword);
        if (EncryptFile(szSource, szDestination, szPassword))
        {
            printf("\n 加密文件成功", szSource);
            printf("\n加密后的文件在 %s.\n", szDestination);
        }

    }
    if (way[0] == 2) {
        printf("\n---------------------解密文件---------------------------------\n");
        printf("");
        printf("输入要解密的文件的名字: ");
        scanf("%s", szSource);
        printf("输入解密后生成的文件的名字: ");
        scanf("%s", szDestination);
        printf("输入密码:");
        scanf("%s", szPassword);
        if (DecryptFile(szSource, szDestination, szPassword))
        {
            printf("解密文件成功\n", szSource);
            printf("解密后的文件在 %s.\n", szDestination);
        }
    }
    if (way[0] == 3) {
        printf("\n-----------------------签名文件-----------------------------\n");
        printf("");
        printf("输入要被签名的文件: ");
        scanf("%s", szSource);
        printf("输入签名后的文件名: ");
        scanf("%s", szDestination);
        if (SignFile(szSource, szDestination))
        {
            printf("签名文件成功\n", szSource);
            printf("签名后的文件在 %s.\n", szDestination);
        }

    }
    if (way[0] == 4) {
        printf("\n-------------------验证签名----------------------------\n");
        printf("");
        printf("输入要被验证签名的文件的名称 ");
        scanf("%s", szSource);
        printf("输入签名的文件的名称 ");
        scanf("%s", szDestination);
        printf("内存分配成功\n ");
        if (VerifyFile(szSource, szDestination))
        {
            printf("验证成功", szSource);
        }

    }
} 


static BOOL VerifyFile(
    PCHAR szSource,   //原文件    
    PCHAR szSignature) //数字签名文件
{
    FILE* hSource;
    FILE* hSignature;
    HCRYPTPROV hCryptProv; //CSP：钥匙容器
    HCRYPTKEY hKey;   //公钥对：包括配对的一个公钥和一个密钥
    HCRYPTKEY hPubKey;  //公钥对中的公钥
    HCRYPTHASH hHash;  //hash对象，用于对数据文件进行hash处理，得到hash值
    //公钥签名就是针对hash值进行签名，而不是原文件，
    //这是因为公钥处理的速度非常慢
    BYTE* pbSignature;
    DWORD dwSigLen;
    PBYTE pbBuffer;
    DWORD dwBufferLen;
    DWORD dwCount;
    if (hSource = fopen(szSource, "rb"))
    {
        printf("打开文件成功", szSource);
    }
    
    if (pbBuffer = (BYTE*)malloc(MAX_FILE_SIZE))
    {
        printf("内存分配成功\n");
    }
    
    //将源文件读入pbBuffer
    dwCount = fread(pbBuffer, 1, MAX_FILE_SIZE, hSource);
    
    // Open signature file 读入签名文件（特殊处理：直接采用保留在内存中的签名来进行验证）
    if (hSignature = fopen(szSignature, "rb"))
    {
        printf("读入签名文件成功", szSignature);
    }

    if (pbSignature = (BYTE*)malloc(SIGNATURE_SIZE))
    {
        printf("内存分配成功\n");
    }

    //将签名读入pbSignature
    dwSigLen = fread(pbSignature, 1, SIGNATURE_SIZE, hSignature);

    //以下获得一个CSP句柄
    if (CryptAcquireContext(
        &hCryptProv,  //调用完成之后hCryptProv保存密钥容器的句柄
        NULL,    //NULL表示使用默认密钥容器，默认密钥容器名为用户登陆名
        NULL,
        PROV_RSA_FULL,
        0))
    {
        printf("获得了一个CSP句柄");
    }
    else
    {
        if (CryptAcquireContext(
            &hCryptProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))//创建密钥容器
        {
            //创建密钥容器成功，并得到CSP句柄
            printf("创建了一个密钥容器");
        }

    }
    //导入 pbKeyBlob 公钥（这个公钥与签名时所用的私钥配对，在签名时导出到pbKeyBlob中）
    if (CryptImportKey(
        hCryptProv,
        pbKeyBlob,
        dwBlobLen,
        0,
        0,
        &hPubKey))
    {
        printf("导入公钥成功");
    }
    else
    
    // Create a new hash object. 对原文件进行hash处理
    if (CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash))
    {
    }
    if (CryptHashData(
        hHash,
        pbBuffer,
        dwCount,
        0))
    {
    }
   
    // 验证数字签名是否正确
    if (CryptVerifySignature(
        hHash,
        pbSignature,
        dwSigLen,
        hPubKey,
        NULL,
        0))
    {
        printf("签名文件通过验证了！");
    }
    else
    {
        printf("这个不是签名文件！");
    }
    if (hSource)
        fclose(hSource);
    if (pbSignature)
        free(pbSignature);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    return(TRUE);
}

static BOOL SignFile(
    PCHAR szSource,
    PCHAR szDestination)
{
    FILE* hSource;
    FILE* hDestination;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    BYTE* pbSignature;
    PBYTE pbBuffer;
    DWORD dwBufferLen;
    DWORD dwCount;
    DWORD dwSigLen;

    if (hSource = fopen(szSource, "rb"))
    {
        printf("文件成功打开", szSource);
    }
    
    // Allocate memory. 
    if (pbBuffer = (BYTE*)malloc(MAX_FILE_SIZE))
    {
        printf("内存成功被分配");
    }

    dwCount = fread(pbBuffer, 1, MAX_FILE_SIZE, hSource);

    if (hDestination = fopen(szDestination, "wb"))
    {
        printf("目标文件成功打开", szDestination);
    }

    //以下获得一个CSP句柄
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,    //NULL表示使用默认密钥容器，默认密钥容器名为用户登陆名
        NULL,
        PROV_RSA_FULL,
        0))
    {
        printf("获得了CSP句柄");
    }
    else
    {
        if (CryptAcquireContext(
            &hCryptProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))//创建密钥容器
        {
            //创建密钥容器成功，并得到CSP句柄
            printf("创建密钥容器成功\n");
        }
     
    }
    if (CryptGetUserKey(
        hCryptProv,                     // 我们已经得到的CSP句柄
        AT_SIGNATURE,                   // 这里想得到signature key pair
        &hKey))                         // 返回密钥句柄
    {
        printf("signature key 可用");
    }
    else  //取signature key pair错误
    {
        printf("No signature key is available./n");
        if (GetLastError() == NTE_NO_KEY) //密钥容器里不存在signature key pair
        {
            // 创建 signature key pair. 
            printf("The signature key does not exist./n");
            printf("Create a signature key pair./n");
            if (CryptGenKey(
                hCryptProv,  //CSP句柄
                AT_SIGNATURE, //创建的密钥对类型为signature key pair
                0,    //key类型，这里用默认值
                &hKey))   //创建成功返回新创建的密钥对的句柄
            {
                printf("创建密钥对\n");
            }
        }
    } // end if
    if (CryptExportKey(
        hKey,
        NULL,
        PUBLICKEYBLOB,
        0,
        NULL,
        &dwBlobLen))
    {
        printf("导出公钥\n");
    }
    if (pbKeyBlob = (BYTE*)malloc(dwBlobLen))
    {
        printf("分配内存\n");
    }

    if (CryptExportKey(
        hKey,
        NULL,
        PUBLICKEYBLOB,
        0,
        pbKeyBlob,
        &dwBlobLen))
    {
    }
    if (CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash))
    {
        printf("哈希对象已创建");
    }

    if (CryptHashData(
        hHash,
        pbBuffer,
        dwCount,
        0))
    {
    }

    //释放缓冲区
    if (pbBuffer)
        free(pbBuffer);
    pbBuffer = NULL;
    dwSigLen = 0;
    if (CryptSignHash(
        hHash,
        AT_SIGNATURE,
        NULL,
        0,
        NULL,
        &dwSigLen))
    {
    }

    if (pbSignature = (BYTE*)malloc(dwSigLen))
    {
        printf("已经为签名文件分配好内存");
    }

    if (CryptSignHash(
        hHash,
        AT_SIGNATURE,
        NULL,
        0,
        pbSignature,
        &dwSigLen))
    {
    }


    if (fwrite(pbSignature, 1, dwSigLen, hDestination) != dwSigLen)
    printf("哈希对象已摧毁\n");
    printf("完成签名了\n");
    if (hKey)
        CryptDestroyKey(hKey);
    if (hHash)
        CryptDestroyHash(hHash);
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    if (hSource)
        fclose(hSource);
    if (hDestination)
        fclose(hDestination);

    return(TRUE);
}
static BOOL DecryptFile(
    PCHAR szSource,
    PCHAR szDestination,
    PCHAR szPassword)
{
    FILE* hSource;
    FILE* hDestination;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    PBYTE pbBuffer;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;
    if (hSource = fopen(szSource, "rb"))
    {
        printf("打开了文件 %s", szSource);
    }
    if (hDestination = fopen(szDestination, "wb"))
    {
        printf("打开了文件 %s ", szDestination);
    }

    //以下获得一个CSP句柄
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,    //NULL表示使用默认密钥容器，默认密钥容器名为用户登陆名
        NULL,
        PROV_RSA_FULL,
        0))
    {
        printf("获得一个CSP句柄");
    }
    else
    {
        if (CryptAcquireContext(
            &hCryptProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))//创建密钥容器
        {
            //创建密钥容器成功，并得到CSP句柄
            printf("创建密钥容器成功");
        }

    }
    if (CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash))
    {
        printf("创建了hash");
    }
    //--------------------------------------------------------------------
    // 用输入的密码产生一个散列
    if (CryptHashData(
        hHash,
        (BYTE*)szPassword,
        strlen(szPassword),
        0))
    {
        printf("输入的密码产生了一个散列");
    }
    //--------------------------------------------------------------------
    // 通过散列生成会话密钥
    if (CryptDeriveKey(
        hCryptProv,
        ENCRYPT_ALGORITHM,
        hHash,
        KEYLENGTH,
        &hKey))
    {
        printf("通过散列生成会话密钥 /n");
    }
    CryptDestroyHash(hHash);
    hHash = NULL;
    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    if (ENCRYPT_BLOCK_SIZE > 1)
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    else
        dwBufferLen = dwBlockLen;
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        printf("Memory has been allocated for the buffer. /n");
    }


    //*****************************解密***********************************
    do
    {
        dwCount = fread(pbBuffer, 1, dwBlockLen, hSource);
        if (ferror(hSource))
        {
        }
        if (!CryptDecrypt(
            hKey,   //密钥
            0,    //如果数据同时进行散列和加密，这里传入一个散列对象
            feof(hSource), //如果是最后一个被加密的块，输入TRUE.如果不是输.
            //入FALSE这里通过判断是否到文件尾来决定是否为最后一块。
            0,    //保留
            pbBuffer,  //输入被加密数据，输出加密后的数据
            &dwCount))  //输入被加密数据实际长度，输出加密后数据长度
        {
        }
        fwrite(pbBuffer, 1, dwCount, hDestination);
        if (ferror(hDestination))
        {
        }
    } while (!feof(hSource));
    //*****************************解密***********************************

    if (hSource)
        fclose(hSource);
    if (hDestination)
        fclose(hDestination);

    //--------------------------------------------------------------------
    // 释放内存
    if (pbBuffer)
        free(pbBuffer);
    //--------------------------------------------------------------------
    // 摧毁sessionkey
    if (hKey)
        CryptDestroyKey(hKey);
    // 摧毁哈希对象
    if (hHash)
        CryptDestroyHash(hHash);
    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    return(TRUE);
}

static BOOL EncryptFile(
    PCHAR szSource,
    PCHAR szDestination,
    PCHAR szPassword)
{

    FILE* hSource;
    FILE* hDestination;

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    PBYTE pbBuffer;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwCount;

    // 打开源文件
    if (hSource = fopen(szSource, "rb"))
    {
        printf("打开了文件 %s \n", szSource);
    }

    // 打开目标文件
    if (hDestination = fopen(szDestination, "wb"))
    {
        printf("打开了目标文件 %s  \n", szDestination);
    }

    //获得一个CSP句柄
    if (CryptAcquireContext(
        &hCryptProv,
        NULL,				//默认密钥容器，默认密钥容器名即用户登陆名
        NULL,
        PROV_RSA_FULL,
        0))
    {
        printf("获得了CSP句柄 \n");
    }
    else
    {
        if (CryptAcquireContext(
            &hCryptProv,
            NULL,
            NULL,
            PROV_RSA_FULL,
            CRYPT_NEWKEYSET))//创建密钥容器
        {
            //创建密钥容器成功，并得到CSP句柄
            printf("创建了密钥容器\n");
        }


    }

    //创建一个对称密钥
    //创建哈希对象
    if (CryptCreateHash(
        hCryptProv,
        CALG_MD5,
        0,
        0,
        &hHash))
    {
        printf("创建了一个hash \n");
    }

    // 用输入的密码产生一个散列
    if (CryptHashData(
        hHash,
        (BYTE*)szPassword,
        strlen(szPassword),
        0))
    {
        printf("已经用输入的密码产生一个hash. \n");
    }

    // 通过散列生成会话密钥
    if (CryptDeriveKey(
        hCryptProv,
        ENCRYPT_ALGORITHM,
        hHash,
        KEYLENGTH,
        &hKey))
    {
        printf("已通过散列生成会话密钥. \n");
    }
    // Destroy the hash object. 

    CryptDestroyHash(hHash);
    hHash = NULL;

    // 因为加密算法是按ENCRYPT_BLOCK_SIZE 大小的块加密的，所以被加密的
    // 数据长度必须是ENCRYPT_BLOCK_SIZE 的整数倍。下面计算一次加密的
    // 数据长度。

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    if (ENCRYPT_BLOCK_SIZE > 1)
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    else
        dwBufferLen = dwBlockLen;

    //分配内存
    if (pbBuffer = (BYTE*)malloc(dwBufferLen))
    {
        printf("内存已分配. \n");
    }

    // 在循环中写文件

    do
    {
        dwCount = fread(pbBuffer, 1, dwBlockLen, hSource);
        if (ferror(hSource))
        {
            //HandleError("Error reading plaintext!\n");
        }

        //--------------------------------------------------------------------
        // 加密数据
        if (!CryptEncrypt(
            hKey,			//密钥
            0,				//如果数据同时进行散列和加密，这里传入一个散列对象
            feof(hSource),	//如果是最后一个被加密的块，输入TRUE.如果不是输.
            //入FALSE这里通过判断是否到文件尾来决定是否为最后一块。
            0,				//保留
            pbBuffer,		//输入被加密数据，输出加密后的数据
            &dwCount,		//输入被加密数据实际长度，输出加密后数据长度
            dwBufferLen
        ))	//pbBuffer的大小。
        {
        }

        //写数据到目标文件

        fwrite(pbBuffer, 1, dwCount, hDestination);
        if (ferror(hDestination))
        {
           
        }

    } while (!feof(hSource));
    if (hSource)
        fclose(hSource);
    if (hDestination)
        fclose(hDestination);

    if (pbBuffer)
        free(pbBuffer);

    if (hKey)
        CryptDestroyKey(hKey);


    if (hHash)
        CryptDestroyHash(hHash);

    if (hCryptProv)
        CryptReleaseContext(hCryptProv, 0);
    return(TRUE);
} // End of Encryptfile


