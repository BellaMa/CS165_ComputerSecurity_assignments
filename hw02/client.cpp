#include "string.h"
#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include <sys/errno.h>
#include <openssl/rsa.h>
int readFile(char *filename, char *data) {
    FILE *fp;
    if ((fp = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "open %s error: %s\n", filename, strerror(errno));
        return -1;
    }
    int n  = fread(data, 1 ,2000, fp);
    fprintf(stdout, "\nread %s finished\n", filename);
    data[n]='\0';
    //    printf("******** length is n = %d  ******\n",n);
    fclose(fp);
    return n;
}

int writeFile(char *filename, char *data, int len) {
    FILE *fp;
    if ((fp = fopen(filename, "w")) == NULL) {
        fprintf(stderr, "open %s error: %s\n", filename, strerror(errno));
        return -1;
    }
    int length = 0;
    while(length < len) {
        int n = fwrite(data, sizeof(char), len - length, fp);
        length += n;
    }
    // fseek(fp, 0L, SEEK_SET);
    fclose(fp);
    fprintf(stdout, "write %s finished\n", filename);
    return 1;
}


void sendFileToServer(SSL * clientSSL,char * filename){
    puts("now sending file to server");
    char file[2000];
    bzero(file, 2000);
    
    readFile(filename, file);
    
    //send it to the server
    int sendFile = SSL_write(clientSSL, file, 2000);
    if(sendFile !=2000) {
        ERR_print_errors_fp(stderr);
    }
    
    puts("\nsending file is over\n");
}


void receiveFileFromServer(SSL * clientSSL, char * filename){
    puts("\nrevieving file from server now\n");
    char file[2000];
    bzero(file, 2000);
    int recievedFile = SSL_read(clientSSL, file, 2000);
    if(recievedFile != 2000) {
        ERR_print_errors_fp(stderr);
    }
    
    puts("\nrecieveing is over\nnow write to a new file\n");
    writeFile(filename, file, 2000);
    puts("writing is over");
    
}



int main(int argc, char **argv) {
    
    
    if (argc!=5) {
        puts("you neet 5 argc");
        return 0;
    }
    
    
    char *host = argv[1];
    char *port = argv[2];
    char *opt  = argv[3];
    char *file = argv[4];
    
    host = strchr(host, '=') + 1; //may be wrong
    port = strchr(port, '=') + 1;
    
    
    //using PRNG to generate an challenge
    puts( "generating a random integer ");
    int randomInteger,seedBuff;
    RAND_seed((char*)&seedBuff,4);
    if (!RAND_bytes((unsigned char*)&randomInteger,4)) { //int has 4 bits
        puts("error when generating radom integer");
        return -1;
    }
    printf("\n\nrand is %d\n",randomInteger);
    puts("generating a random interger is over" );
    
    //client read publickey and store it in publickey[1000]
    char publickeyName[20]="pubkey.pem",publickey[1000];
    puts("inputting publickey now");
    readFile(publickeyName, publickey);
    //printf("publickey is %s\n",publickey);
    puts("reading publickey is over");
    
    
    
    puts("now starting encrpting the challenge");
    //encrypting the challenge, using RSA_public_encrypt
    //1.set up rsa
    RSA *rsa = NULL;
    BIO *bioEncrypt;
    if(!(bioEncrypt = BIO_new_mem_buf(publickey, -1))) {
        puts("Error setting up bio\n");
        return -1;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(bioEncrypt, &rsa, NULL, NULL);
    if(rsa == NULL) {
        puts("Error setting up rsa\n");
        return -1;
    }
    
    
    //2.allocating space for to
    int rasSize = RSA_size(rsa);
    //unsigned char encrpytedChallenge[RSA_size(rsa)+1];
    unsigned char encrpytedChallenge[rasSize+1];
    puts("\nRSA_size is: ");
    printf("%d\n", rasSize);
    int sizeOfEncrpytedChallenge = RSA_public_encrypt(4,(unsigned char*)&randomInteger,encrpytedChallenge,rsa,RSA_PKCS1_OAEP_PADDING);
    if (sizeOfEncrpytedChallenge==-1) {
        puts("encrpytion error when using RSA_public_encrypt");
        // printf("%lu\n", ERR_get_error());
        printf("\n\n%s\n",ERR_error_string(ERR_get_error(),NULL));
        return 0;
    }
    puts("the size of encrptyted data is ");
    encrpytedChallenge[256]='\0';
    printf(":    %d\n\n",sizeOfEncrpytedChallenge);
    printf("the encrpyted data is:\n%s\n\n",encrpytedChallenge);
    
    puts("\nNow set up connection with the server\n");
    
    connect();
    //set up connection with the server
    puts ("initialize ssl");
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    
    puts("\ncreate a new SSL_CTX object as framework to establish TLS/SSL enabled connections\n");
    SSL_CTX *clientSSL_CTX = SSL_CTX_new(SSLv23_client_method());
    if(!clientSSL_CTX) {
        printf("The creation of a new SSL_CTX object failed\n");
        return -1;
    }
    
    puts("\nset a ciper suite that suports the Anonymous Diffie-Hellman key exchange protocol\n");
    SSL_CTX_set_cipher_list(clientSSL_CTX, "EXP-ADH-RC4-MD5");
    
    puts("\ncreates a new SSL structure which is needed to hold the data for a TLS/SSL connection.\n");
    SSL *clientSSL = SSL_new(clientSSL_CTX);
    if(!clientSSL) {
        printf("creating a new SSL structure for a connection failed\n");
        return -1;
    }
    
    printf("\ncreate a new accept BIO with port host_port.\n");
    BIO *bio = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(bio, host);
    BIO_set_conn_port(bio, port);
    
    printf("\nattempt to connect the supplied BIO\n");
    if(BIO_do_connect(bio) <= 0) {
        printf("unable to connect \n");
        return -1;
    }
    
    printf("\nconnects the BIOs rbio and wbio for the read and write operations of the TLS/SSL (encrypted) side of ssl.\n");
    SSL_set_bio(clientSSL, bio, bio);
    
    printf("\ninitiates the TLS/SSL handshake with a server\n");
    int handshake = SSL_connect(clientSSL);
    
    printf("\nwrites num bytes from the buffer buf into the specified ssl connection.\n");
    int sendDataLength = SSL_write(clientSSL, (unsigned char*)& rasSize, 4);
    if(sendDataLength != 4) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("\nwrites num bytes from the buffer buf into the specified ssl connection.\n");
    int sendEncryption = SSL_write(clientSSL, encrpytedChallenge, rasSize);
    if(sendEncryption !=rasSize) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    printf("\nrecieve the encypted chanllege from client\n");
    printf("\nrecieve the incoming data length\n");
    char dataLength[4];//recieve the incoming data length
    bzero(dataLength,4);
    int recievedDataLength = SSL_read(clientSSL, dataLength, 4);
    if(recievedDataLength != 4) {
        ERR_print_errors_fp(stderr);
    }
    int len=0;
    len = *((int *)dataLength);
    if (len==0) {
        printf("there is an error when recieving the length of oncoming data");
        return -2;
    }
    printf("\nrecieve the coming data length is over: len is %d\n", len);
    printf("\nrecieve the coming encyption data length\n");
    
    char dataRecieved[len+1];// recieve the encyption
    bzero(dataRecieved,len);
    int recievedEncryption = SSL_read(clientSSL, dataRecieved, len);
    if (recievedEncryption != len) {
        ERR_print_errors_fp(stderr);
        printf("there is an error when recieving encryption");
        return -2;
    }
    dataRecieved[len]='\0';
    printf("recieved encryption is: \n%s\n", dataRecieved);
    
    
    //decrypt the signed data
    puts("\nnow decrypting the recieved data");
    unsigned char decryptedHashedChallenge[20+1];
    
    int sizeOfDecryptedHashedChallenge = RSA_public_decrypt(len,(unsigned char *)dataRecieved,decryptedHashedChallenge,rsa,RSA_PKCS1_PADDING);
    
    if (sizeOfDecryptedHashedChallenge==-1) {
        puts("Decrpytion error when using RSA_public_decrypt");
        printf("%lu\n", ERR_get_error());
        return 0;
    }
    puts("the size of dncrptyted data is ");
    decryptedHashedChallenge[20]='\0';
    printf(":    %d\n\n",sizeOfDecryptedHashedChallenge);
    printf("\n now hash the challenge\n");
    unsigned char hashedChallenge[20+1];
    bzero(hashedChallenge, 21);
    unsigned char *hash = SHA1((unsigned char*)&randomInteger, 4, hashedChallenge);
    hashedChallenge[20]='\0';
    puts("\nhashing challenge is over\n");
    // printf("\nthe hashed challenge is: %s \n",hashedChallenge);
    
    
    
    
    int compare = strncmp(hashedChallenge, decryptedHashedChallenge,20);
    if (compare == 0) {
        printf("\n successful authentication\n");
    }
    else{
        printf("\nunsuccessful authentication\n");
        return -1;
    }
    
    
    puts("\nnow start to send or retrive files\n");
    int choice = SSL_write(clientSSL, opt, strlen(opt));
    if( choice < 0) {
        ERR_print_errors_fp(stderr);
    }
    //    char fileRecieved[100];
    //    bzero(fileRecieved, 100);
    if(strstr(opt, "send")) {
        sendFileToServer(clientSSL, file);
    }
    else
        if(strstr(opt, "receive")) {
            int f = SSL_write(clientSSL, file, strlen(file));
            if( f < 0) {
                ERR_print_errors_fp(stderr);
            }
            receiveFileFromServer(clientSSL, file);
            
        }
        else {
            printf("\nsomething went wrong\n");
        }
    
    
    SSL_shutdown(clientSSL);
    return 0;
}
