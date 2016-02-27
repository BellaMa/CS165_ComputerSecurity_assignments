#include <stdlib.h>
#include "string.h"
#include "stdio.h"
#include "openssl/ssl.h"
#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include <sys/errno.h>


int readFile(char *filename, char *data) {
    FILE *fp;
    if ((fp = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "open %s error: %s\n", filename, strerror(errno));
        return -1;
    }
    int n  = fread(data, 1 ,2000, fp);
    fprintf(stdout, "\nread %s finished\n", filename);
    
    data[n]='\0';
    printf("\nfile is %s \n",data);
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
    fclose(fp);
    fprintf(stdout, "write %s finished\n", filename);
    return 1;
}

void  receiveFileFromeClient(SSL * serverSSL){
    
    char file[2000];
    bzero(file, 2000);
    puts("\nnow recieving file from client\n");
    char filename[]="recievedFromClient.txt";
    int recievedFile = SSL_read(serverSSL, file, 2000);
    if(recievedFile != 2000) {
        ERR_print_errors_fp(stderr);
    }
    puts("\nrecieving is over\nnow wrting to a new file\n");
    writeFile(filename, file, 2000);
    puts("\nwriting is over\n");
}



void sendFileToClient(SSL * serverSSL, char * filename){
    
    char file[2000];
    int len =  readFile(filename, file);
    
    puts("\nnow sending file to server\n");
    //send it to the server
    int sendFile = SSL_write(serverSSL, file, len);
    if(sendFile !=len) {
        ERR_print_errors_fp(stderr);
    }
    puts("\nsending is over");
}



int main(int argc, char **argv) {
    
    
    if (argc!=2) {
        puts("you need 2 argcs");
        return 0;
    }
    
    char *port = argv[1];
    
    port = strchr(port, '=') + 1;
    /* read in private key
     need to read in private key at the beginning
     if reading fails, no damage done
     if reads later, the client may have connected to the server,
     and if reading fails, the connecton needs to be cut off as well
     */
    char privatekeyName[20]="privkey.pem",privatekey[3000];
    puts("reading in private key now");
    readFile(privatekeyName, privatekey);
    //printf("private key is %s\n",privatekey);
    puts("reading private key is over");
    
    printf("\ninitialize ssl\n");
    SSL_load_error_strings();
    puts("1");
    SSL_library_init();
    puts("2");
    //SSL_load_error_strings();
    puts("3");
    ERR_load_BIO_strings();
    puts("4");
    OpenSSL_add_all_algorithms();
    printf("\ninitialize ssl is over\n");
    
    
    printf("\ncreate a new SSL_CTX object as framework to establish TLS/SSL enabled connections\n");
    SSL_CTX *serverSSL_CTX = SSL_CTX_new(SSLv23_server_method());
    if(!serverSSL_CTX) {
        printf("The creation of a new SSL_CTX object failed\n");
        return -1;
    }
    
    printf("\nset a ciper suite that suports the Anonymous Diffie-Hellman key exchange protocol\n");
    DH *diffieHellman = DH_new();
    DH_generate_parameters_ex(diffieHellman, 256, 2, NULL);
    DH_generate_key(diffieHellman);
    SSL_CTX_set_cipher_list(serverSSL_CTX, "EXP-ADH-RC4-MD5");
    SSL_CTX_set_tmp_dh(serverSSL_CTX, diffieHellman);
    
    printf("\ncreates a new SSL structure which is needed to hold the data for a TLS/SSL connection.\n");
    SSL *serverSSL = SSL_new(serverSSL_CTX);
    if(!serverSSL) {
        printf("creating a new SSL structure for a connection failed\n");
        return -1;
    }
    
    printf("\ncreate a new accept BIO with port host_port.\n");
    /*BIO *bio = BIO_new(BIO_s_accept());;
     BIO_set_accept_port(bio, port);
     */
    BIO *bio = BIO_new_accept(port);
    
    printf("\n/*When it is first called, after the accept BIO has been setup, it will attempt to create the accept socket and bind an address to it. Second and subsequent calls to BIO_do_accept() will await an incoming connection, or request a retry in non blocking mode.");
    int acceptionBind;
    if((acceptionBind = BIO_do_accept(bio)) <= 0) {
        printf("Attemp to creat socket and bind an address failes %d \n", SSL_get_error(serverSSL, acceptionBind));
    } else {
        printf("Connection is successful\n");
    }



    printf("\nconnect the BIOs rbio and wbio for the read and write operations of the TLS/SSL\n");
    printf("\n(encrypted) side of ssl.\n");
    SSL_set_bio(serverSSL, bio, bio);
    
    
    printf("\nwait for a TLS/SSL client to initiate the TLS/SSL handshake\n");
    int waiting = SSL_accept(serverSSL);
    
    
    
    printf("\nrecieve the encypted chanllege from client\n");
    printf("\nrecieve the incoming data length\n");
    char dataLength[4];//recieve the incoming data length
    bzero(dataLength,4);
    int recievedDataLength = SSL_read(serverSSL, dataLength, 4);
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
    printf("\nrecieve the ncoming encyption data length\n");
    
    char dataRecieved[len+1];// recieve the encyption
    bzero(dataRecieved,len);
    int recievedEncryption = SSL_read(serverSSL, dataRecieved, len);
    if (recievedEncryption != len) {
        ERR_print_errors_fp(stderr);
        printf("there is an error when recieving encryption");
        return -2;
    }
    dataRecieved[len]='\0';
    printf("recieved encryption is: \n%s\n", dataRecieved);
    
    //now decrypt the recieved data
    //set up rsa data strucuter
    printf("\nnow set up rsa \n");
    RSA *rsa = NULL;
    BIO *bioDecrypt;
    if(!(bioDecrypt = BIO_new_mem_buf(privatekey, -1))) {
        puts("Error setting up bio\n");
    }
    rsa = PEM_read_bio_RSAPrivateKey(bioDecrypt, &rsa, NULL, NULL);
    if(rsa == NULL) {
        puts("Error setting up rsa\n");
    }
    puts("now starting decryption");




    int rsaSize = RSA_size(rsa);
    unsigned char decryptedChallenge[len + 1];
    int sizeOfDecrpytedChallenge = RSA_private_decrypt(len,(unsigned char*)&dataRecieved,decryptedChallenge,rsa,RSA_PKCS1_OAEP_PADDING);
    if (sizeOfDecrpytedChallenge==-1) {
        puts("Decrpytion error when using RSA_public_encrypt");
        printf("%lu\n", ERR_get_error());
        printf("\n\n%s\n",ERR_error_string(ERR_get_error(),NULL));
        return 0;
    }
    puts("the size of dncrptyted data is ");
    decryptedChallenge[len]='\0';
    printf(":    %d\n\n",sizeOfDecrpytedChallenge);
    // printf("the decrpyted data is:\n%s\n\n",decrpytedChallenge);
    // int challenge = atoi(decrpytedChallenge);
    printf("the decrpyted data is:\n%d\n\n",*(int *)decryptedChallenge);
    //   printf("the decrpyted data is:\n%d\n\n",challenge);
    
    
    
    
    //hash the decrypted challenge
    printf("\n now hash the decrypyed challenge\n");
    unsigned char hashedDecryption[20];
    bzero(hashedDecryption, 20);
    unsigned char *hash = SHA1(decryptedChallenge, 4, hashedDecryption);
    


    //sign the hashed chllenge by using private key
    //which means use the private key to encrypt the data
    unsigned char encryptedHashedDecryption[rsaSize+1];
    bzero(encryptedHashedDecryption, rsaSize+1);
    
    int sizeOfEncryptedHashedDecryption = RSA_private_encrypt(20, hashedDecryption, encryptedHashedDecryption, rsa, RSA_PKCS1_PADDING);
    if(sizeOfEncryptedHashedDecryption == -1) {
        printf("\nencrypting the hashed data went wrong\n");
        ERR_print_errors_fp(stderr);
    }
    puts("the size of encrptyted data is ");
    hashedDecryption[rsaSize]='\0';
    printf(":    %d\n\n",sizeOfEncryptedHashedDecryption);
    printf("the encrpyted data is:\n%s\n\n",encryptedHashedDecryption);
    
    //now send the encryptedHashedDecryption to client
    puts("\nnow send the encryptedHashedDecryption to client\n");
    int sendDataLength = SSL_write(serverSSL, (unsigned char*)& rsaSize, 4);
    if(sendDataLength != 4) {
        ERR_print_errors_fp(stderr);
    }
    printf("\nwrites num bytes from the buffer buf into the specified ssl connection.\n");
    int sendEncryption = SSL_write(serverSSL, encryptedHashedDecryption, rsaSize);
    if(sendEncryption !=rsaSize) {
        ERR_print_errors_fp(stderr);
    }



    
    char opt[100];
    int choice = SSL_read(serverSSL, opt, 100);
    if (choice < 0) {
        ERR_print_errors_fp(stderr);
        return -2;
    }
    
    char fileSent[100];
    bzero(fileSent, 100);
    
    if(strstr(opt, "send")) {
        receiveFileFromeClient(serverSSL);
    }
    else
        if(strstr(opt, "receive")) {
            int f = SSL_read(serverSSL, fileSent, 100);
            if (f < 0) {
                ERR_print_errors_fp(stderr);
                return -2;
            }
            sendFileToClient(serverSSL,fileSent);
        }
        else {
            SSL_shutdown(serverSSL);
            return 0;
        }
    
    
    /* shutdown ssl and free bio */
    SSL_shutdown(serverSSL);
    return 0;
    
    
    
    
    
    
}

