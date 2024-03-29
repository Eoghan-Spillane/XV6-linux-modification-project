/*
    C socket server example, handles multiple clients using threads
*/
 
#include <stdio.h>
#include <string.h>    //strlen
#include <sys/ioctl.h>
#include <stdlib.h>    //strlen
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>    //write
#include <pthread.h> //for threading , link with lpthread
#include <errno.h>
#include "server.h"

#define min(a, b) ((a) < (b) ? (a) : (b))


size_t rio_writen(int fd, const char *usrbuf, size_t n) {
    size_t nleft = n;
    ssize_t nwritten;
    const char *bufp = usrbuf;

    while (nleft > 0) {
        if ((nwritten = write(fd, bufp, nleft)) <= 0) {
            return 0;
        }
        nleft -= nwritten;
        bufp += nwritten;
    }

    return n;
}

int parse_request(const char *req_str, request_t *req_info) {
    if (sscanf(req_str, "%s %s %[^\r\n]", req_info->method, req_info->uri, req_info->version) != 3) {
        fprintf(stderr, "malformed http request\n");
        return -1;
    }

    printf("method %s uri %s\n",req_info->method, req_info->uri);
}

void send_response(int connfd, status_t status, const char *content, size_t content_length, int type) {
    char buf[512];

    if (status == NF) {
        sprintf(buf, "HTTP/1.0 404 Not Found\r\n");
    } else if (status == OK) {
        sprintf(buf, "HTTP/1.0 200 OK\r\n");
    } else {
        sprintf(buf, "HTTP/1.0 500 Internal Servere Error\r\n");
    }

    sprintf(buf, "%sContent-Length: %lu\r\n", buf, content_length);

    //Content Type
    if(!type){
        sprintf(buf, "%sContent-Type: %s\r\n\r\n", buf, "text/html; charset=utf-8");
    }
    else{
        sprintf(buf, "%sContent-Type: %s\r\n\r\n", buf, "text/text; charset=utf-8");
    }
   
    size_t buf_len = strlen(buf);
    if (rio_writen(connfd, buf, buf_len) < buf_len) {
        fprintf(stderr, "error while sending response\n");
        return;
    }
    if (rio_writen(connfd, content, content_length) < content_length) {
        fprintf(stderr, "error while sending response\n");
    }
}

//the thread function
void *connection_handler(void *);
int oldstate;

int main(int argc , char *argv[])
{
    int socket_desc , client_sock ,rc, c , *new_sock;
    struct sockaddr_in server , client;
    int on=1;
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
    puts("Socket created");
        /*************************************************************/
    /* Allow socket descriptor to be reuseable                   */
    /*************************************************************/
    rc = setsockopt( socket_desc, SOL_SOCKET,  SO_REUSEADDR,
                    (char *)&on, sizeof(on));
    if (rc < 0)
    {
        perror("setsockopt() failed");
        close(socket_desc);
        exit(-1);
    }

    /*************************************************************/
    /* Set socket to be nonblocking. All of the sockets for    */
    /* the incoming connections will also be nonblocking since  */
    /* they will inherit that state from the listening socket.   */
    /*************************************************************/
    rc = ioctl( socket_desc, FIONBIO, (char *)&on);
    if (rc < 0)
    {
        perror("ioctl() failed");
        close(socket_desc);
        exit(-1);
    }

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 3000 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        //print the error message
        perror("bind failed. Error");
        return 1;
    }
    puts("bind done");
     
    //Listen
    listen(socket_desc , 3);
     
    //Accept incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);
     
     
    //Accept and incoming connection
    puts("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);


    int first=1;
    while(1 ){
    //printf("here S=%ld Input =%ld oldInput =%ld",S,Input,oldInput);
        if ((client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))>=0) {
            puts("Connection accepted");
            
            pthread_t sniffer_thread;
            new_sock = malloc(sizeof(int));
            *new_sock = client_sock;
            
            if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_sock) < 0){
                perror("could not create thread");
                return 1;
            }
            
            //Now join the thread , so that we dont terminate before the thread
            //pthread_join( sniffer_thread , NULL);
            puts("Handler assigned");
        }
    }
    
    if (client_sock < 0)
    {
        perror("accept failed");
        return 1;
    }
     
    return 0;
}

void *connection_handler(void *socket_desc){
    //Get the socket descriptor
    int sock = *(int*)socket_desc;
    int sz;
    char message[2000];
    char data[2000];
    FILE *file;

    //Receive a message from client
    while( (sz = recv(sock , data , 2000 , 0)) > 0 ){

        if ( sz >= 4 && data[sz - 1] == '\n' && data[sz - 2] == '\r' && data[sz - 3] == '\n' && data[sz - 4] == '\r' ){ 
            request_t req_info;
            if (parse_request(data, &req_info) < 0) {
                //error
                send_response(sock, ISE, content_500, strlen(content_500), 1);
                break;
            }
            else{
                // Parse & get directory
                char actPath[4000];
                char *cwd = getcwd(NULL,0);
                strcpy(actPath, cwd);
                strcat(actPath, req_info.uri);
                free(cwd);

                //Get File
                file = fopen(actPath, "r");
                if (file){
                    fseek(file, 0L, SEEK_END);
                    __off_t file_size = ftell(file);
                    fseek(file, 0L, SEEK_SET);

                    //Get Contents of file 
                    strcpy(message, "\n\n");                   
                    fread(message, file_size+1, 1, file);
                    fclose(file);
                    strcat(message, "\n\n");

                    //Get content type and send response
                    if(*actPath && actPath[strlen(actPath + 1)] == 'l'){
                        send_response(sock, OK, message, strlen(message), 0);
                    }
                    else{
                        send_response(sock, OK, message, strlen(message), 1); 
                    }
                      
                }
                else{ // File not found
                    printf("File Does not exist\n");
                    send_response(sock, NF, content_404, strlen(content_404), 1);
                }
            }
        }
    }
     
    if(sz == 0){
        puts("Client disconnected");
        fflush(stdout);
    }
    else if(sz == -1){
        perror("recv failed");
    }
         
    //Free the socket pointer
    free(socket_desc);
     
    return 0;
}
