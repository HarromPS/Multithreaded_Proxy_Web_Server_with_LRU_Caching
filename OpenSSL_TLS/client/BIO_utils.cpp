#include "./BIO_Utils.hpp"

namespace bio
{   
    // creating and connecting tcp socket
    // creates a TCP socket connection to a remote server using OpenSSL's BIO (Basic I/O) abstraction.
    BIO *create_socket_bio(const char *hostname, const char *port, int family)
    {
        BIO_ADDRINFO *res = NULL;               // stores BIO address information

        // IP address lookup info for the server using hostname and port
        if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_STREAM, 0, &res))
            return NULL;

        int sock = -1;
        const BIO_ADDRINFO *ai = NULL;
        
        // trying for each IP address and creating socket for each 
        // loops through all possible IP addresses from DNS results, tries each one until successful connection
        // e.g for google.com tries all its possible ip address and try to connects
        for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai))
        {
            sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);  // creates a raw tcp socket 
            if (sock == -1)
                continue;

            /* Connect the socket to the server's address */    
            if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY))     // attempts connection, disabled nagles connection
            {
                ERR_print_errors_fp(stderr);
                BIO_closesocket(sock);
                sock = -1;
                continue;
            }

            /* We have a connected socket so break out of the loop */
            break;
        }

        BIO_ADDRINFO_free(res);
        
        // if no connection is made it returns null
        if (sock == -1)
            return NULL;

        /* Create a BIO object to wrap the socket */
        BIO *bio = BIO_new(BIO_s_socket());             // wraps in bio
        if (bio == NULL)
        {   
            ERR_print_errors_fp(stderr);        // error on memory allocation
            BIO_closesocket(sock);
            return NULL;
        }

        // BIO_CLOSE ensures the socket will be automatically closed when the BIO is freed
        // attach socket in bio
        BIO_set_fd(bio, sock, BIO_CLOSE);   // free bio and close connection

        return bio;
    }

} // namespace bio