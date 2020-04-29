//
// Created by klego on 7/03/19.
//

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <err.h>

enum {
    SIGNATURE_DATA = 512,
    SIZE = 1000,
    PADSIZE = 448,
    ID_SIZE = 19,
    PS_SIZE = 426,
};

char cadena_depuracion[2] = "-d";
char cadena_verificacion[2] = "-v";
unsigned char EMSASHA512ID[] = {0x30, 0x51, 0x30, 0x0d,
                                0x06, 0x09, 0x60, 0x86,
                                0x48, 0x01, 0x65, 0x03,
                                0x04, 0x02, 0x03, 0x05,
                                0x00, 0x04, 0x40};


void Padding(unsigned char* digest, unsigned char* recipiente){
    unsigned char* ps = NULL;
    ps = (unsigned char*)malloc(PS_SIZE*sizeof(unsigned char));
    memset(ps, 0xFF, PS_SIZE);
    memset(&recipiente[0], 0x00, 1);
    memset(&recipiente[1], 0x01, 1);
    memcpy(&recipiente[2], ps, PS_SIZE);
    memset(&recipiente[428], 0x00, 1);
    memcpy(&recipiente[429], EMSASHA512ID, ID_SIZE);
    memcpy(&recipiente[448], digest, SHA512_DIGEST_LENGTH);
    free(ps);

}

void SHA_512(char* nombre_fichero, unsigned char* digest, int depuracion){
    char* texto = NULL;
    int long_texto = 1;
    int fichero;

    texto = (char*)malloc(SIZE * sizeof(char));
    SHA512_CTX ctx;

    if(SHA512_Init(&ctx) == 1){
        fichero = open(nombre_fichero, O_RDONLY);
        if(fichero < 0){
            free(texto);
            err(1, "Error al abrir fichero %s\n", nombre_fichero);
        }
        while(long_texto != 0){
            long_texto = read(fichero, texto, SIZE);
            if(long_texto != -1){
                if(SHA512_Update(&ctx, texto, long_texto) == 0){
                    if(depuracion == 1){
                        free(texto);
                        close(fichero);
                        err(1, "Error en SHA512_Update\n");
                    }
                    else{
                        free(texto);
                        close(fichero);
                        exit(1);
                    }
                }
            }
            else{
                if(depuracion == 1){
                    free(texto);
                    close(fichero);
                    err(1, "Error en lectura de fichero\n");
                }
                else{
                    free(texto);
                    close(fichero);
                    exit(1);
                }
            }
        }

        if(SHA512_Update(&ctx, nombre_fichero, strlen(nombre_fichero)) == 0){
            if(depuracion == 1){
                free(texto);
                close(fichero);
                err(1, "Error en SHA512_Update\n");
            }
            else{
                free(texto);
                close(fichero);
                exit(1);
            }

        }

        if(SHA512_Final(digest, &ctx) == 0){
            if(depuracion == 1){
                free(texto);
                close(fichero);
                err(1, "Error en SHA512_Final\n");
            }
            else{
                free(texto);
                close(fichero);
                exit(1);
            }

        }
        free(texto);
        close(fichero);
    }

    else{
        if(depuracion == 1){
            free(texto);
            err(1, "Error en SHA512_Init\n");
        }
        else{
            free(texto);
            exit(1);
        }
    }
}

void Write_Base64(unsigned char* recipiente_cripto, int depuracion){
    BIO* bio;
    BIO* b64;

    int nr=0;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);

    write(1, "---BEGIN SRO SIGNATURE---\n", strlen("---BEGIN SRO SIGNATURE---\n"));

    nr=BIO_write(b64, recipiente_cripto, SIGNATURE_DATA);
    if(nr < 0){
        if(depuracion == 1){
            err(1, "BIO_write eror\n");
        }
        else{
            exit(1);
        }
    }
    BIO_flush(b64);
    BIO_free_all(b64);
    write(1, "---END SRO SIGNATURE---\n", strlen("---END SRO SIGNATURE---\n"));
}

int Comprueba_Hash(unsigned char* digest, unsigned char* firma_digest){
    int flag = 0;
    if(memcmp(digest, firma_digest, SHA512_DIGEST_LENGTH) != 0){
        flag = 1;
    }
    return flag;
}

int Comprueba_Padding(unsigned char* recipiente, unsigned char* firma_digest){
    unsigned char pad [PADSIZE];
    unsigned char ps [PS_SIZE];
    int flag = 0;
    int aux = 0;


    memcpy(&firma_digest[0], &recipiente[SIGNATURE_DATA-SHA512_DIGEST_LENGTH], SHA512_DIGEST_LENGTH);
    memset(ps, 0xFF, PS_SIZE);
    memset(&pad[0], 0x00, 1);
    memset(&pad[1], 0x01, 1);
    memcpy(&pad[2], ps, PS_SIZE);
    memset(&pad[428], 0x00, 1);
    memcpy(&pad[429], EMSASHA512ID, ID_SIZE);
    aux = memcmp(pad, recipiente, PADSIZE);
    if (aux != 0){
        flag = 1;
    }
    return flag;
}


void Descifrar (char* clave_publica, unsigned char* recipiente, unsigned char* recipiente_cripto, int depuracion){
    FILE* fichero = NULL;
    RSA* rsa = RSA_new();
    int long_clave_publica = 0;

    fichero = fopen(clave_publica, "r");
    if (fichero == NULL){
        err(1, "Error abriendo la clave publica %s\n", clave_publica);
    }
    rsa = PEM_read_RSA_PUBKEY(fichero, NULL, NULL, NULL);
    if (rsa == NULL && depuracion  == 1){
        if(depuracion == 1){
            fclose(fichero);
            err(1, "Error leyendo la clave publica %s\n", clave_publica);
        }
        else{
            fclose(fichero);
            exit(1);
        }
    }
    long_clave_publica = RSA_public_decrypt(SIGNATURE_DATA, recipiente_cripto, recipiente, rsa, RSA_NO_PADDING);
    if(long_clave_publica == -1){
        if(depuracion == 1){
            fclose(fichero);
            err(1, "Error al descifrar\n");
        }
        else{
            fclose(fichero);
            exit(1);
        }
    }
    fclose(fichero);
    RSA_free(rsa);
}

void Cifrar (char* clave_privada, unsigned char* recipiente, unsigned char* recipiente_cripto, int depuracion){
    FILE* fichero = NULL;
    RSA* rsa=RSA_new();
    int long_firma = 0;
    fichero = fopen(clave_privada, "r");
    if(fichero == NULL){
        err(1, "Error abriendo el fichero de clave privada %s\n", clave_privada);
    }
    rsa = PEM_read_RSAPrivateKey(fichero, NULL, NULL, NULL);
    if(rsa == NULL){
        if(depuracion == 1){
            fclose(fichero);
            err(1, "Error leyendo la clave privada %s\n", clave_privada);
        }
        else{
            fclose(fichero);
            exit(1);
        }
    }
    long_firma = RSA_private_encrypt(SIGNATURE_DATA, recipiente, recipiente_cripto, rsa, RSA_NO_PADDING);
    if(long_firma == -1){
        if(depuracion==1){
            fclose(fichero);
            err(1, "Error al cifrar\n");
        }
        else{
            fclose(fichero);
            exit(1);
        }
    }
    fclose(fichero);
    RSA_free(rsa);
}

void Read_Base64(char* firma, unsigned char* recipiente_crypto, int depuracion){
    BIO* bio;
    BIO* b64;
    FILE* fichero;

    int nr = 0;
    fichero = fopen(firma, "r");
    if(fichero == NULL ){
        err(1, "Error al abrir fichero %s\n", firma);
    }
    b64 = BIO_new(BIO_f_base64());
    bio=BIO_new_fp(fichero, BIO_NOCLOSE);
    BIO_push(b64, bio);

    nr = BIO_read(b64, recipiente_crypto, SIGNATURE_DATA);
    if(nr<0){
        if(depuracion == 1){
            fclose(fichero);
            err(1, "Error en BIO_read\n");
        }
        else{
            fclose(fichero);
            exit(1);
        }
    }
    fclose(fichero);
    BIO_free(b64);
}

void Firmar(char* datos, char* clave_privada, int depuracion){
    unsigned char recipiente[SIGNATURE_DATA];
    unsigned char recipiente_cripto[SIGNATURE_DATA];
    unsigned char digest[SHA512_DIGEST_LENGTH];

    SHA_512(datos, digest, depuracion);
    Padding(digest, recipiente);
    Cifrar(clave_privada, recipiente, recipiente_cripto, depuracion);
    Write_Base64(recipiente_cripto, depuracion);
}

void Verifica(char* firma, char* datos, char* clave_publica, int depuracion){
    unsigned char recipiente[SIGNATURE_DATA];
    unsigned char recipiente_crypto[SIGNATURE_DATA];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned char firma_digest[SHA512_DIGEST_LENGTH];

    memset(recipiente, 0x00, SIGNATURE_DATA);
    memset(recipiente_crypto, 0x00, SIGNATURE_DATA);
    memset(digest, 0x00, SHA512_DIGEST_LENGTH);
    memset(firma_digest, 0x00, SHA512_DIGEST_LENGTH);

    Read_Base64(firma, recipiente_crypto, depuracion);
    Descifrar(clave_publica, recipiente, recipiente_crypto, depuracion);

    if(Comprueba_Padding(recipiente, firma_digest) != 0){
        if(depuracion == 1){
            err(1, "Padding Incorrecto\n");
        }
        else{
            err(1, "Firma incorrecta\n");
        }
    }
    SHA_512(datos, digest, depuracion);

    if(Comprueba_Hash(digest, firma_digest) !=0){
        err(1, "Firma incorrecta\n");
    }
}

int main(int argc, char* argv[]){
    int depuracion = 0;
    switch(argc){
        case 3:
            Firmar(argv[1], argv[2], depuracion);
            break;
        case 4:
            if(strncmp(argv[1], cadena_verificacion, 2) == 0 && strncmp(argv[2], cadena_depuracion, 2) == 0){
                depuracion = 1;
                Firmar(argv[3], argv[4], depuracion);
            }
            else{
                err(1, "Argumentos incorrectos.\n Uso: ./sign [OPCIONES] [FICHEROS]\n");
            }
            break;
        case 5:
            if(strncmp(argv[1], cadena_verificacion, 2) == 0){
                Verifica(argv[2], argv[3], argv[4], depuracion);
            }
            else{
                err(1, "Argumentos incorrectos.\n Uso: ./sign [OPCIONES] [FICHEROS]\n");
            }
            break;
        case 6:
            if(strncmp(argv[1], cadena_verificacion, 2) == 0 && strncmp(argv[2], cadena_depuracion, 2) == 0){
                depuracion = 1;
                Verifica(argv[3], argv[4], argv[5], depuracion);
            }
            else{
                err(1, "Argumentos incorrectos.\n Uso: ./sign [OPCIONES] [FICHEROS]\n");
            }
            break;
        default:
            err(1, "Error en el numero de argumentos");
    }
    return 0;
}
