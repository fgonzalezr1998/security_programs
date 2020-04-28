-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

PRACTICA DE SEGURIDAD EN REDES DE ORDENADORES.

USO DE GPG Y COMANDOS DE OPENSSL

Esta práctica consiste en aprender a utilizar GPG y los comandos de
OpenSSL para cifrar y descifrar ficheros, y gestionar las claves
públicas del resto de usuarios.

ENTREGA: el usuario debe responder a las preguntas en este mismo
fichero, en el hueco indicado. Las respuestas deben estar escritas en
texto plano UTF-8 **CORRECTAMENTE FORMATEADO** , respondiendo a las
preguntas, resumiendo los pasos que ha tenido que seguir para realizar
cada apartado de la práctica y especificando los comandos que ha
ejecutado. SE DEBEN ESPECIFICAR TODOS LOS COMANDOS PARA REALIZAR CADA
PARTE DE CADA APARTADO DEL ENUNCIADO, COPIANDO EL TEXTO DEL TERMINAL
(TANTO COMANDO COMO SALIDA, SIEMPRE QUE NO SEA MUY LARGA LA SALIDA).

Entregue la memoria como indica el último apartado del enunciado.


1. Cree su par de claves GPG, eligiendo como algoritmo RSA de 4096
bit. Elija una passphrase segura.

COMANDO:
====================================================

$ gpg --gen-key

====================================================

2. Descargue la clave pública del profesor y guárdela en
su anillo de claves. Puede descargar la clave del profesor Enrique Soriano
de:

	http://gsyc.urjc.es/~/esoriano

También se puede conseguir de los servidor de claves GPG de
RedIris (pgp.rediris.es) y MIT (pgp.mit.edu).

Compruebe que en ambos sitios la clave pública de Enrique
Soriano es la misma.

COMANDOS:
====================================================
-- Descargar la clave --
$ wget https://gsyc.urjc.es/esoriano/publickey.asc

-- cambiar nombre --
$ mv publickey.asc sorianopubkey.asc

-- importar la clave --
$ gpg --import sorianopubkey.asc
====================================================

3. ¿Puede estar seguro de que esas claves descargadas son auténticas y
pertenecen a Enrique Soriano? ¿Por qué?

RESPUESTA:
====================================================

-- Listo los fingerprint de todas las claves importadas --
$ gpg --fingerprint

Veo que el fingerprint coincide con el que nos dio Enrique Soriano Salvador
por un canal seguro (en persona).

====================================================

4. Compruebe la autenticidad de la clave del profesor Enrique Soriano
comprobando su  fingerprint con el que ha dado el profesor en
persona.

COMANDOS:
====================================================
$ gpg --fingerprint
->output:
    pub   rsa4096 2012-11-14 [SCEA] [expires: 2020-11-15]
      29C5 32C0 EE85 7DCE 384E  3627 2693 0ACA F90A 5363
    uid           [ unknown] Enrique Soriano-Salvador <enrique.soriano@urjc.es>
    uid           [ unknown] Enrique Soriano-Salvador <enrique.soriano@gmail.com>
    sub   rsa4096 2012-11-14 [SEA] [expires: 2020-11-15]
->end output;

El fingerprint es: 29C5 32C0 EE85 7DCE 384E  3627 2693 0ACA F90A 5363
====================================================

4. ¿Puede estar seguro de que la clave descargada es auténtica
y pertenece al profesor?

RESPUESTA:
====================================================
Puedo estar seguro porque el fingerprint coincide con el que el profesor
nos proporcionó.
====================================================

5. Si es así, firme la clave del profesor y suba la firma al servidor
de Rediris.

COMANDOS:
====================================================
$ gpg --edit-key enrique.soriano@urjc.es
    gpg>sign
    Really sign all text user IDs? (y/N) y

    pub  rsa4096/26930ACAF90A5363
         created: 2012-11-14  expires: 2020-11-15  usage: SCEA
         trust: unknown       validity: unknown
     Primary key fingerprint: 29C5 32C0 EE85 7DCE 384E  3627 2693 0ACA F90A 5363

         Enrique Soriano-Salvador <enrique.soriano@urjc.es>
         Enrique Soriano-Salvador <enrique.soriano@gmail.com>

    This key is due to expire on 2020-11-15.
    Are you sure that you want to sign this key with your
    key "fgonzalezr1998 <fergonzaramos@yahoo.es>" (87472BC50001A2F2)

    Really sign? (y/N) y

-- Subo la firma al servidor de rediris --
$ gpg --keyserver pgp.rediris.es --send-keys F90A5363
====================================================

6. Comparta su clave pública con otras personas de la clase (por ejemplo
por correo electrónico). ¿Cómo exporta su clave pública? Resuma todos los
pasos para compartir su clave pública de forma segura:

COMANDO y RESPUESTA:
====================================================
-- Puedo compartir mi clave publica subiendola a un servidor de claves PGP --
$ gpg --keyserver pgp.rediris.es --send-keys 0001A2F2
====================================================

7. Añada las claves de dos compañeros en su anillo. Asigne a cada compañero
el nivel de confianza que desee.

COMANDOS:
====================================================
$ gpg --keyserver 130.206.1.8 --recv-key 056BAC2C
$ gpg --edit-key miguelalamilloreguero@gmail.com

gpg (GnuPG) 2.2.4; Copyright (C) 2017 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


pub  rsa4096/9A65BFB1056BAC2C
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: unknown       validity: unknown
sub  rsa4096/E4413146C2719569
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Miguel Alamillo Reguero <miguelalamilloreguero@gmail.com>
[ unknown] (2)  Miguel Alamillo Reguero <m.alamillo.2017@alumnos.urjc.es>

gpg> trust
pub  rsa4096/9A65BFB1056BAC2C
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: unknown       validity: unknown
sub  rsa4096/E4413146C2719569
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Miguel Alamillo Reguero <miguelalamilloreguero@gmail.com>
[ unknown] (2)  Miguel Alamillo Reguero <m.alamillo.2017@alumnos.urjc.es>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 4

pub  rsa4096/9A65BFB1056BAC2C
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: full          validity: unknown
sub  rsa4096/E4413146C2719569
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Miguel Alamillo Reguero <miguelalamilloreguero@gmail.com>
[ unknown] (2)  Miguel Alamillo Reguero <m.alamillo.2017@alumnos.urjc.es>
Please note that the shown key validity is not necessarily correct
unless you restart the program.

$ gpg --keyserver 18.9.60.141 --recv-key 02E5DCA1
$ gpg --edit-key luis.martinez.sanchez@gmail.com

gpg (GnuPG) 2.2.4; Copyright (C) 2017 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


pub  rsa4096/D74521B502E5DCA1
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: unknown       validity: unknown
sub  rsa4096/776729209A4938A8
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Luis Martinez Sanchez <luis.martinez.sanchez@gmail.com>

gpg> trust
pub  rsa4096/D74521B502E5DCA1
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: unknown       validity: unknown
sub  rsa4096/776729209A4938A8
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Luis Martinez Sanchez <luis.martinez.sanchez@gmail.com>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 4

pub  rsa4096/D74521B502E5DCA1
     created: 2020-02-07  expires: 2030-02-04  usage: SC
     trust: full          validity: unknown
sub  rsa4096/776729209A4938A8
     created: 2020-02-07  expires: 2030-02-04  usage: E
[ unknown] (1). Luis Martinez Sanchez <luis.martinez.sanchez@gmail.com>
Please note that the shown key validity is not necessarily correct
unless you restart the program.
====================================================


8. Compruebe la autenticidad y la integridad de las tres versiones
del enunciado que están disponibles (1, 2, 3). ¿Puede asegurar que
alguna de las versiones fue publicada por el profesor? ¿Cuál o cuáles?
¿Por qué?

COMANDO y RESPUESTA:
====================================================
$ gpg --verify 1-practica.txt.1.sig
->output:
    gpg: Signature made Fri 01 Feb 2019 09:40:56 AM CET
    gpg:                using RSA key C7DC3D54399FC39D290A61C9A8D6D9F50054BBA6
    gpg: BAD signature from "Enrique Soriano-Salvador <enrique.soriano@urjc.es>" [full]

$ gpg --verify 1-practica.txt.2.sig
->output:
    gpg: Signature made Fri 01 Feb 2019 09:40:56 AM CET
    gpg:                using RSA key C7DC3D54399FC39D290A61C9A8D6D9F50054BBA6
    gpg: Good signature from "Enrique Soriano-Salvador <enrique.soriano@urjc.es>" [full]
    gpg:                 aka "Enrique Soriano-Salvador <enrique.soriano@gmail.com>" [full]

$ gpg --verify 1-practica.txt.3.sig
->output:
    gpg: Signature made Fri 01 Feb 2019 09:40:56 AM CET
    gpg:                using RSA key C7DC3D54399FC39D290A61C9A8D6D9F50054BBA6
    gpg: BAD signature from "Enrique Soriano-Salvador <enrique.soriano@urjc.es>" [full]

->end output;

Sólo podemos asegurar la autenticidad y la integridad de "1-practica.txt.2.sig".

====================================================

9. Descargue del foro de la asignatura el fichero p1secret.gpg,
cifrado con una clave simétrica y descífrelo. El secreto para
descifrar el fichero se comunicará en clase. ¿Qué es?

COMANDOS Y RESPUESTA:
====================================================
-- Descifrar el fichero --
$ gpg --output p1secret --decrypt --ignore-mdc-error p1secret.gpg
->output:
    gpg: CAST5 encrypted data
    gpg: encrypted with 1 passphrase
    gpg: WARNING: message was not integrity protected

Se trata de una imagen con formato JPEG
====================================================

10. Descargue la firma del mensaje en claro, p1secret.sig.
¿Puede estar seguro de que el mensaje es integro (no ha sido
modificado por un atacante)? ¿Puede el profesor repudiar dicho
mensaje?

COMANDOS Y RESPUESTA:
====================================================
$ gpg --verify p1secret.sig
->output:
    gpg: assuming signed data in 'p1secret'
    gpg: Signature made Thu 05 Feb 2015 05:27:46 PM CET
    gpg:                using RSA key A8D6D9F50054BBA6
    gpg: Good signature from "Enrique Soriano-Salvador <enrique.soriano@urjc.es>" [full]
    gpg:                 aka "Enrique Soriano-Salvador <enrique.soriano@gmail.com>" [full]

No puede repudiar ya que se ha comprobado que el mensaje es íntegro, lo que garantiza
la NO alteración de los datos y fue firmado por él.
====================================================

11. Cifre esa misma imagen con el algoritmo de clave simétrica AES, con
una clave de 256 bits, usando el comando gpg.

COMANDO:
====================================================

$ gpg --output p1secretAES.gpg --symmetric --cipher-algo AES256 p1secret

====================================================

12. Haga lo mismo que en el apartado anterior usando el comando
openssl. Tiene que usar el modo CBC.

COMANDO:
====================================================
$openssl aes-256-cbc -in p1secret -out p1secretAES.ssl
->output:
    enter aes-256-cbc encryption password:
    Verifying - enter aes-256-cbc encryption password:
    *** WARNING : deprecated key derivation used.
    Using -iter or -pbkdf2 would be better.
====================================================

13. Calcule el resumen hash SHA-1 para los dos ficheros anteriores.
¿Coinciden? ¿Deberían coincidir? ¿Por qué?

COMANDO Y RESPUESTA:
====================================================
$ sha1sum p1secretAES.gpg
->output:
    243623bd3d9a180bc2e47168cfe71d8c6d3a0f7e  p1secretAES.gpg

$ sha1sum p1secretAES.ssl
->output:
    6c32ad2e190cf86837b4dbdcae6382cf011bcbdf  p1secretAES.ssl

Las hashes difieren porque ambos archivos están cifrados con algoritmos distintos.

Tambien puede usarse:
$ gpg --print-md SHA1 p1secretAES.gpg
->output:
    p1secretAES.gpg: 2436 23BD 3D9A 180B C2E4  7168 CFE7 1D8C 6D3A 0F7E
====================================================

14. Descifre ambos ficheros y compruebe que los datos descifrados son
exactamente los mismos que los originales.

COMANDOS:
====================================================

$ gpg --output p1secret_gpg_decrypted --decrypt p1secretAES.gpg

$ openssl aes-256-cbc -d -in p1secretAES.ssl -out p1secret_ssl_decrypted

Los archivos resultantes son exactamente iguales que los originales
====================================================

15. Genere un certificado X.509 en texto plano para la compañía ACME,
con correo electrónico pepe@acme.jp. La clave RSA tiene que ser de
4096 bits y el certificado debe ser válido por un año desde su
creación. Indique su número de serie:

COMANDOS:
====================================================
$ openssl req -new -nodes -x509 -newkey 4096 -out cert.pem  -keyout privkey.pem \
-days 365 -subj "/C=ES/ST=Madrid/L=Alcorcon/O=ACME\Company/OU=IT/CN=lsub.org/emailAddress=pepe@acme.jp"
->output:
    Can't load /home/fernando/.rnd into RNG
    140050958382912:error:2406F079:random number generator:RAND_load_file:Cannot open file:../crypto/rand/randfile.c:88:Filename=/home/fernando/.rnd
    Generating a RSA private key
    ............................................................................................................................................................................................................++++
    ..............................................++++
    writing new private key to 'privkey.pem'
    -----

$ openssl x509 -in cert.pem -text
->output:
    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number:
                69:be:29:5b:28:f2:71:ef:01:95:56:c9:71:e5:c5:e9:1c:b4:59:da
            Signature Algorithm: sha256WithRSAEncryption
            Issuer: C = ES, ST = Madrid, L = Alcorcon, O = ACMECompany, OU = IT, CN = lsub.org, emailAddress = pepe@acme.jp
            Validity
                Not Before: Apr 28 15:10:10 2020 GMT
                Not After : Apr 28 15:10:10 2021 GMT
            Subject: C = ES, ST = Madrid, L = Alcorcon, O = ACMECompany, OU = IT, CN = lsub.org, emailAddress = pepe@acme.jp
            Subject Public Key Info:
                Public Key Algorithm: rsaEncryption
                    RSA Public-Key: (4096 bit)
                    Modulus:
                        00:d2:39:e3:20:a4:9c:b8:d3:8c:9c:d8:fb:03:24:
                        55:0f:aa:31:33:b8:07:21:e1:d4:08:80:c2:ce:c1:
                        19:d2:0a:39:c0:0b:53:7a:a5:28:eb:31:9d:18:16:
                        ab:eb:55:64:d0:ff:ae:c5:1b:c8:c1:49:19:a5:df:
                        55:4c:de:f8:8a:da:a8:ea:49:71:d5:f4:61:9f:16:
                        c6:5d:ea:02:00:a2:ca:12:15:30:d4:39:aa:6c:49:
                        b2:8f:97:72:81:26:5b:81:25:72:9b:90:22:21:83:
                        2d:33:2b:25:e4:80:0e:1b:3a:0d:1f:21:b6:04:37:
                        6b:6e:07:14:2a:a0:0c:a3:55:14:22:8b:bf:8f:b9:
                        6d:84:18:b2:db:a7:6c:0e:d4:73:58:cd:ba:2f:a6:
                        6e:80:fb:39:56:d3:25:a3:36:ea:1c:67:d3:3b:c1:
                        5d:e1:d9:9c:d1:f9:fb:de:99:7b:81:d5:df:3d:02:
                        02:6c:43:0b:fd:ec:f5:71:53:17:cf:65:52:2f:10:
                        09:eb:20:a8:eb:cd:33:3e:02:3f:b6:22:c1:68:61:
                        4f:c0:d5:3c:5b:3b:4f:e8:25:3b:40:9a:13:6a:34:
                        f0:28:18:59:32:83:d3:e6:32:5a:9f:0b:33:54:1b:
                        ff:66:55:ba:e2:39:dc:9b:98:3f:f4:d3:38:fa:c0:
                        8d:d4:3a:b2:c5:64:52:85:a3:f6:1c:56:57:08:4e:
                        57:e1:f6:7f:bf:93:c7:fa:a7:06:6e:34:5e:8b:76:
                        98:d3:cd:be:19:8f:33:0e:2f:2a:d1:46:b8:c6:52:
                        da:0a:e6:e6:53:f1:fe:ed:4f:03:14:df:3b:d2:ca:
                        75:d9:02:d8:87:d8:f7:98:10:91:d9:76:12:2d:1e:
                        6e:f4:0d:d4:d6:39:fd:74:e4:a8:ae:eb:ad:46:ac:
                        72:7f:2a:48:c0:7a:2c:71:e1:3e:16:5e:e8:79:52:
                        b1:42:d9:67:18:c4:a7:92:90:fb:c9:9c:89:6e:b3:
                        ac:26:dd:08:1d:4f:40:85:cb:c9:24:80:ef:20:0f:
                        64:50:3d:a6:4f:9e:f5:3d:a4:b6:70:42:4e:94:0c:
                        38:98:4f:32:90:99:bd:f9:d2:5f:fd:05:e8:6e:fc:
                        92:71:88:dd:3c:da:90:ae:65:f6:88:20:e9:26:e4:
                        df:0f:89:62:e9:6a:bb:b0:1e:98:19:7c:a3:f3:6c:
                        4b:04:3b:97:ad:59:90:fc:b0:47:dc:56:9d:b6:da:
                        d0:b3:a3:f5:d6:a6:cc:ab:3d:b1:f3:bb:1c:3b:ed:
                        34:57:8f:9b:40:b4:52:43:77:a1:09:5d:ff:d7:e7:
                        05:2a:17:d8:ff:7b:4c:65:fa:da:c1:00:32:a6:df:
                        57:2c:e3
                    Exponent: 65537 (0x10001)
            X509v3 extensions:
                X509v3 Subject Key Identifier:
                    D3:F6:42:22:3A:55:A4:E9:BF:2C:E0:BF:50:9E:AE:72:03:76:22:BA
                X509v3 Authority Key Identifier:
                    keyid:D3:F6:42:22:3A:55:A4:E9:BF:2C:E0:BF:50:9E:AE:72:03:76:22:BA

                X509v3 Basic Constraints: critical
                    CA:TRUE
        Signature Algorithm: sha256WithRSAEncryption
             71:46:15:47:73:05:43:86:43:b5:ce:fa:42:45:7b:e0:e0:03:
             5e:1a:0c:c7:70:d3:f3:c8:c4:91:b8:91:5c:da:61:9a:7e:63:
             55:26:2e:6e:6c:32:7e:63:eb:dd:f3:b1:de:77:02:f1:14:a0:
             92:c2:46:46:e8:5f:b7:f3:50:86:f5:e8:07:15:11:e2:0e:5c:
             42:79:0f:b8:56:19:a3:1a:8a:1e:1f:a3:a7:fa:54:5e:77:d0:
             6d:92:72:cf:4a:ad:71:fb:67:8d:3f:ed:8f:07:35:10:c6:64:
             04:be:4c:64:ff:bf:3b:d1:3a:dd:94:24:46:12:2a:e5:5f:7b:
             1f:2f:73:fe:de:27:1c:72:e3:1b:d0:1d:1a:e8:b3:b2:11:2f:
             9e:18:a6:88:f8:68:c9:a6:1f:dd:73:87:81:a8:d6:64:b0:13:
             a1:fd:41:f1:9f:78:14:ad:cc:f3:70:fc:f4:a5:e6:23:b1:02:
             b3:5d:f1:82:96:29:44:0c:78:ff:77:79:e4:de:16:b0:34:5c:
             65:4d:02:9f:f2:4c:4f:2a:b9:64:bf:fc:f6:9c:21:ed:f8:7b:
             fa:62:ad:99:9b:c9:6f:75:43:6e:c7:21:a6:65:dd:1b:2e:05:
             52:79:4f:08:15:06:4f:b0:1b:e6:65:a3:ec:10:6e:9c:32:0f:
             63:af:35:78:ea:38:fb:91:24:86:48:cd:33:ed:66:94:eb:00:
             9a:00:02:74:c9:9a:fe:7f:6d:96:b1:9e:81:83:c2:87:43:6a:
             65:1a:5d:1d:14:53:ef:75:fa:56:7e:c3:1e:58:a7:ad:53:d5:
             5f:c7:62:2d:43:df:79:b9:43:93:45:5a:b9:67:3b:7e:50:f3:
             26:85:08:9f:a3:a8:d8:d9:36:38:cb:da:0e:45:a8:33:0e:c1:
             0c:9c:10:37:97:d2:0b:84:e1:23:3f:be:42:68:df:7a:b4:a2:
             51:d7:bc:cd:09:24:93:ba:c7:b3:12:af:c9:dd:67:93:70:8b:
             23:a7:3d:d8:6b:7a:b1:db:af:c2:88:a9:62:c1:60:84:95:3d:
             46:ad:f9:5a:c9:68:e0:88:df:57:ed:2c:81:b0:92:24:97:83:
             11:6e:2f:96:e4:2e:56:02:28:81:4a:97:9c:eb:df:da:92:9c:
             6f:30:72:c1:74:29:e1:72:95:b2:61:ae:3e:27:8e:70:9f:a4:
             36:94:0a:d1:e3:7c:37:04:a6:49:17:8a:59:26:37:b4:1b:97:
             d1:0d:c4:9c:d3:a2:06:87:44:bb:e0:23:b1:e8:c4:30:5c:ee:
             10:5b:68:3e:fd:8c:7f:e3:17:71:98:0d:8a:25:c4:70:24:f7:
             97:58:5b:12:04:02:0c:95
        -----BEGIN CERTIFICATE-----
        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
        -----END CERTIFICATE-----

====================================================

16. ¿Cómo puede enviar la clave privada del certificado anterior como
cuerpo de un correo electrónico, en texto plano y aplanado en PEM a un
compañero (de los del ejercicio 7)? ¿Puede el profesor descifrar dicho
mensaje si se hace con el correo electrónico enviado? ¿Y si le roba
sus anillos de claves de su directorio $HOME/.gnugp?

COMANDO Y RESPUESTAS:
====================================================

Se puede enviar la clave privada en texto plano como cuerpo de un correo si
antes la ciframos con la clave pública de dicho compañero. Podemos hacerlo con
el siguiente comando:
$ gpg -o privkey.gpg --sign --encrypt -r luis.martinez.sanchez@gmail.com privkey.pem

El profesor no podría descifrar el mensaje porque no dispone de la clave privada
de la persona a la que va dirigido el mensaje.

Si el profesor roba el anillo de claves a mi compañero, podría pasarle un cracker.
Todo dependerá de lo fuerte que sea su contraseña.
====================================================

17. ¿Cómo tendría que descifrar y verificar su compañero el mensaje
del punto anterior?

RESPUESTA:
====================================================
-- Verificar --
gpg --verify privkey.gpg

-- Descifrar la clave privada cifrada y enviada por el emisor --
$ gpg --output privkey --decrypt privkey.gpg
====================================================

18. ¿Cuál es el número de serie y el fingerprint del certificado
X509 que usa www.urjc.es? ¿Para qué dominios es válido? ¿Y si el
navegador no entiende la extensión Subject Alternative Names?

COMANDOS Y RESPUESTAS:
====================================================

Serial Number: 0D:33:81:80:9E:94:EA:6F:BF:31:2E:5C:26:F6:C1:2F

Fingerprint SHA-256: 6B:C0:9D:89:CF:5D:48:92:F7:BC:D1:C6:A6:D9:CE:81:54:71:B5:B5:60:F2:A8:A0:E4:51:DD:1B:43:64:93:03

Fingerprint SHA-1: 9C:04:41:82:73:C2:D3:DF:B0:DD:68:9E:64:48:4E:0F:E1:CF:BF:1B




====================================================


19. Verifique la cadena de confianza del certificado del punto anterior
con el comando openssl. En un sistema GNU/Linux, los certificados raíz
del sistema se encuentran en el directorio /etc/ssl/certs.

COMANDOS:
====================================================
$ openssl verify -verbose -CAfile <(cat digicert.pem terena.pem) www-urjc-es.pem

www-urjc-es.pem: OK
====================================================


20. Entregue este fichero con las respuestas, firmado y cifrado
para que sólo Enrique Soriano pueda leerlo. El fichero se tiene
que llamar practica.gpg. También debe entregar un fichero con su
clave pública, llamado clave.gpg.

Especifique los comandos que va a ejecutar para crear el fichero
practica.gpg:

RESPUESTA:
====================================================
-- Firmar y cifrar --
$ gpg -o practica.gpg --sign --encrypt -r enrique.soriano@urjc.es 1-practica.txt.1.sig

====================================================
-----BEGIN PGP SIGNATURE-----
Comment: GPGTools - https://gpgtools.org

iQIzBAEBCgAdFiEEx9w9VDmfw50pCmHJqNbZ9QBUu6YFAlxUBhgACgkQqNbZ9QBU
u6bfTg/9G3vJ44zDZ5+Tw1oX26c/yLsAC7Iai3e49VYTQGxUFXUrA5gJc1LvM/Sm
csjwckXvzYunPNcOH88dEXAQYqB94rwi4N8zUWsF2iHBY35WViDRQj2MO+fOAlX5
1JAc0S7Q9z+yN0IVppNZUeEQNb/moqNg4FbtEMWEWG92k423ldew0EDKQ/RzhNEP
72G9g43IFgE3tVTU5G4OTje80/hgfyvlwGXqVLJykb9GqXkAXAJ6ZG7UmwUEohGF
Yyqzy2zF4p1NEoJZV4oN931NgW5v5mKxt1NvDEZTWR5PcrZ7Hb0js31ecZxGgdZ/
owEW8RA0ziCE54cmOu6XNjQSPlPxfGvgxrfhhPy0ij0t4RAR7UwDkNkfbtJ8+A0W
qfxfaL4Vg/17Ln5msBBRBf4WTVZPOxYpydfaR5dkciyGXnI/i6l9NcGa18oi4uMd
laleZrVpnI1b7ERSNgDr6T2Btq3j3k3d3P9Y0Sg3wEvqaYd1Ck5Vb41IxBh6i2zF
z7n1RJZ+YacTJTzfomfRqWx7fRp6Y41ggRiWL+zIKoeAza1Met+oPK+bQRDW8Uir
zCgAa/xy/MJnr7d6djlfT16LYmJSugTaJWj890A5oLzoeNOArl4s3l9CUpRIvkmk
QT4FBg6dqQjzD46RzwVFoMfwrhZNNPyucaKJXy6GS9+pGeuGKLk=
=chWW
-----END PGP SIGNATURE-----
