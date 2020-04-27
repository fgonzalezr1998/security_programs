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


====================================================

3. ¿Puede estar seguro de que esas claves descargadas son auténticas y
pertenecen a Enrique Soriano? ¿Por qué?

RESPUESTA:
====================================================






====================================================

4. Compruebe la autenticidad de la clave del profesor Enrique Soriano
comprobando su  fingerprint con el que ha dado el profesor en
persona.

COMANDOS:
====================================================






====================================================

4. ¿Puede estar seguro de que la clave descargada es auténtica
y pertenece al profesor?

RESPUESTA:
====================================================






====================================================

5. Si es así, firme la clave del profesor y suba la firma al servidor
de Rediris.

COMANDOS:
====================================================






====================================================

6. Comparta su clave pública con otras personas de la clase (por ejemplo
por correo electrónico). ¿Cómo exporta su clave pública? Resuma todos los
pasos para compartir su clave pública de forma segura:

COMANDO y RESPUESTA:
====================================================






====================================================

7. Añada las claves de dos compañeros en su anillo. Asigne a cada compañero
el nivel de confianza que desee.

COMANDOS:
====================================================






====================================================


8. Compruebe la autenticidad y la integridad de las tres versiones
del enunciado que están disponibles (1, 2, 3). ¿Puede asegurar que
alguna de las versiones fue publicada por el profesor? ¿Cuál o cuáles?
¿Por qué?

COMANDO y RESPUESTA:
====================================================






====================================================

9. Descargue del foro de la asignatura el fichero p1secret.gpg,
cifrado con una clave simétrica y descífrelo. El secreto para
descifrar el fichero se comunicará en clase. ¿Qué es?

COMANDOS Y RESPUESTA:
====================================================






====================================================

10. Descargue a firma del mensaje en claro, p1secret.sig.
¿Puede estar seguro de que el mensaje es integro (no ha sido
modificado por un atacante)? ¿Puede el profesor repudiar dicho
mensaje?

COMANDOS Y RESPUESTA:
====================================================






====================================================

11. Cifre esa misma imagen con el algoritmo de clave simétrica AES, con
una clave de 256 bits, usando el comando gpg.

COMANDO:
====================================================






====================================================

12. Haga lo mismo que en el apartado anterior usando el comando
openssl. Tiene que usar el modo CBC.

COMANDO:
====================================================






====================================================

13. Calcule el resumen hash SHA-1 para los dos ficheros anteriores.
¿Coinciden? ¿Deberían coincidir? ¿Por qué?

COMANDO Y RESPUESTA:
====================================================






====================================================

14. Descifre ambos ficheros y compruebe que los datos descifrados son
exactamente los mismos que los originales.

COMANDOS:
====================================================






====================================================

15. Genere un certificado X.509 en texto plano para la compañía ACME,
con correo electrónico pepe@acme.jp. La clave RSA tiene que ser de
4096 bits y el certificado debe ser válido por un año desde su
creación. Indique su número de serie:

COMANDOS:
====================================================






====================================================

16. ¿Cómo puede enviar la clave privada del certificado anterior como
cuerpo de un correo electrónico, en texto plano y aplanado en PEM a un
compañero (de los del ejercicio 7)? ¿Puede el profesor descifrar dicho
mensaje si se hace con el correo electrónico enviado? ¿Y si le roba
sus anillos de claves de su directorio $HOME/.gnugp?

COMANDO Y RESPUESTAS:
====================================================






====================================================

17. ¿Cómo tendría que descifrar y verificar su compañero el mensaje
del punto anterior?

RESPUESTA:
====================================================






====================================================

18. ¿Cuál es el número de serie y el fingerprint del certificado
X509 que usa www.urjc.es? ¿Para qué dominios es válido? ¿Y si el
navegador no entiende la extensión Subject Alternative Names?

COMANDOS Y RESPUESTAS:
====================================================






====================================================


19. Verifique la cadena de confianza del certificado del punto anterior
con el comando openssl. En un sistema GNU/Linux, los certificados raíz
del sistema se encuentran en el directorio /etc/ssl/certs.

COMANDOS:
====================================================






====================================================


20. Entregue este fichero con las respuestas, firmado y cifrado
para que sólo Enrique Soriano pueda leerlo. El fichero se tiene
que llamar practica.gpg. También debe entregar un fichero con su
clave pública, llamado clave.gpg.

Especifique los comandos que va a ejecutar para crear el fichero
practica.gpg:

RESPUESTA:
====================================================






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
