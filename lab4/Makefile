all: crack gen verifier

crack:
	gcc CRACK/main.c func.c -Wall -lssl -lcrypto -o crack

gen:
	gcc GEN/main.c func.c -Wall -lssl -lcrypto -o gen

verifier:
	gcc VERIFIER/main.c func.c -Wall -lssl -lcrypto -o verifier

clean:
	rm if *.o
