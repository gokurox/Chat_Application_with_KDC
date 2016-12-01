DATABASE_DIR = ./database/
DATABASE_PRIVATE_DIR = ./database/private/
DATABASE_GROUPS_DIR = ./database/groups/
FILES_DIR = ./files/
OBJECTS_DIR = ./obj/
EXECS_DIR = ./exec/

HEADERS_DIR = ./header/
AUXCODE_DIR = ./auxcode/
MAINCODE_DIR = ./main/

all: make_objs
	g++ $(OBJECTS_DIR)chatclient.o $(OBJECTS_DIR)client_aux.o $(OBJECTS_DIR)common_aux.o $(OBJECTS_DIR)crypto_aux.o -o $(EXECS_DIR)client.out -lssl -lcrypto -std=c++11
	g++ $(OBJECTS_DIR)chatserver.o $(OBJECTS_DIR)server_aux.o $(OBJECTS_DIR)common_aux.o $(OBJECTS_DIR)crypto_aux.o $(OBJECTS_DIR)kdc_aux.o -o $(EXECS_DIR)server.out -lssl -lcrypto -std=c++11
	###########################################################
	# Please change directory to ./exec before running any ".out" file #

server: make_dirs obj2 obj3 obj4 obj5 obj7
	g++ $(OBJECTS_DIR)chatserver.o $(OBJECTS_DIR)server_aux.o $(OBJECTS_DIR)common_aux.o $(OBJECTS_DIR)crypto_aux.o $(OBJECTS_DIR)kdc_aux.o -o $(EXECS_DIR)server.out -lssl -lcrypto -std=c++11

client: make_dirs obj1 obj2 obj3 obj6
	g++ $(OBJECTS_DIR)chatclient.o $(OBJECTS_DIR)client_aux.o $(OBJECTS_DIR)common_aux.o $(OBJECTS_DIR)crypto_aux.o -o $(EXECS_DIR)client.out -lssl -lcrypto -std=c++11

make_objs: make_dirs obj1 obj2 obj3 obj4 obj5 obj6 obj7


obj1: $(AUXCODE_DIR)client_aux.cpp
	g++ -c $(AUXCODE_DIR)client_aux.cpp -o $(OBJECTS_DIR)client_aux.o -std=c++11

obj2: $(AUXCODE_DIR)common_aux.cpp
	g++ -c $(AUXCODE_DIR)common_aux.cpp -o $(OBJECTS_DIR)common_aux.o -std=c++11

obj3: $(AUXCODE_DIR)crypto_aux.cpp
	g++ -c $(AUXCODE_DIR)crypto_aux.cpp -o $(OBJECTS_DIR)crypto_aux.o -std=c++11

obj4: $(AUXCODE_DIR)kdc_aux.cpp
	g++ -c $(AUXCODE_DIR)kdc_aux.cpp -o $(OBJECTS_DIR)kdc_aux.o -std=c++11

obj5: $(AUXCODE_DIR)server_aux.cpp
	g++ -c $(AUXCODE_DIR)server_aux.cpp -o $(OBJECTS_DIR)server_aux.o -std=c++11

obj6: $(MAINCODE_DIR)chatclient.cpp
	g++ -c $(MAINCODE_DIR)chatclient.cpp -o $(OBJECTS_DIR)chatclient.o -std=c++11

obj7: $(MAINCODE_DIR)chatserver.cpp
	g++ -c $(MAINCODE_DIR)chatserver.cpp -o $(OBJECTS_DIR)chatserver.o -std=c++11

make_dirs:
	if [ ! -d $(DATABASE_DIR) ]; then mkdir $(DATABASE_DIR); fi;
	if [ ! -d $(DATABASE_PRIVATE_DIR) ]; then mkdir $(DATABASE_PRIVATE_DIR); fi;
	if [ ! -d $(DATABASE_GROUPS_DIR) ]; then mkdir $(DATABASE_GROUPS_DIR); fi;
	if [ ! -d $(FILES_DIR) ]; then mkdir $(FILES_DIR); fi;
	if [ ! -d $(OBJECTS_DIR) ]; then mkdir $(OBJECTS_DIR); fi;
	if [ ! -d $(EXECS_DIR) ]; then mkdir $(EXECS_DIR); fi;

clean:
	if [ -d $(DATABASE_DIR) ]; then rm -rf $(DATABASE_DIR); fi;
	if [ -d $(FILES_DIR) ]; then rm -rf $(FILES_DIR); fi;
	if [ -d $(OBJECTS_DIR) ]; then rm -rf $(OBJECTS_DIR); fi;
	if [ -d $(EXECS_DIR) ]; then rm -rf $(EXECS_DIR); fi;
