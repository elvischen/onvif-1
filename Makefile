CC=gcc
CXX=g++

extras=-luuid -lcrypto

client:main.o soapC.o soapClient.o stdsoap2.o duration.o getCapabilities.o
	$(CXX) -g -Wall -o client main.o soapC.o soapClient.o stdsoap2.o duration.o getCapabilities.o $(extras)
	
main.o:main.c
	$(CXX) -g -c main.c
soapC.o:soapC.c
	$(CXX) -g -c soapC.c
soapClient.o:soapClient.c
	$(CXX) -g -c soapClient.c
stdsoap2.o:stdsoap2.c
	$(CXX) -g -c stdsoap2.c
duration.o:duration.c
	$(CXX) -g -c duration.c
getCapabilities.o:getCapabilities.c
	$(CXX) -g -c  getCapabilities.c
	
clean:
	rm main.o getCapabilities.o client 
