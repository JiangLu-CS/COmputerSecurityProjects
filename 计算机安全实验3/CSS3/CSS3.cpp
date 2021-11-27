#include <stdio.h>
#include <string.h>
void Get(int x, int y)
{
	int z = 0x33333333;
	char s[] = "9999999999999999999999\0";
	x = z;
	y = z;
	sprintf_s(s, "%x,%x", x, y);
}
int main(int argc, char* argv[], char* envp[])
{
	int t1 = 0x11111111;
	int t2 = 0x22222222;
	Get(t1, t2);
	return 0;
}
