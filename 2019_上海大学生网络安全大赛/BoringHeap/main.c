#include<stdio.h>
int main()
{
	for(int i=1;i!=0;i++)
	{
		int tmp=abs(i)%0x30;
		if(tmp>=0x30||tmp<0)
		{	printf("%d\n",tmp);
			printf("%d\n",i);}
	}
}
