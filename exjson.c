#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct find
{
    char key[100];
    char value[100];
    int isfather;
    int father;
};

int u=0;
int slo = 0;
int mark = 0;
char js[200][100];
struct find usr[100000];

void getyinorzhen(){
	while(1){
		if(js[mark][u]=='"'||js[mark][u]=='}')return;
		if(js[mark][u]=='\n'){
			u=0;
			mark++;
			continue;
		}
		u++;
	}
}

void getyinorfan(){
	while(1){
		if(js[mark][u]=='"'||js[mark][u]=='{')return;
		if(js[mark][u]=='\n'){
			u=0;
			mark++;
			continue;
		}
		u++;
	}
}

void getson(int father);

int main()
{
    int n, m;
    scanf("%d %d", &n, &m);
    int i = 0;
    getchar();
    for (; i < n; i++)fgets(js[i],99,stdin);
    int p;
	while(1){
		getyinorzhen();
		if(js[mark][u]=='}')break;
		u++;
		p=0;
		usr[slo].father=-1;
		usr[slo].isfather=0;
		for (;;u++,p++)
        {
        	if (js[mark][u] == '"')break;
            if (js[mark][u] == '\\')u++;
            usr[slo].key[p] = js[mark][u];
        }
        usr[slo].key[p]='\0';
        u++;
        getyinorfan();
        if(js[mark][u]=='"'){
        	u++;
        	p=0;
        	for (;;u++,p++)
        	{
        		if (js[mark][u] == '"')break;
            	if (js[mark][u] == '\\')u++;
            	usr[slo].value[p] = js[mark][u];
        	}
        	usr[slo].value[p]='\0';
        	slo++;
        	u++;
		}
		else{
			u++;
			usr[slo].isfather=1;
			getson(slo);
			u++;
		}
	}
	slo--;
	char s[100];
    //find goal str
    while(m--){
        scanf("%s",s);
        //printf("%s",s); 
        if (strchr(s, '.') != NULL) {//has more floor
            char *token=token = strtok(s, ".");
            int last=-1;
            int flag=0;
            while(token!=NULL){
                //printf("token:%s",token);
                int r=0;
                int v=0;
                flag=0;
                for(;r<=slo;r++){
                    if(strcmp(token,usr[r].key)==0&&usr[r].father==last){
                            last=r;
                            flag=1;
                            break;
                        }
                    }
                        if(flag==0)break;
                        token=strtok(NULL, ".");
                }
            if(flag==0){
                printf("NOTEXIST");
            }
            else{
                if(usr[last].isfather==0){
                printf("STRING %s",usr[last].value);
                    }
                else{
                        printf("OBJECT");
                    }
            }
        } 
        else {//singal
            int r=0;
            int flag=1;
            for(;r<=slo;r++){
                if(strcmp(s,usr[r].key)==0&&usr[r].father==-1){
                    if(usr[r].isfather==0){
                        printf("STRING %s",usr[r].value);
                    }
                    else{
                        printf("OBJECT");
                    }
                    flag=0;
                    break;
                }
            }
            if(flag){
                printf("NOTEXIST");
            }
        }
        if(m!=0){
            printf("\n");
        } 
    }
    return 0; 
}

void getson(int father){
	slo++;
	while(1){
		getyinorzhen();
		if(js[mark][u]=='}')return;
		u++;
		int p=0;
		usr[slo].father=father;
		usr[slo].isfather=0;
		for (;;u++,p++)
        {
        	if (js[mark][u] == '"')break;
            if (js[mark][u] == '\\')u++;
            usr[slo].key[p] = js[mark][u];
        }
        usr[slo].key[p]='\0';
        u++;
        getyinorfan();
        if(js[mark][u]=='"'){
        	u++;
        	p=0;
        	for (;;u++,p++)
        	{
        		if (js[mark][u] == '"')break;
            	if (js[mark][u] == '\\')u++;
            	usr[slo].value[p] = js[mark][u];
        	}
        	usr[slo].value[p]='\0';
        	slo++;
        	u++;
		}
		else{
			u++;
			usr[slo].isfather=1;
			getson(slo);
			u++;
		}
	}
} 
