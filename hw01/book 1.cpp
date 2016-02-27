#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdlib.h>
using namespace std;


int CountLines(char *filename)
{
    ifstream ReadFile;
    int n=0;
    string tmp;
    ReadFile.open(filename,ios::in);//ios::in 表示以只读的方式读取文件
    if(ReadFile.fail())//文件打开失败:返回0
    {
        return 0;
    }
    else//文件存在
    {
        while(getline(ReadFile,tmp,'\n'))
        {
            n++;
        }
        ReadFile.close();
        return n;
    }
}

void compute_key (int64_t * ciphertext, int64_t * key)
{
    int64_t character[17] = {80,114,111, 106, 101, 99, 116, 32, 71, 117, 116, 101,110, 98, 101, 114, 103};
    int i=0;
    for(i=0;i<17;i++)
    {
        key[i]= ciphertext[i+1] - character[i];
    }
    //for(i=0;i<17;i++)
    //  cout<<key[i]<<endl;

}

size_t compute_m_multiple(int64_t *x)
{
    int64_t y0,y1,y2;
    size_t m_m;
    
    y0 = x[1]-x[0];
    y1 = x[2]-x[1];
    y2 = x[3]-x[2];

    m_m = y1*y1 - y2*y0;
    //cout<<m_m<<endl;

    return m_m;
}


size_t compute_a ( size_t m, int64_t * x)
{
    int64_t y0,y1;
    size_t a;
    
    y0 = x[1]-x[0];
    y1 = x[2]-x[1];
    
    for (a = 0; a < m; a ++)
    {
        if (y1 == (a * y0) % m)
        {
            return a;
        }
    }
    
    return 0;
}

size_t compute_b ( size_t m, int64_t * x, size_t a)
{
    if (a == 0)
        return 0;
    
    size_t b, ax0;
    ax0 = a * x[0];
    for (b = 0; b < m; b ++) {
        if (x[1] == ((ax0 + b) % m))
            return b;
    }
    return 0;
}

void compute_factor( vector<size_t> & factor, size_t m, int64_t key_M) //m is bigger than the biggest key
{
    size_t temp = key_M, factor_MAX = 1;
    int i = 0, j = 1, i1 = 0;
    
    while ((key_M / 10) > 1) {
        j++;                            //compute how many digits are in the biggest key
        key_M /= 10;
    }
    for (i1 = j; i1 > 0; i1 --)
    {
        factor_MAX *= 10;
        
    }
    //cout<<"factor_MAX is "<<factor_MAX<<endl;
                                                // only compute the first 5 possible m which is bigger
                                                // than the biggest ke
        //while (temp <= (factor_MAX / 2))
        while (temp < 4602794000)
        {
            
            if (!(m % temp))
            {
                i ++;
                factor.push_back(temp);
                cout<<endl<<i<<"st factor is "<<temp<<endl;
            }
            
            temp ++;
            
        }

    
    
    
}

void compute_m_factor( vector<size_t> & factor, int64_t * key, size_t m_m, vector<size_t> & A, vector<size_t> & B, vector<size_t> & m)
{
    vector<int64_t> key_max;
    vector<size_t> m_prime_factor;
    //vector<size_t> m_factor;
    key_max.resize(17);
    size_t m_temp;
    size_t a = 0, b = 0;
    
    int i = 0, j = 0;
    int64_t key_M = 0;
    
    for(i=0;i<17;i++)
    {
        key_max[i]=key[i];
        //cout<<key_max[i]<<endl;
    }
    
    key_M = key_max[0];    // key_M is the biggest one in the keys
    for(i=0;i<17;i++)
    {
        if (key_M < key_max[i])
        {
            key_M = key_max[i];
        }
    }
    //cout<<"m_m is "<<m_m<<endl<<endl<<"the key_M is "<<key_M<<endl;
    //cout<<"key_M is "<<key_M<<endl;
 
    compute_factor( factor, m_m , key_M);

    for (j = 0; j < 10; j++)  // compute the first possible a and b
    {
        m_temp = factor[j];
        if ( m_temp >= key_M)
        {
            a = compute_a( m_temp, key);
            b = compute_b( m_temp, key, a);
            //cout<<endl<< j<<" when m = "<<m_tem<<endl<<"a = "<<a<<endl<<"b = "<<b<<endl<<endl;
        }
        if( (a != 0) && (b != 0))
            break;
    }
    m.push_back(m_temp);
    if (a != 0)
        A.push_back(a);
    if (b != 0)
        B.push_back(b);
    cout<<endl<<"m is "<<m[0]<<endl<<"a = "<<A[0]<<endl<<"b = "<<B[0]<<endl;
    
}
void decription_compute_key (size_t a, size_t b, size_t m, vector<size_t> & decription_key, int LINES, int64_t * key)
{
    decription_key[0]= key[0];
    int i = 0;
    
    for (i = 0; i <= LINES; i++)
    {
        decription_key[i+1] = (a * decription_key[i] + b) % m;
        
        //cout<<"key "<<key[i]<<endl;
    }
    /*cout<<endl<<endl<<endl<<"keys?"<<endl;
    for (i = 0; i < 17; i ++)
    {
        cout<<key[i]<<endl;
    }*/
}

/*void compute_character (vector<size_t> & character,int64_t * chiphertext, vector<size_t> & key, int LINES)
{
    int i = 0;
    for (i = 0; i < LINES; i ++)
    {
        character[i] = key[i] - chiphertext [i] ;
        //character[i] -= key[i];
        cout<<character[i]<<endl;
    }
    
}*/

int if_the_keys_are_right(int64_t * key, vector<size_t> & decription_key)
{
    int i = 0;
    vector<size_t> difference_between_the_two_keys(17);
    for (i = 0; i < 17; i++)
    {
        difference_between_the_two_keys[i] = key[i] - decription_key[i];
        if((difference_between_the_two_keys[i]) != 0)
            cout<<"wrong decription_key"<<endl;
        return i;
    }
    return 0;
}
void decript( size_t m_m, int64_t * key, int64_t * ciphertext, int LINES)
{
    //vector<size_t> m_factor, a, b, m, decription_key(LINES);
    
    //compute_m_factor(m_factor, key, m_m, a, b, m);
    int i;
    vector<size_t> m_factor, a(10), b(10), m(10), decription_key(LINES), character(LINES);  //记得去了！！！nt
    m[0] = 4294967296;                                                 //记得去了！！！
    a[0] = 4276115653;                                                 //记得去了！！！
    b[0] = 634785765;                                                  //记得去了！！！
    compute_m_factor(m_factor, key, m_m, a, b, m);

    
    decription_compute_key(a[0],b[0],m[0],decription_key, LINES, key);
    //compute_character(character, ciphertext, decription_key, LINES);
    i = if_the_keys_are_right(key, decription_key);
    if (i == 0)
    {
        cout<<"successful "<<endl;
    }
    else
        cout<<"sorry =.= u are unsuccessful"<<endl;

}

int main()
{
    ifstream file;
    int LINES;
    char filename[128]="/Users/BellaMa/Downloads/CS 165/book1.enc";
    file.open(filename,ios::in);
    if(file.fail())
    {
        cout<<"文件不存在."<<endl;
        file.close();
    }
    else//文件存在
    {
        LINES=CountLines(filename);
        int64_t *ciphertext=new int64_t[LINES];
        int64_t *key=new int64_t[17];
        size_t m_multiple;
        int i=0;
        while(!file.eof()) //读取数据到数组
        {
            
            file>>ciphertext[i];
            i++;
        }
        file.close(); //关闭文件
        //for(i=0;i<LINES;i++)//输出数组内容
        //    cout<<ciphertext[i]<<endl;
        compute_key(ciphertext, key);
        m_multiple = compute_m_multiple(key);
        //cout<<m_multiple<<endl;
        decript (m_multiple, key, ciphertext, LINES);
        delete []ciphertext;
        delete [] key;
    }
}
