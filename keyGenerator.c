/*
 *  Key generation application
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 Original source code can be found in Mbedtls->programs->pkey->gen_key.c
*/


#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <commctrl.h>
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"


#define FORMAT_PEM              0
#define FORMAT_DER              1
#define BUF_SIZE               64
#define BIG_BUF_SIZE           16000

#define ID_START 8000
#define ID_KTYPE 8001

#define FONT_SET(_h_)        SendMessage(_h_, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1, 0))
#define WS_BOXCENTER         WS_CHILD|WS_VISIBLE|BS_GROUPBOX|BS_CENTER
#define WS_DROPALL           WS_CHILD|WS_VISIBLE |CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP
#define COMBO_ADD(_h_,_a_)   SendMessage(_h_,CB_ADDSTRING,0,(LPARAM)(LPCSTR)_a_)
#define COMBO_SET(_h_,_i_)   SendMessage(_h_,CB_SETCURSEL, (WPARAM)_i_,0)
#define COMBO_GET(_h_)       SendMessage(_h_, CB_GETCURSEL, 0, 0)
#define STATUS(_s_)  SetWindowText(hWnd,_s_)

static char szClassName[ ] = "PrivateKeyGenerator";

HINSTANCE ins;
HWND hWnd;

HWND     hKeyType;
HWND     hKeyFormat;
HWND     hECCurve;
HWND     hKeySize;

void CenterOnScreen()
{
     RECT rcClient, rcDesktop;
	 int nX, nY;
     SystemParametersInfo(SPI_GETWORKAREA, 0, &rcDesktop, 0);
     GetWindowRect(hWnd, &rcClient);
     nX=((rcDesktop.right - rcDesktop.left) / 2) -((rcClient.right - rcClient.left) / 2);
     nY=((rcDesktop.bottom - rcDesktop.top) / 2) -((rcClient.bottom - rcClient.top) / 2);
     SetWindowPos(hWnd, NULL, nX, nY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
     SetWindowPos(hWnd, HWND_TOPMOST,0,0,0,0, SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOMOVE);						
  return;
}

void InitData()
{
   //---build EC Curve options      
    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_list();
    const char *oid;
    size_t oid_len;
    do
    {    //check if the EC curve is available,it depends on Config file
        if(mbedtls_oid_get_oid_by_ec_grp(curve_info->grp_id, &oid, &oid_len) == 0)
        {
          COMBO_ADD(hECCurve,curve_info->name);
        }
    }while ((++curve_info)->name != NULL);
    
    COMBO_SET(hECCurve,0); //the first is the default
    //---build key size options
    UCHAR tmp[8];
    DWORD i;
    for(i=1;i<=MBEDTLS_MPI_MAX_BITS/1024;i++)
    {
        sprintf(tmp,"%d\0",i*1024);
        COMBO_ADD(hKeySize,tmp); 
    }
    COMBO_SET(hKeySize,3); 
    //---build key type
    COMBO_ADD(hKeyType,"RSA");  
    COMBO_ADD(hKeyType,"ECKEY"); 
    COMBO_SET(hKeyType,0);
    //---build (export) key format
    COMBO_ADD(hKeyFormat,"PEM"); 
    COMBO_ADD(hKeyFormat,"DER");  
    COMBO_SET(hKeyFormat,0);
    EnableWindow(hECCurve,FALSE); 
}


unsigned char Fname[MAX_PATH];
typedef struct _KEYINFO
{
    int type;                   /* the type of key to generate          */
    int rsa_keysize;            /* length of key in bits                */
    int ec_curve;               /* curve identifier for EC keys         */
    unsigned char *filename;       /* filename of the key file             */
    int format;                 /* the output format to use             */
   // int use_dev_random;         /* use /dev/random as entropy source    */
   //#AM71113363 the "use_dev_random;" its always random because I'm using Fname
   //as entropy source which uses GetTickCount(),well its not random,but for sure
   //its not always the same
}KEYINFO;

int write_private_key( mbedtls_pk_context *key, KEYINFO *info)
{
    FILE *f;
    int ret;
    unsigned char output_buf[BIG_BUF_SIZE];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, BIG_BUF_SIZE);
    if( info->format == FORMAT_PEM )
    {
        if(mbedtls_pk_write_key_pem( key, output_buf, BIG_BUF_SIZE ) != 0 )
        {
            STATUS("!pk_write_key_pem.");                         
            return( -1 );
        }
        len = strlen(output_buf);
    }
    else //FORMAT_DER
    {
        ret = mbedtls_pk_write_key_der( key, output_buf, BIG_BUF_SIZE );
        if(ret < 0 )
        {
            STATUS("!pk_write_key_der.");                         
            return( -1 );
        }
        len = ret;
        c = output_buf + BIG_BUF_SIZE - len;
    }
    
    f = fopen(info->filename, "wb" );
    
    if( f == NULL )
    {
        STATUS("!fopen(FileName)."); 
        return( -1 );
    }

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        STATUS("!fwrite(FileName)."); 
        return( -1 );
    }
    fclose( f );
    return( 0 );
}

int GetSettings(KEYINFO *opt)
{
    int ret = 0;
    const mbedtls_ecp_curve_info *curve_info; 
    unsigned char buf[BUF_SIZE];
    //Get KeyType
    ret = COMBO_GET(hKeyType);
    if(ret == 0){   opt->type = MBEDTLS_PK_RSA;   }
    else        {   opt->type = MBEDTLS_PK_ECKEY; }

    //Get export Key format
    ret = COMBO_GET(hKeyFormat);
    if(ret == 0){   opt->format = FORMAT_PEM;    }
    else        {   opt->format = FORMAT_DER;    }

    if(opt->type == MBEDTLS_PK_ECKEY)
    {
        //Get EC curve option
        memset(buf,0,BUF_SIZE);
        GetWindowText(hECCurve,buf,BUF_SIZE);
        curve_info = mbedtls_ecp_curve_info_from_name(buf);
        if(curve_info == NULL)
        {
           STATUS("BUG: EC Curve");  //this should not happen
           return( -1 );
        }
       opt->ec_curve = curve_info->grp_id;
    }
    //Get Key Size
    memset(buf,0,BUF_SIZE);
    GetWindowText(hKeySize,buf,BUF_SIZE);
    
    ret = atoi(buf);
    if(ret < 1024 || ret > MBEDTLS_MPI_MAX_BITS)
    {
        STATUS("BUG: Key Size");  //this should not happen
        return( -1 );
    }
    opt->rsa_keysize = ret;
    //Set a random name to avoid re-write the same key
    sprintf(Fname,"pKey_%X.key\0",GetTickCount());
    opt->filename            = Fname;
 
  return (0);
}

int VerifyRSAkey(mbedtls_rsa_context *rsa)
{
    int ret = 0;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP; 
    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
    do
    {
       ret = mbedtls_rsa_export( rsa, &N, &P, &Q, &D, &E );
       if(ret != 0){ STATUS("!Verify(rsa_export)"); break; }               
       
       ret = mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP );
       if(ret != 0 ){ STATUS("!Verify(rsa_export_crt)"); break; }
    }while(0);
 
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

   return ret;  
}

void FreeAll(mbedtls_pk_context *key,
             mbedtls_ctr_drbg_context *ctr_drbg,
             mbedtls_entropy_context *entropy)
{
    mbedtls_pk_free( key );
    mbedtls_ctr_drbg_free( ctr_drbg );
    mbedtls_entropy_free( entropy ); 
}

int GenerateKey()
{
    int ret = 0; 
    KEYINFO keyinfo;
    mbedtls_pk_context key;   
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
       
    STATUS("Settings...");
    ret = GetSettings(&keyinfo);
    if(ret != 0)
      return ret;

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    STATUS("Random generator...");
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,mbedtls_entropy_func,&entropy,Fname,strlen(Fname));
    if(ret != 0){ STATUS("!ctr_drbg_seed"); FreeAll(&key, &ctr_drbg, &entropy); return ret; } 
           
    STATUS("Setup key ...");
    ret = mbedtls_pk_setup( &key, mbedtls_pk_info_from_type( keyinfo.type ));
    if(ret != 0 ){ STATUS("!pk_setup"); FreeAll(&key, &ctr_drbg, &entropy); return ret; } 
        
    STATUS("Create key ...");
    if(keyinfo.type == MBEDTLS_PK_RSA )
    {
        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random,&ctr_drbg,keyinfo.rsa_keysize, 65537 );
        if(ret != 0 ){ STATUS("!rsa_gen_key"); FreeAll(&key, &ctr_drbg, &entropy); return ret; } 
        STATUS("Verify Key...");
        mbedtls_rsa_context *rsa = mbedtls_pk_rsa( key );
        ret = VerifyRSAkey(rsa);
        if(ret != 0 ){ FreeAll(&key, &ctr_drbg, &entropy); return ret; } 
    }
    else //if(keyinfo.type == MBEDTLS_PK_ECKEY )
    {
        ret = mbedtls_ecp_gen_key(keyinfo.ec_curve,mbedtls_pk_ec(key),mbedtls_ctr_drbg_random,&ctr_drbg);
        if(ret != 0 ){ STATUS("!ecp_gen_key"); FreeAll(&key, &ctr_drbg, &entropy); return ret; }  
    } 
    STATUS("Writing key...");  //save key to file
    
    ret = write_private_key( &key, &keyinfo);
    
    FreeAll(&key, &ctr_drbg, &entropy);
 return ret;    
}


void CreateRSAKey()
{
     EnableWindow(GetDlgItem(hWnd,ID_START),0);
     if(GenerateKey() == 0)
       STATUS(Fname);
     EnableWindow(GetDlgItem(hWnd,ID_START),1);                      
}


LRESULT CALLBACK WindowProcedure (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
  switch (message) 
  {
    case WM_CREATE:
    {
        HFONT hFont;       
        hWnd = hwnd;
        InitCommonControls();
        hFont = CreateFont(15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "Comic Sans MS");
 
        FONT_SET(CreateWindow("BUTTON","Type",WS_BOXCENTER,10,3,90,50,hwnd,0,ins,NULL));
        FONT_SET(CreateWindow("BUTTON","Format",WS_BOXCENTER,103,3,70,50,hwnd,0,ins,NULL));
        FONT_SET(CreateWindow("BUTTON","EC Curve",WS_BOXCENTER,10,55,163,50,hwnd,0,ins,NULL));
        FONT_SET(CreateWindow("BUTTON","Key Size",WS_BOXCENTER,10,107,80,50,hwnd,0,ins,NULL));
        
        hKeyType=CreateWindow("combobox", "",WS_DROPALL,19, 22, 73, 80, hwnd, (HMENU)ID_KTYPE,ins, NULL);  	
	    hKeyFormat=CreateWindow("combobox", "",WS_DROPALL,112, 22, 53, 80, hwnd, NULL,ins, NULL);  	
	    hECCurve=CreateWindow("combobox", "",WS_DROPALL,18, 74, 147, 280, hwnd,NULL,ins, NULL);  	
        hKeySize=CreateWindow("combobox", "",WS_DROPALL,19, 126, 63, 200, hwnd, NULL,ins, NULL);  	
	    
        CreateWindow("BUTTON","Start",WS_CHILD|WS_VISIBLE,100,122,70,32,hwnd,(HMENU)ID_START,ins,NULL);
        CenterOnScreen();
        CreateThread(0,0,(LPTHREAD_START_ROUTINE)InitData,0,0,0);	 
        }
        break;
        case WM_COMMAND:
        switch(LOWORD(wParam))
        {
              case ID_START:
              { 
                  CreateThread(0,0,(LPTHREAD_START_ROUTINE)CreateRSAKey,0,0,0);	 
              }
              break;  
              case ID_KTYPE:
              {
                   if(COMBO_GET(hKeyType) == 1)
                   {
                       EnableWindow(hECCurve,TRUE);                  
                   }
                   else
                   {
                       EnableWindow(hECCurve,FALSE);  
                   }
              }break;                               
         }
         break;
        case WM_DESTROY:
            PostQuitMessage (0);
            break;
        default: 
            return DefWindowProc (hwnd, message, wParam, lParam);
    }

    return 0;
}

int WINAPI WinMain (HINSTANCE _a_,HINSTANCE _b_,LPSTR _c_,int _d_)
{
    HWND hwnd;
    MSG messages;
    WNDCLASSEX wincl;
    ins = _a_;
    wincl.hInstance = _a_;
    wincl.lpszClassName = szClassName;
    wincl.lpfnWndProc = WindowProcedure;
    wincl.style = CS_DBLCLKS; 
    wincl.cbSize = sizeof (WNDCLASSEX);

    wincl.hIcon = LoadIcon (ins,MAKEINTRESOURCE(200));
    wincl.hIconSm = LoadIcon (ins,MAKEINTRESOURCE(200));
    wincl.hCursor = LoadCursor (NULL, IDC_ARROW);
    wincl.lpszMenuName = NULL;               
    wincl.cbClsExtra = 0;  
    wincl.cbWndExtra = 0;
    wincl.hbrBackground = (HBRUSH) COLOR_BACKGROUND;

    if (!RegisterClassEx (&wincl))
        return 0;

    hwnd = CreateWindowEx (0,szClassName,"Private Key Generator",WS_OVERLAPPED|WS_SYSMENU, CW_USEDEFAULT,CW_USEDEFAULT,
           190,200,HWND_DESKTOP,NULL,_a_,NULL);

    ShowWindow (hwnd, _d_);
    while (GetMessage (&messages, NULL, 0, 0))
    {
        TranslateMessage(&messages);
        DispatchMessage(&messages);
    }
   return messages.wParam;
}

