/* ******************************************************************** **
** @@ CC-2-IDA.IDC
** @  Copyrt : Aleph
** @  Author : Aleph
** @  Modify :
** @  Update : 2014-01-25
** @  Notes  : Simple script to "import" CC report file to IDA database
** ******************************************************************** */

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Be care if you use PEiD KANAL Plug-In's IDC output - it do some stupid
// marking and will be just replace any your early done marks (and sometimes
// place them at incorrect offset).
// Also, you can use my 'delete_marks.idc' for clear all previous marks
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

//    BTW, you can save all lines appearing in the messages window to a file.
//    Just set an enviroment variable:
//
//          set IDALOG=ida.log
//
//    I always have this variable set, it is great help in the development.
//
//    Copyright (c) by Ilfak Guilfanov.
//////////////////////////////////////////////////////////////////////////
// ; --
// ; --  CC type naming convention (for IDA IDC cc2ida.idc script)
// ; --
// ; --  ' '  - <empty> - Do Nothing
// ; --  '.'  - Comment only
// ; --  'R'  - Rename only
// ; --  'N'  - Both Rename & Comment
// ; --  'A'  - convert to ASCIIZ string
// ; --  'C'  - convert to Fixed size ASCII string (Char Arr)
// ; --  'a'  - convert to Delphi ASCIIZ string (with two DWORDs prefix)
// ; --  'U'  - convert to Unicode ZString
// ; --  'B'  - convert to BYTE
// ; --  'W'  - convert to WORD
// ; --  'D'  - convert to DWORD
// ; --  'Q'  - convert to QWORD
// ; --  'O'  - convert to OWORD
// ; --  'f'  - convert to float
// ; --  'd'  - convert to double
// ; --  't'  - convert to TBYTE
// ; --
//////////////////////////////////////////////////////////////////////////

#include <idc.idc>

//////////////////////////////////////////////////////////////////////////
static GetImageBaseHi(Line)
{
   return xtol(substr(Line,14,22));
}
//////////////////////////////////////////////////////////////////////////
static IsMarked(Line)
{
   return substr(Line,1,2) == "*";
}
//////////////////////////////////////////////////////////////////////////
static GetFlag(Line)
{
   return substr(Line,36,37);
}
//////////////////////////////////////////////////////////////////////////
static GetAddress(Line)
{
   return xtol(substr(Line,37,45));
}
//////////////////////////////////////////////////////////////////////////
static GetTypeFlag(Line)
{
   return substr(Line,76,77);
}
//////////////////////////////////////////////////////////////////////////
static GetText(Line)
{
   auto  LL;

   LL = substr(Line,78,-1);
   LL = substr(LL,0,strstr(LL,"\n"));

   return LL;
}
//////////////////////////////////////////////////////////////////////////
static main(void)
{
   auto     MAX_SLOT;

   auto     File;
   auto     Handle;
   auto     Line;
   auto     Flag;
   auto     Type;
   auto     Adr;
   auto     PAdr;
   auto     NAdr;
   auto     LAdr;
   auto     Text;
   auto     Idx;
   auto     pConv;
   auto     bFirstTime;
   auto     ImageBaseHi;
   auto     NewName;

   MAX_SLOT   = 1024;
   Idx        = 0;
   bFirstTime = 1;

   File = AskFile(Handle,"MapFile.CC","*.CC");

   Handle = fopen(File,"rt");

   if (!Handle)
   {
      Warning("Error open input file %s",File);
      return;
   }

   Message("Proceed Input File: %s\n",File);

   while (1)
   {
      Line = readstr(Handle);

      if (Line == -1)
      {
         break;
      }

      if (bFirstTime)
      {
         if (IsMarked(Line))
         {
            ImageBaseHi = GetImageBaseHi(Line) << 32;
            bFirstTime  = 0;
         }
      }

      // Parse String
      Flag = GetFlag(Line);
      Adr  = GetAddress(Line);
      Type = GetTypeFlag(Line);
      Text = GetText(Line);

      if (Flag == ".")
      {
         // Find first free slot
         for (Idx = 1; Idx < MAX_SLOT; ++Idx)
         {
            if (GetMarkedPos(Idx) == -1)
            {
               break;
            }
         }

         LAdr = Adr + ImageBaseHi;

         PAdr = PrevNotTail(LAdr);
         NAdr = NextNotTail(PAdr);

         if ((PAdr != -1) && (NAdr != -1))
         {
            LAdr =  LAdr < NAdr  ?  PAdr  :  NAdr;
         }

         if (Type == 0x20)
         {
            if (MakeComm(LAdr,Text) != 1)
            {
               Message("Err: MakeComm() at adr %08X - %s\n",LAdr,Text);
            }
            else
            {
               Message("Commented at Adr %08X - %s\n",LAdr,Text);
               MarkPosition(LAdr,0,0,0,Idx,Text);
            }
         }
         else
         {
            auto  Marker;
            auto  Size;
            auto  Name;

            Marker = strstr(Text,"{ ");
            Size   = xtol(substr(Text,Marker + 2,Marker + 6));
            Name   = substr(Text,Marker + 7,strstr(Text," }"));
            Text   = substr(Text,0,Marker);

            if (substr(Name,0,-1) != "")
            {
               Name = Name + "_";
               Name = Name + Type;
            }
            
            SetArrayFormat(LAdr,AP_ALLOWDUPS,0,0);

            if (substr(Type,0,1) == "B") // BYTE
            {
               MakeUnknown(LAdr,Size,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_BYTE,1,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "W") // WORD
            {
               MakeUnknown(LAdr,Size * 2,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_WORD,2,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "D") // DWORD
            {
               MakeUnknown(LAdr,Size * 4,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_DWRD,4,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "Q") // QWORD
            {
               MakeUnknown(LAdr,Size * 8,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_QWRD,8,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "O") // OWORD
            {
               MakeUnknown(LAdr,Size * 16,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_OWRD,16,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "f") // float
            {
               MakeUnknown(LAdr,Size * 4,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_FLOAT,4,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "d") // double
            {
               MakeUnknown(LAdr,Size * 8,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_DOUBLE,8,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == "t") // TBYTE
            {
               MakeUnknown(LAdr,Size * 10,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               MakeData(LAdr,FF_TBYT,10,0);
               MakeArray(LAdr,Size);
               MakeNameEx(LAdr,Name,SN_CHECK);
            }
            else if (substr(Type,0,1) == ".") // Comment only
            {
               MakeComm(PAdr,substr(Name,0,strlen(Name) - 2));
            }
            else if (substr(Type,0,1) == "R") // Rename only
            {
               NewName = sprintf("%s%08X",substr(Name,0,strlen(Name) - 1),PAdr);
               MakeNameEx(PAdr,NewName,SN_CHECK);
            }
            else if (substr(Type,0,1) == "N") // Both Rename & Comment
            {
               NewName = sprintf("%s%08X",substr(Name,0,strlen(Name) - 1),PAdr);
               MakeNameEx(PAdr,NewName,SN_CHECK);
               MakeComm(PAdr,substr(Name,0,strlen(Name) - 2));
            }
            else if (substr(Type,0,1) == "A") // ASCIIZ
            {
               if (!Size)
               {
                  MakeUnknown(LAdr,1,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }
               else
               {
                  MakeUnknown(LAdr,Size,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }

               SetLongPrm(INF_STRTYPE,ASCSTR_C);
               MakeStr(LAdr,BADADDR);

               if (substr(Name,0,-1) != "")
               {
                  MakeNameEx(LAdr,Name,SN_CHECK);
               }
            }
            else if (substr(Type,0,1) == "C") // ASCII Char Arr
            {
               if (!Size)
               {
                  MakeUnknown(LAdr,1,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }
               else
               {
                  MakeUnknown(LAdr,Size,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }

               if (!Size)
               {
                  SetLongPrm(INF_STRTYPE,ASCSTR_C);
                  MakeStr(LAdr,BADADDR);
               }
               else
               {
                  SetLongPrm(INF_STRTYPE,ASCSTR_C);
                  MakeStr(LAdr,LAdr + Size);
               }

               if (substr(Name,0,-1) != "")
               {
                  MakeNameEx(LAdr,Name,SN_CHECK);
               }
            }
            else if (substr(Type,0,1) == "a") // Delphi ASCII
            {
               if (!Size)
               {
                  MakeUnknown(LAdr,1,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }
               else
               {
                  MakeUnknown(LAdr,Size + 8,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }

               MakeData(LAdr,    FF_DWRD,4,0);
               MakeData(LAdr + 4,FF_DWRD,4,0);

               SetLongPrm(INF_STRTYPE,ASCSTR_C);
               MakeStr(LAdr + 8,LAdr + 8 + Size);

               if (substr(Name,0,-1) != "")
               {
                  MakeNameEx(LAdr,Name,SN_CHECK);
               }
            }
            else if (substr(Type,0,1) == "U") // Unicode
            {
               if (!Size)
               {
                  MakeUnknown(LAdr,1,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }
               else
               {
                  MakeUnknown(LAdr,Size,DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES);
               }

               SetLongPrm(INF_STRTYPE,ASCSTR_UNICODE);
               MakeStr(LAdr,BADADDR);

               if (substr(Name,0,-1) != "")
               {
                  MakeNameEx(LAdr,Name,SN_CHECK);
               }
            }

            if (MakeComm(LAdr,Text) != 1)
            {
               Message("Err: MakeComm() at adr %08X - %s\n",LAdr,Text);
            }
            else
            {
               Message("Commented at Adr %08X - %s\n",LAdr,Text);
               MarkPosition(LAdr,0,0,0,Idx,Text);
            }
         }
      }
   }

   fclose(Handle);

   Warning("Done");
}

/* ******************************************************************** **
**                End of File
** ******************************************************************** */
