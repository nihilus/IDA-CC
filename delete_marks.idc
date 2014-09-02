/* ******************************************************************** **
** @@ DELETE_MARKS.IDC
** @  Copyrt : Aleph
** @  Author : Aleph
** @  Modify :
** @  Update : 14 Sep 2007
** @  Notes  : Simple script to delete ALL marks from IDA database
** ******************************************************************** */

//    BTW, you can save all lines appearing in the messages window to a file.
//    Just set an enviroment variable:
//
//          set IDALOG=ida.log
//
//    I always have this variable set, it is great help in the development.
//
//    Copyright (c) by Ilfak Guilfanov.

//////////////////////////////////////////////////////////////////////////
static main(void)
{
   auto     MAX_SLOT;
   
   auto     Idx;
   auto     Pos;

   MAX_SLOT = 1024;
   Idx      = 0;

   for (Idx = MAX_SLOT; Idx > 0; --Idx)
   {
      Pos = GetMarkedPos(Idx);

      if ( Pos != -1)
      {
         MarkPosition(Pos,0,0,0,Idx,"");
      }
   }

   Warning("Done");
}

/* ******************************************************************** **
**                End of File
** ******************************************************************** */
