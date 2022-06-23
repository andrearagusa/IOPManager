/*******************************************************************
                            IOP Manager
Copyright (C) 2019 Andrea Ragusa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
********************************************************************/

#include "ZipArchive/ZipArchive.h"
#include "ZipArchive/ZipAbstractFile.h"
#include <iostream>
#include <list>
#include <string>
#include <sstream>
#include <io.h>
#include <string>
#include <direct.h>
#include <list>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <experimental/filesystem>

#define MAX_PASSWORD 20

BOOL DirectoryExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
            (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void createDirectoryRecursively(std::string path)
{
    unsigned int pos = 0;
    do
    {
        pos = path.find_first_of("\\/", pos + 1);
        CreateDirectory(path.substr(0, pos).c_str(), NULL);
    }
    while (pos != std::string::npos);
}

inline void ProgressBar(float progress)
{
    static float oldProgress = 0;

    if (progress - oldProgress >= 0.01)
    {
        int barWidth = 50;

        std::cout << "[";
        int pos = barWidth * progress;
        for (int i = 0; i < barWidth; ++i)
        {
            if (i < pos)
                std::cout << "=";
            else if (i == pos)
                std::cout << ">";
            else
                std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << " %\r";
        std::cout.flush();
        oldProgress = progress;
    }
}

void EncryptDecryptData( OUT char *szResultData, IN const int iResultSize, IN const char *szSourceData, IN const int iSourceSize, IN bool bPassword )
{
    enum { MAX_KEY_TYPE = 2,  MAX_KEY = 30, };
    BYTE byKey[MAX_KEY_TYPE][MAX_KEY]= {255,1,2,9,89,32,123,39,34,211,222,244,100,129,23,1,4,3,29,30,1,4,5,7,8,233,89,1,98,67,
                                        48,29,96,1,9,48,57,213,178,123,67,90,2,4,254,255,6,8,9,23,90,44,214,199,108,119,3,2,2};
    int iKeyType = 0;
    if( !bPassword )
        iKeyType = 1;

    for(int i =0; i < iSourceSize; i++)
    {
        if( i >= iResultSize )
            break;
        szResultData[i] = szSourceData[i] ^ byKey[iKeyType][i%MAX_KEY];
        szResultData[i] = szResultData[i] ^ byKey[iKeyType][(iSourceSize-i)%MAX_KEY];
    }
}

char *GetPacPassword(CZipArchive &mZip)
{
    static char szEncPW[MAX_PASSWORD+1];
    CZipFileHeader header;
    CZipMemFile mfOut;
    int isFile = 0;

    char szPWList[20][MAX_PASSWORD] =
    {
        { -105, 112, 108, 127, 62, 66, 9, -43, 53, 4, 64, 39, 70, -90, 108, 33, 93, 10, 31, 31 },
        { -90, 109, 89, 120, 20, 17, 73, -107, 4, 97, 37, 6, 118, -30, 15, 89, 121, 57, 47, 50 },
        { -101, 90, 44, 51, 25, 74, 41, -121, 99, 98, 48, 39, 70, -90, 108, 33, 93, 10, 31, 31 },
        { -69, 120, 58, 84, 52, 78, 92, -107, 19, 115, 36, 100, 48, -64, 85, 19, 108, 39, 62, 59 },
        { -69, 121, 122, 110, 59, 16, 94, -117, 7, 84, 118, 39, 70, -90, 108, 33, 93, 10, 31, 31 },
        { -104, 122, 120, 77, 112, 19, 88, -41, 49, 4, 35, 19, 34, -64, 9, 20, 111, 47, 44, 53 },
        { -102, 106, 108, 43, 44, 73, 8, -57, 45, 84, 108, 39, 70, -90, 108, 33, 93, 10, 31, 31 },
        { -118, 116, 123, 96, 44, 80, 2, -121, 34, 75, 102, 98, 46, -44, 29, 74, 59, 98, 120, 112 },
        { -105, 74, 75, 57, 101, 2, 44, -110, 127, 81, 110, 97, 34, -52, 10, 8, 117, 62, 108, 120 },
        { -89, 118, 60, 125, 56, 117, 73, -8, 127, 23, 51, 114, 40, -48, 92, 5, 111, 109, 121, 117 },
        { -86, 53, 59, 108, 105, 17, 42, -12, 44, 65, 111, 66, 108, -114, 10, 77, 110, 58, 43, 123 },
        { -77, 121, 122, 46, 120, 19, 92, -110, 127, 66, 70, 66, 41, -62, 7, 11, 123, 57, 46, 69 },
        { -69, 91, 120, 111, 52, 4, 50, -62, 32, 30, 51, 23, 99, -123, 10, 75, 124, 85, 34, 66 },
        { -66, 40, 59, 109, 55, 117, 62, -44, 35, 78, 101, 122, 29, -121, 95, 19, 110, 69, 52, 52 },
        { -69, 91, 120, 111, 52, 4, 50, -62, 32, 30, 51, 23, 99, -123, 10, 75, 124, 85, 34, 66 },
        { -66, 40, 59, 109, 55, 117, 62, -44, 35, 78, 101, 122, 29, -121, 95, 19, 110, 69, 52, 52 },
        { -75, 44, 59, 110, 49, 82, 88, -97, 31, 114, 35, 3, 101, -61, 3, 100, 110, 58, 42, 43 },
        { -45, 64, 43, 51, 104, 104, 57, -29, 16, 109, 100, 75, 53, -54, 71, 10, 110, 56, 122, 123 },
        { -45, 54, 43, 94, 15, 71, 7, -54, 107, 19, 49, 3, 99, -62, 11, 74, 47, 103, 47, 42 },
        { -126, 47, 42, 51, 47, 85, 25, -31, 20, 66, 111, 80, 41, -26, 79, 2, 41, 97, 120, 47 }
    };

    if (!mZip.GetCount())
        return NULL;

    while (mZip.GetCount() >= isFile)
    {
        mZip.GetFileInfo( header, isFile );
        if( header.IsDirectory() )
        {
            isFile++;
            continue;
        }
        else
            break;
    }

    for (int k = 0; k < 20; k++)
    {
        memset(szEncPW, 0, sizeof szEncPW);
        EncryptDecryptData( szEncPW, MAX_PASSWORD, szPWList[k], MAX_PASSWORD, true );
        try
        {
            mZip.SetPassword( szEncPW );
            mZip.ExtractFile(isFile, mfOut);

            std::cout << "The password is: " << szEncPW << std::endl;

            return szEncPW;
        }
        catch( CZipException & ex )	{ ;	}
    }
    std::cout << "Password not found" << std::endl;
    return NULL;
}

void Compress(std::string ArchiveName, std::string inFolder, const char Password[])
{
    CZipArchive mZip;
    std::vector<std::string> vecFiles;
    int numFiles;
    float Prog = 1.0;

    if (!Password)
    {
        std::cout << "You must specify a password when creating an archive" << std::endl;
        return;
    }

    if (!DirectoryExists(inFolder.c_str()))
    {
        std::cout << "The specified folder does not exist" << std::endl;
        return;
    }

    try
    {
        mZip.Open( ArchiveName.c_str(), CZipArchive::zipCreate );
        mZip.SetPassword( Password );
    }
    catch( CZipException & ex )
    {
        std::cout << ex.GetErrorDescription() << std::endl;
    }

    for(auto& p: std::experimental::filesystem::recursive_directory_iterator(inFolder))
        vecFiles.push_back(p.path().string());

    numFiles = vecFiles.size();

    if (!numFiles)
    {
        std::cout << "The specified folder is empty" << std::endl;
        return;
    }

    try
    {
        for( int k = 0; k < numFiles; ++k )
        {
            mZip.AddNewFile( vecFiles[k].c_str(), vecFiles[k].substr(inFolder.size()).c_str() );

            Prog = (float) k / numFiles;
            ProgressBar(Prog + 0.01);
        }
    }
    catch( CZipException & ex )
    {
        std::cout << ex.GetErrorDescription() << std::endl;
    }
    mZip.Close();
}

void Extract(std::string ArchiveName, std::string outFolder, const char Password[])
{
    CZipArchive mZip;
    CZipFileHeader header;
    CZipMemFile mfOut;

    std::string strFolder;
    float Prog = 1.0;

    try
    {
        mZip.Open(ArchiveName.c_str(), CZipArchive::zipOpenReadOnly);

        if(mZip.GetCount() < 1)
        {
            printf("The specified iop file is empty\n");
            return;
        }

        //GetPacPassword(mZip);

        if (Password)
            mZip.SetPassword( Password );
        else
            mZip.SetPassword( GetPacPassword(mZip) );

        for( int x = 0; x < mZip.GetCount(); ++x )
        {
            CZipFileHeader header;
            mZip.GetFileInfo( header, static_cast< WORD >( x ) );
            if( header.IsDirectory() )
                continue;

            strFolder = header.GetFileName();
            //std::cout << header.GetFileName() << " found" << std::endl;
            size_t pos = strFolder.find_last_of("\\");
            if (pos != std::string::npos)
            {
                strFolder = strFolder.substr(0, pos);

                if (!DirectoryExists((outFolder + strFolder).c_str()))
                    createDirectoryRecursively(outFolder + strFolder);
            }
        }

        for( int x = 0; x < mZip.GetCount(); ++x )
        {
            mZip.GetFileInfo( header, x );
            if( header.IsDirectory() )
                continue;

            Prog = (float) x / mZip.GetCount();
            ProgressBar(Prog + 0.01);

            mZip.ExtractFile( x, outFolder.c_str());

            if (header.GetFileName().compare(header.GetFileName().find_first_of("."), 4, ".ini") == 0 && header.GetComment() == "1" )
            {
                FILE *fp = fopen((outFolder + header.GetFileName()).c_str(), "r+b");
                fseek(fp, 0, SEEK_END);
                int size = ftell(fp);
                char *mBuf = new char[size];
                fseek(fp, 0, SEEK_SET);
                fread(mBuf, 1, size, fp);
                EncryptDecryptData(mBuf, size, mBuf, size, false);
                fseek(fp, 0, SEEK_SET);
                fwrite(mBuf, 1, size, fp);
                fclose(fp);
                delete[] mBuf;
            }
        }
        mZip.Close();
        ProgressBar(1.0);
    }
    catch( CZipException & ex )
    {
        std::cout << ex.GetErrorDescription() << std::endl;
    }
}

int main(int argc, const char* argv[])
{

    std::string ArchiveName;
    std::string WorkFolder;
    const char *Password = NULL;

    printf("IOP Manager\n");

    if (argc < 4)
        goto usage;

    ArchiveName = argv[2];
    WorkFolder = argv[3];

    if (WorkFolder[WorkFolder.length()] != '\\')
        WorkFolder += "\\";

    if (argc == 5)
        Password = argv[4];

    if (!strncmp(argv[1], "-c", 2))
        Compress(ArchiveName, WorkFolder, Password);

    else if (!strncmp(argv[1], "-d", 2))
        Extract(ArchiveName, WorkFolder, Password);

    else
        goto usage;

    std::cout << std::endl << "Done! \\o/" << std::endl;

    return 0;

usage:
    printf("Usage:\n"
           "\tTo decompress - %s -d archive.iop output_folder [password]\n"
           "\tor\n"
           "\tTo compress - %s -c archive.iop input_folder password\n", argv[0], argv[0]);
}
