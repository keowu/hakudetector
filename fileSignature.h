#ifndef FILESIGNATURE_H
#define FILESIGNATURE_H

#include <QDialog>
#include <QtDebug>

class FileSignature{

public:
    QString fileSignature(QByteArray a, QString* sign){
        if(!(a.size() > 3)){
            qDebug() << "Image size not is better than 3";
            return " ";
        }

        if(a.at(0) == 0x4D && a.at(1) == 0x5A){
            sign[0] = 'M';
            sign[1] = 'Z';
            qDebug() << "DOS MZ executable file format and its descendants (including NE and PE)";
            return "DOS MZ executable file format and its descendants (including NE and PE)";
        }else if(a.at(0) == 0x50 && a.at(1) == 0x4B && a.at(2) == 0x03 && a.at(3) == 0x04){
            sign[0] = 'P';
            sign[1] = 'K';
            qDebug() << "ZIP, aar, apk, docx, epub, ipa, jar, kmz, maff, odp, ods, odt, pk3, pk4, pptx, usdz, vsdx, xlsx, xpi";
            return "ZIP, aar, apk, docx, epub, ipa, jar, kmz, maff, odp, ods, odt, pk3, pk4, pptx, usdz, vsdx, xlsx, xpi";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xFF) && ((unsigned char)a.at(1) == (unsigned char)0xD8)
                 && ((unsigned char)a.at(2) == (unsigned char)0xFF) && ((unsigned char)a.at(3) == (unsigned char)0xDB)){
            sign[0] = 'J';
            sign[1] = 'P';
            sign[2] = 'G';
            qDebug() << "JPG OR JPEG IMAGE FILE";
            return "JPG OR JPEG IMAGE FILE";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xFF) && ((unsigned char)a.at(1) == (unsigned char)0xD8)
                 && ((unsigned char)a.at(2) == (unsigned char)0xFF) && ((unsigned char)a.at(3) == (unsigned char)0xE0)
                 && ((unsigned char)a.at(4) == (unsigned char)0x00) && ((unsigned char)a.at(5) == (unsigned char)0x10)
                 && ((unsigned char)a.at(6) == (unsigned char)0x4A) && ((unsigned char)a.at(7) == (unsigned char)0x46)
                 && ((unsigned char)a.at(8) == (unsigned char)0x49) && ((unsigned char)a.at(9) == (unsigned char)0x46)
                 && ((unsigned char)a.at(10) == (unsigned char)0x00) && ((unsigned char)a.at(11) == (unsigned char)0x01)){
            sign[0] = 'J';
            sign[1] = 'P';
            sign[2] = 'G';
            qDebug() << "JPG OR JPEG IMAGE FILE";
            return "JPG OR JPEG IMAGE FILE";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x89) && ((unsigned char)a.at(1) == (unsigned char)0x50)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4e) && ((unsigned char)a.at(3) == (unsigned char)0x47)){
            sign[0] = 'P';
            sign[1] = 'N';
            sign[2] = 'G';
            qDebug() << "PNG IMAGE FILE";
            return "PNG IMAGE FILE";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x47) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x38)
                 && ((unsigned char)a.at(5) == (unsigned char)0x61)){
            if(((unsigned char)a.at(4) == (unsigned char)0x37)){
                sign[0] = 'G';
                sign[1] = 'I';
                sign[2] = 'F';
                sign[3] = '1';
                qDebug() << "PNG IMAGE FILE 1º Generation";
                return "PNG IMAGE FILE 1º Generation";
            }else{
                //&& ((unsigned char)a.at(4) == (unsigned char)0x39)
                sign[0] = 'G';
                sign[1] = 'I';
                sign[2] = 'F';
                sign[3] = '2';
                qDebug() << "PNG IMAGE FILE 2º Generation";
                return "PNG IMAGE FILE 2º Generation";
            }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x5A) && ((unsigned char)a.at(1) == (unsigned char)0x4D)){
              sign[0] = 'Z';
              sign[1] = 'M';
              qDebug() << "DOS ZM executable file format and its descendants (rare)";
              return "DOS ZM executable file format and its descendants (rare)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x7F) && ((unsigned char)a.at(1) == (unsigned char)0x45)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4C) && ((unsigned char)a.at(3) == (unsigned char)0x46)){
            sign[0] = '.';
            sign[1] = 'E';
            sign[2] = 'L';
            sign[3] = 'F';
            qDebug() << "Executable and Linkable Format";
            return "Executable and Linkable Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x21) && ((unsigned char)a.at(1) == (unsigned char)0x3C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x61) && ((unsigned char)a.at(3) == (unsigned char)0x72)
                 && ((unsigned char)a.at(4) == (unsigned char)0x63) && ((unsigned char)a.at(5) == (unsigned char)0x68)
                 && ((unsigned char)a.at(6) == (unsigned char)0x3E)){
            sign[0] = 'D';
            sign[1] = 'E';
            sign[2] = 'B';
            qDebug() << "linux deb file";
            return "linux deb file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x61)
                 && ((unsigned char)a.at(2) == (unsigned char)0x72) && ((unsigned char)a.at(3) == (unsigned char)0x21)
                 && ((unsigned char)a.at(4) == (unsigned char)0x1A) && ((unsigned char)a.at(5) == (unsigned char)0x07)){
               if(((unsigned char)a.at(6) == (unsigned char)0x01) && ((unsigned char)a.at(7) == (unsigned char)0x00)){
                   sign[0] = 'R';
                   sign[1] = 'A';
                   sign[2] = 'R';
                   sign[3] = '5';
                   qDebug() << "RAR archive version 5.0 onwards";
                   return "RAR archive version 5.0 onwards";
               }else{
                   sign[0] = 'R';
                   sign[1] = 'A';
                   sign[2] = 'R';
                   sign[3] = '1';
                   qDebug() << "RAR archive version 1.50 onwards";
                   return "RAR archive version 1.50 onwards";
               }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x37) && ((unsigned char)a.at(1) == (unsigned char)0x7A)
                 && ((unsigned char)a.at(2) == (unsigned char)0xBC) && ((unsigned char)a.at(3) == (unsigned char)0xAF)
                 && ((unsigned char)a.at(4) == (unsigned char)0x27) && ((unsigned char)a.at(5) == (unsigned char)0x1C)){
            sign[0] = '7';
            sign[1] = 'Z';
            sign[2] = 'I';
            sign[3] = 'P';
            qDebug() << "7-Zip File Format";
            return "7-Zip File Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x25) && ((unsigned char)a.at(1) == (unsigned char)0x50)
                 && ((unsigned char)a.at(2) == (unsigned char)0x44) && ((unsigned char)a.at(3) == (unsigned char)0x46)
                 && ((unsigned char)a.at(4) == (unsigned char)0x2d)){
            sign[0] = 'P';
            sign[1] = 'D';
            sign[2] = 'F';
            qDebug() << "PDF document";
            return "PDF document";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x53) && ((unsigned char)a.at(1) == (unsigned char)0x51)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4c) && ((unsigned char)a.at(3) == (unsigned char)0x69)
                 && ((unsigned char)a.at(4) == (unsigned char)0x74) && ((unsigned char)a.at(5) == (unsigned char)0x65)
                 && ((unsigned char)a.at(6) == (unsigned char)0x20) && ((unsigned char)a.at(7) == (unsigned char)0x66)
                 && ((unsigned char)a.at(8) == (unsigned char)0x6f) && ((unsigned char)a.at(9) == (unsigned char)0x72)
                 && ((unsigned char)a.at(10) == (unsigned char)0x6d) && ((unsigned char)a.at(11) == (unsigned char)0x61)
                 && ((unsigned char)a.at(12) == (unsigned char)0x74) && ((unsigned char)a.at(13) == (unsigned char)0x20)
                 && ((unsigned char)a.at(14) == (unsigned char)0x33) && ((unsigned char)a.at(15) == (unsigned char)0x00)){
            sign[0] = 'S';
            sign[1] = 'Q';
            sign[2] = 'L';
            sign[3] = 'T';
            qDebug() << "SQLite Database";
            return "SQLite Database";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x54) && ((unsigned char)a.at(1) == (unsigned char)0x44)){
                if(((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x24)){
                    sign[0] = 'T';
                    sign[1] = 'D';
                    sign[2] = 'F';
                    qDebug() << "Telegram Desktop File";
                    return "Telegram Desktop File";
                }else if(((unsigned char)a.at(2) == (unsigned char)0x45) && ((unsigned char)a.at(3) == (unsigned char)0x46)){
                    sign[0] = 'T';
                    sign[1] = 'D';
                    sign[2] = 'F';
                    sign[3] = 'C';
                    qDebug() << "Telegram Desktop Encrypted File";
                    return "Telegram Desktop Encrypted File";
                }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x58) && ((unsigned char)a.at(1) == (unsigned char)0x46)
                 && ((unsigned char)a.at(2) == (unsigned char)0x49) && ((unsigned char)a.at(3) == (unsigned char)0x52)){
            sign[0] = 'D';
            sign[1] = 'C';
            sign[2] = 'R';
            qDebug() << "Adobe Shockwave";
            return "Adobe Shockwave";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x1B) && ((unsigned char)a.at(1) == (unsigned char)0x4C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x75) && ((unsigned char)a.at(3) == (unsigned char)0x61)){
            sign[0] = 'L';
            sign[1] = 'U';
            sign[2] = 'A';
            qDebug() << "Lua bytecode";
            return "Lua bytecode";
        }else if (((unsigned char)a.at(0) == (unsigned char)0x62) && ((unsigned char)a.at(1) == (unsigned char)0x6F)
                  && ((unsigned char)a.at(2) == (unsigned char)0x6F) && ((unsigned char)a.at(3) == (unsigned char)0x6B)
                  && ((unsigned char)a.at(4) == (unsigned char)0x00) && ((unsigned char)a.at(5) == (unsigned char)0x00)
                  && ((unsigned char)a.at(6) == (unsigned char)0x00) && ((unsigned char)a.at(7) == (unsigned char)0x00)
                  && ((unsigned char)a.at(8) == (unsigned char)0x6D) && ((unsigned char)a.at(9) == (unsigned char)0x61)
                  && ((unsigned char)a.at(10) == (unsigned char)0x72) && ((unsigned char)a.at(11) == (unsigned char)0x6B)
                  && ((unsigned char)a.at(12) == (unsigned char)0x00) && ((unsigned char)a.at(13) == (unsigned char)0x00)
                  && ((unsigned char)a.at(14) == (unsigned char)0x00) && ((unsigned char)a.at(15) == (unsigned char)0x00)){
             sign[0] = 'B';
             sign[1] = 'O';
             sign[2] = 'O';
             sign[3] = 'K';
             qDebug() << "macOS file Alias (Symbolic link)";
             return "macOS file Alias (Symbolic link)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x1F) && ((unsigned char)a.at(1) == (unsigned char)0x8B)){
            sign[0] = 'G';
            sign[1] = 'Z';
            qDebug() << "GZIP compressed file";
            return "GZIP compressed file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x75) && ((unsigned char)a.at(1) == (unsigned char)0x73)
                 && ((unsigned char)a.at(2) == (unsigned char)0x74) && ((unsigned char)a.at(3) == (unsigned char)0x61)
                 && ((unsigned char)a.at(4) == (unsigned char)0x72)){
            if(((unsigned char)a.at(5) == (unsigned char)0x00) && ((unsigned char)a.at(6) == (unsigned char)0x30) && ((unsigned char)a.at(7) == (unsigned char)0x30)){
                sign[0] = 'T';
                sign[1] = 'A';
                sign[2] = 'R';
                sign[3] = '1';
                qDebug() << "tar archive 1º Generation";
                return "tar archive 1º Generation";
            }else if(((unsigned char)a.at(5) == (unsigned char)0x20) && ((unsigned char)a.at(6) == (unsigned char)0x20) && ((unsigned char)a.at(7) == (unsigned char)0x00)){
                sign[0] = 'T';
                sign[1] = 'A';
                sign[2] = 'R';
                sign[3] = '2';
                qDebug() << "tar archive 2º Generation";
                return "tar archive 2º Generation";
            }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x43) && ((unsigned char)a.at(1) == (unsigned char)0x44)
                 && ((unsigned char)a.at(2) == (unsigned char)0x30) && ((unsigned char)a.at(3) == (unsigned char)0x30)
                 && ((unsigned char)a.at(4) == (unsigned char)0x31)){
                sign[0] = 'I';
                sign[1] = 'S';
                sign[2] = 'O';
                qDebug() << "ISO9660 CD/DVD image file";
                return "ISO9660 CD/DVD image file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x49) && ((unsigned char)a.at(1) == (unsigned char)0x44)
                && ((unsigned char)a.at(2) == (unsigned char)0x33)){
                sign[0] = 'M';
                sign[1] = 'P';
                sign[2] = '3';
                qDebug() << "MP3 file with an ID3v2 container";
                return "MP3 file with an ID3v2 container";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xFF)){
                if(((unsigned char)a.at(1) == (unsigned char)0xFB)){
                    sign[0] = 'M';
                    sign[1] = 'P';
                    sign[2] = '3';
                    sign[3] = '1';
                    qDebug() << "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                    return "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                }else if(((unsigned char)a.at(1) == (unsigned char)0xF3)){
                    sign[0] = 'M';
                    sign[1] = 'P';
                    sign[2] = '3';
                    sign[3] = '2';
                    qDebug() << "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                    return "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                }else if(((unsigned char)a.at(1) == (unsigned char)0xF2)){
                    sign[0] = 'M';
                    sign[1] = 'P';
                    sign[2] = '3';
                    sign[3] = '3';
                    qDebug() << "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                    return "MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag (which's appended at the end of the file)";
                }
        // 0  1  2  3  4  5  6 7  8  9  10 11
        //52 49 46 46 ?? ?? ?? ?? 57 41 56 45
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x46)
                 && ((unsigned char)a.at(8) == (unsigned char)0x57) && ((unsigned char)a.at(9) == (unsigned char)0x41)
                 && ((unsigned char)a.at(10) == (unsigned char)0x56) && ((unsigned char)a.at(11) == (unsigned char)0x45)){
               sign[0] = 'W';
               sign[1] = 'A';
               sign[2] = 'V';
               qDebug() << "Waveform Audio File Format";
               return "Waveform Audio File Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4F) && ((unsigned char)a.at(1) == (unsigned char)0x67)
                 && ((unsigned char)a.at(2) == (unsigned char)0x67) && ((unsigned char)a.at(3) == (unsigned char)0x53)){
              sign[0] = 'O';
              sign[1] = 'g';
              sign[2] = 'g';
              sign[3] = 'S';
              qDebug() << "Ogg, an open source media container format";
              return "Ogg, an open source media container format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xCA) && ((unsigned char)a.at(1) == (unsigned char)0xFE)
                 && ((unsigned char)a.at(2) == (unsigned char)0xBA) && ((unsigned char)a.at(3) == (unsigned char)0xBE)){
              sign[0] = 'C';
              sign[1] = 'L';
              sign[2] = 'A';
              sign[3] = 'S';
              qDebug() << "Java class file, Mach-O Fat Binary";
              return "Java class file, Mach-O Fat Binary";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4C) && ((unsigned char)a.at(1) == (unsigned char)0x5A)
                 && ((unsigned char)a.at(2) == (unsigned char)0x49) && ((unsigned char)a.at(3) == (unsigned char)0x50)){
              sign[0] = 'L';
              sign[1] = 'Z';
              qDebug() << "lzip compressed file";
              return "lzip compressed file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x41) && ((unsigned char)a.at(9) == (unsigned char)0x43)
                 && ((unsigned char)a.at(10) == (unsigned char)0x42) && ((unsigned char)a.at(11) == (unsigned char)0x4D)){
              sign[0] = 'A';
              sign[1] = 'C';
              sign[2] = 'B';
              sign[3] = 'M';
              qDebug() << "Amiga Contiguous Bitmap";
              return "Amiga Contiguous Bitmap";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xBE) && ((unsigned char)a.at(1) == (unsigned char)0xBA)
                 && ((unsigned char)a.at(2) == (unsigned char)0xFE) && ((unsigned char)a.at(3) == (unsigned char)0xCA)){
              sign[0] = 'D';
              sign[1] = 'B';
              sign[2] = 'A';
              sign[3] = '1';
              qDebug() << "Palm Desktop Calendar Archive";
              return "Palm Desktop Calendar Archive";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x01)
                 && ((unsigned char)a.at(2) == (unsigned char)0x44) && ((unsigned char)a.at(3) == (unsigned char)0x54)){
              sign[0] = 'T';
              sign[1] = 'D';
              sign[2] = 'A';
              qDebug() << "Palm Desktop Calendar Archive";
              return "Palm Desktop Calendar Archive";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xED) && ((unsigned char)a.at(1) == (unsigned char)0xAB)
                 && ((unsigned char)a.at(2) == (unsigned char)0xEE) && ((unsigned char)a.at(3) == (unsigned char)0xDB)){
              sign[0] = 'R';
              sign[1] = 'P';
              sign[2] = 'M';
              qDebug() << "RedHat Package Manager (RPM) package";
              return "RedHat Package Manager (RPM) package";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x53) && ((unsigned char)a.at(1) == (unsigned char)0x50)
                 && ((unsigned char)a.at(2) == (unsigned char)0x30) && ((unsigned char)a.at(3) == (unsigned char)0x31)){
              sign[0] = 'B';
              sign[1] = 'I';
              sign[2] = 'N';
              qDebug() << "Amazon Kindle Update Package";
              return "Amazon Kindle Update Package";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x01)
                 && ((unsigned char)a.at(2) == (unsigned char)0x42) && ((unsigned char)a.at(3) == (unsigned char)0x44)){
              sign[0] = 'D';
              sign[1] = 'B';
              sign[2] = 'A';
              qDebug() << "Palm Desktop To Do Archive";
              return "Palm Desktop To Do Archive";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x00)
                 && ((unsigned char)a.at(2) == (unsigned char)0x00) && ((unsigned char)a.at(3) == (unsigned char)0x00)
                 && ((unsigned char)a.at(4) == (unsigned char)0x00) && ((unsigned char)a.at(5) == (unsigned char)0x00)
                 && ((unsigned char)a.at(6) == (unsigned char)0x00) && ((unsigned char)a.at(7) == (unsigned char)0x00)
                 && ((unsigned char)a.at(8) == (unsigned char)0x00) && ((unsigned char)a.at(9) == (unsigned char)0x00)
                 && ((unsigned char)a.at(10) == (unsigned char)0x00)){
            //00 00 00 00 00 00 00 00
            //00 00 00 00 00 00 00 00
            //00 00 00 00 00 00 00 00
            //24 bytes with 23 postion with 0
            //It is not necessary to implement all possible possibilities,
            //as no other file can start with this signature,
            //it can be removed in the future given feedback from the community!
             sign[0] = 'P';
             sign[1] = 'D';
             sign[2] = 'B';
             qDebug() << "PalmPilot Database/Document File";
             return "PalmPilot Database/Document File";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x00)
                 && ((unsigned char)a.at(2) == (unsigned char)0x00) && ((unsigned char)a.at(3) == (unsigned char)0x18)
                 && ((unsigned char)a.at(4) == (unsigned char)0x66) && ((unsigned char)a.at(5) == (unsigned char)0x74)
                 && ((unsigned char)a.at(6) == (unsigned char)0x79) && ((unsigned char)a.at(7) == (unsigned char)0x70)
                 && ((unsigned char)a.at(8) == (unsigned char)0x69) && ((unsigned char)a.at(9) == (unsigned char)0x73)
                 && ((unsigned char)a.at(10) == (unsigned char)0x6F) && ((unsigned char)a.at(11) == (unsigned char)0x6D)){
            sign[0] = 'M';
            sign[1] = 'P';
            sign[2] = '4';
            qDebug() << "ISO Base Media file (MPEG-4)";
            return "ISO Base Media file (MPEG-4)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x00)
                 && ((unsigned char)a.at(2) == (unsigned char)0x01) && ((unsigned char)a.at(3) == (unsigned char)0xBA)){
            sign[0] = 'M';
            sign[1] = '2';
            sign[2] = 'P';
            qDebug() << "MPEG Program Stream (MPEG-1 Part 1 (essentially identical) and MPEG-2 Part 1)";
            return "MPEG Program Stream (MPEG-1 Part 1 (essentially identical) and MPEG-2 Part 1)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x7B) && ((unsigned char)a.at(1) == (unsigned char)0x5C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x72) && ((unsigned char)a.at(3) == (unsigned char)0x74)
                 && ((unsigned char)a.at(4) == (unsigned char)0x66) && ((unsigned char)a.at(5) == (unsigned char)0x31)){
            sign[0] = 'R';
            sign[1] = 'T';
            sign[2] = 'F';
            qDebug() << "Rich Text Format";
            return "Rich Text Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x27) && ((unsigned char)a.at(1) == (unsigned char)0x05)
                 && ((unsigned char)a.at(2) == (unsigned char)0x19) && ((unsigned char)a.at(3) == (unsigned char)0x56)){
            sign[0] = 'U';
            sign[1] = 'B';
            sign[2] = 'T';
            qDebug() << "U-Boot / uImage. Das U-Boot Universal Boot Loader";
            return "U-Boot / uImage. Das U-Boot Universal Boot Loader";
        }else if((((unsigned char)a.at(0) == (unsigned char)0x43) && ((unsigned char)a.at(1) == (unsigned char)0x57)
                 && ((unsigned char)a.at(2) == (unsigned char)0x53)) || (((unsigned char)a.at(0) == (unsigned char)0x46)
                && ((unsigned char)a.at(1) == (unsigned char)0x57) && ((unsigned char)a.at(2) == (unsigned char)0x53))){
            sign[0] = 'S';
            sign[1] = 'W';
            sign[2] = 'F';
            qDebug() << "flash .swf";
            return "flash .swf";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x61)
                 && ((unsigned char)a.at(2) == (unsigned char)0x73) && ((unsigned char)a.at(3) == (unsigned char)0x6d)){
            sign[0] = 'W';
            sign[1] = 'A';
            sign[2] = 'S';
            qDebug() << "WebAssembly binary format";
            return "WebAssembly binary format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x42) && ((unsigned char)a.at(1) == (unsigned char)0x4D)){
            sign[0] = 'B';
            sign[1] = 'M';
            sign[2] = 'P';
            qDebug() << "BMP file, a bitmap format used mostly in the Windows world";
            return "BMP file, a bitmap format used mostly in the Windows world";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x46)
                 && ((unsigned char)a.at(8) == (unsigned char)0x41) && ((unsigned char)a.at(9) == (unsigned char)0x56)
                 && ((unsigned char)a.at(10) == (unsigned char)0x49) && ((unsigned char)a.at(11) == (unsigned char)0x20)){
            sign[0] = 'A';
            sign[1] = 'V';
            sign[2] = 'I';
            qDebug() << "Audio Video Interleave video format";
            return "Audio Video Interleave video format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x46) && ((unsigned char)a.at(9) == (unsigned char)0x41)
                 && ((unsigned char)a.at(10) == (unsigned char)0x4E) && ((unsigned char)a.at(11) == (unsigned char)0x54)){
            sign[0] = 'I';
            sign[1] = 'F';
            sign[2] = 'F';
            qDebug() << "Amiga Fantavision Movie";
            return "Amiga Fantavision Movie";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x76) && ((unsigned char)a.at(1) == (unsigned char)0x2F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x31) && ((unsigned char)a.at(3) == (unsigned char)0x01)){
            sign[0] = 'E';
            sign[1] = 'X';
            sign[2] = 'R';
            qDebug() << "OpenEXR image";
            return "OpenEXR image";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x38) & ((unsigned char)a.at(1) == (unsigned char)0x42)
                 && ((unsigned char)a.at(2) == (unsigned char)0x50) && ((unsigned char)a.at(3) == (unsigned char)0x53)){
            sign[0] = 'P';
            sign[1] = 'S';
            sign[2] = 'D';
            qDebug() << "Photoshop Document file, Adobe Photoshop's native file format";
            return "Photoshop Document file, Adobe Photoshop's native file format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xCF) && ((unsigned char)a.at(1) == (unsigned char)0x84)
                 && ((unsigned char)a.at(2) == (unsigned char)0x01)){
            sign[0] = 'L';
            sign[1] = 'E';
            sign[2] = 'P';
            qDebug() << "Lepton compressed JPEG image";
            return "Lepton compressed JPEG image";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4D) && ((unsigned char)a.at(1) == (unsigned char)0x53)
                 && ((unsigned char)a.at(2) == (unsigned char)0x43) && ((unsigned char)a.at(3) == (unsigned char)0x46)){
            sign[0] = 'C';
            sign[1] = 'A';
            sign[2] = 'B';
            qDebug() << "Microsoft Cabinet file";
            return "Microsoft Cabinet file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4F) && ((unsigned char)a.at(1) == (unsigned char)0x41)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52)){
            //In the future the byte of position 3 is the version of the file, it may be added in the future, be free to modify if necessary !
            sign[0] = 'O';
            sign[1] = 'A';
            sign[2] = 'R';
            qDebug() << "OAR file archive format";
            return "OAR file archive format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x80) && ((unsigned char)a.at(1) == (unsigned char)0x2A)
                 && ((unsigned char)a.at(2) == (unsigned char)0x5F) && ((unsigned char)a.at(3) == (unsigned char)0xD7)){
            sign[0] = 'C';
            sign[1] = 'I';
            sign[2] = 'N';
            qDebug() << "Kodak Cineon image";
            return "Kodak Cineon image";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x3C) && ((unsigned char)a.at(1) == (unsigned char)0x3F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x78) && ((unsigned char)a.at(3) == (unsigned char)0x6D)
                 && ((unsigned char)a.at(4) == (unsigned char)0x6C) && ((unsigned char)a.at(5) == (unsigned char)0x20)){
            sign[0] = 'X';
            sign[1] = 'M';
            sign[2] = 'L';
            qDebug() << "eXtensible Markup Language when using the ASCII character encoding";
            return "eXtensible Markup Language when using the ASCII character encoding";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x65)
                 && ((unsigned char)a.at(2) == (unsigned char)0x63) && ((unsigned char)a.at(3) == (unsigned char)0x65)
                 && ((unsigned char)a.at(4) == (unsigned char)0x69) && ((unsigned char)a.at(5) == (unsigned char)0x76)
                 && ((unsigned char)a.at(6) == (unsigned char)0x65) && ((unsigned char)a.at(7) == (unsigned char)0x64)){
            sign[0] = 'E';
            sign[1] = 'M';
            sign[2] = 'L';
            qDebug() << "Email Message var5";
            return "Email Message var5";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x74) && ((unsigned char)a.at(1) == (unsigned char)0x6F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x78) && ((unsigned char)a.at(3) == (unsigned char)0x33)){
            sign[0] = 'T';
            sign[1] = 'O';
            sign[2] = 'X';
            qDebug() << "Open source portable voxel file";
            return "Open source portable voxel file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x41) && ((unsigned char)a.at(1) == (unsigned char)0x47)
                 && ((unsigned char)a.at(2) == (unsigned char)0x44) & ((unsigned char)a.at(3) == (unsigned char)0x33)){
            sign[0] = 'F';
            sign[1] = 'H';
            sign[2] = '8';
            qDebug() << "FreeHand 8 document";
            return "FreeHand 8 document";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4F) && ((unsigned char)a.at(1) == (unsigned char)0x52)
                 && ((unsigned char)a.at(2) == (unsigned char)0x43)){
            sign[0] = 'O';
            sign[1] = 'R';
            sign[2] = 'C';
            qDebug() << "Apache ORC (Optimized Row Columnar) file format";
            return "Apache ORC (Optimized Row Columnar) file format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x37) && ((unsigned char)a.at(1) == (unsigned char)0x48)
                 && ((unsigned char)a.at(2) == (unsigned char)0x03) && ((unsigned char)a.at(3) == (unsigned char)0x02)
                 && ((unsigned char)a.at(4) == (unsigned char)0x00) && ((unsigned char)a.at(5) == (unsigned char)0x00)
                 && ((unsigned char)a.at(6) == (unsigned char)0x00) && ((unsigned char)a.at(7) == (unsigned char)0x00)
                 && ((unsigned char)a.at(8) == (unsigned char)0x58) && ((unsigned char)a.at(9) == (unsigned char)0x35)
                 && ((unsigned char)a.at(10) == (unsigned char)0x30) && ((unsigned char)a.at(11) == (unsigned char)0x39)
                 && ((unsigned char)a.at(12) == (unsigned char)0x4B) && ((unsigned char)a.at(13) == (unsigned char)0x45)
                 && ((unsigned char)a.at(14) == (unsigned char)0x59)){
            sign[0] = 'K';
            sign[1] = 'D';
            sign[2] = 'B';
            qDebug() << "KDB file";
            return "KDB file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xEF) && ((unsigned char)a.at(1) == (unsigned char)0xBB)
                 && ((unsigned char)a.at(2) == (unsigned char)0xBF)){
            sign[0] = 'U';
            sign[1] = 'T';
            sign[2] = 'F';
            sign[3] = '8';
            qDebug() << "UTF-8 encoded Unicode byte order mark, commonly seen in text files.";
            return "UTF-8 encoded Unicode byte order mark, commonly seen in text files.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xFE) && ((unsigned char)a.at(1) == (unsigned char)0xED)
                 && ((unsigned char)a.at(2) == (unsigned char)0xFE) && ((unsigned char)a.at(3) == (unsigned char)0xED)){
            sign[0] = 'J';
            sign[1] = 'K';
            sign[2] = 'S';
            qDebug() << "JKS JavakeyStore";
            return "JKS JavakeyStore";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x43) && ((unsigned char)a.at(9) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(10) == (unsigned char)0x55) && ((unsigned char)a.at(11) == (unsigned char)0x53)){
            sign[0] = 'C';
            sign[1] = 'M';
            sign[2] = 'U';
            sign[3] = 'S';
            qDebug() << "IFF Musical Score";
            return "IFF Musical Score";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4D) && ((unsigned char)a.at(1) == (unsigned char)0x4C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x56) && ((unsigned char)a.at(3) == (unsigned char)0x49)){
            sign[0] = 'M';
            sign[1] = 'L';
            sign[2] = 'V';
            qDebug() << "Magic Lantern Video file";
            return "Magic Lantern Video file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4D) && ((unsigned char)a.at(1) == (unsigned char)0x54)
                 && ((unsigned char)a.at(2) == (unsigned char)0x68) && ((unsigned char)a.at(3) == (unsigned char)0x64)){
            sign[0] = 'M';
            sign[1] = 'I';
            sign[2] = 'D';
            qDebug() << "MIDI sound file";
            return "MIDI sound file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x53) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4D) && ((unsigned char)a.at(3) == (unsigned char)0x50)
                 && ((unsigned char)a.at(4) == (unsigned char)0x4C) && ((unsigned char)a.at(5) == (unsigned char)0x45)
                 && ((unsigned char)a.at(6) == (unsigned char)0x20) && ((unsigned char)a.at(7) == (unsigned char)0x20)){
            sign[0] = 'F';
            sign[1] = 'I';
            sign[2] = 'T';
            sign[3] = 'S';
            qDebug() << "Flexible Image Transport System (FITS)";
            return "Flexible Image Transport System (FITS)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x66) && ((unsigned char)a.at(1) == (unsigned char)0x4C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x61) && ((unsigned char)a.at(3) == (unsigned char)0x43)){
            sign[0] = 'F';
            sign[1] = 'L';
            sign[2] = 'A';
            sign[3] = 'C';
            qDebug() << "Free Lossless Audio Codec";
            return "Free Lossless Audio Codec";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x64) && ((unsigned char)a.at(1) == (unsigned char)0x65)
                 && ((unsigned char)a.at(2) == (unsigned char)0x78) && ((unsigned char)a.at(3) == (unsigned char)0x0A)
                 && ((unsigned char)a.at(4) == (unsigned char)0x30) && ((unsigned char)a.at(5) == (unsigned char)0x33)
                 && ((unsigned char)a.at(6) == (unsigned char)0x35) && ((unsigned char)a.at(7) == (unsigned char)0x00)){
            sign[0] = 'D';
            sign[1] = 'E';
            sign[2] = 'X';
            qDebug() << "Dalvik Executable";
            return "Dalvik Executable";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x43) && ((unsigned char)a.at(1) == (unsigned char)0x72)
                 && ((unsigned char)a.at(2) == (unsigned char)0x32) && ((unsigned char)a.at(3) == (unsigned char)0x34)){
            sign[0] = 'C';
            sign[1] = 'R';
            sign[2] = 'X';
            qDebug() << "Google Chrome extension or packaged app";
            return "Google Chrome extension or packaged app";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xA1) && ((unsigned char)a.at(1) == (unsigned char)0xB2)
                 && ((unsigned char)a.at(2) == (unsigned char)0xC3) && ((unsigned char)a.at(3) == (unsigned char)0xD4)){
            sign[0] = 'P';
            sign[1] = 'C';
            sign[2] = 'A';
            sign[3] = 'P';
            qDebug() << "Libpcap File Format 1º Gen";
            return "Libpcap File Format 1º Gen";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xD4) && ((unsigned char)a.at(1) == (unsigned char)0xC3)
                 && ((unsigned char)a.at(2) == (unsigned char)0xB2) && ((unsigned char)a.at(3) == (unsigned char)0xA1)){
            sign[0] = 'P';
            sign[1] = 'C';
            sign[2] = 'A';
            sign[3] = 'P';
            qDebug() << "Libpcap File Format 2º Gen";
            return "Libpcap File Format 2º Gen";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x5B) && ((unsigned char)a.at(1) == (unsigned char)0x5A)
                 && ((unsigned char)a.at(2) == (unsigned char)0x6F) && ((unsigned char)a.at(3) == (unsigned char)0x6E)
                 && ((unsigned char)a.at(4) == (unsigned char)0x65) && ((unsigned char)a.at(5) == (unsigned char)0x54)
                 && ((unsigned char)a.at(6) == (unsigned char)0x72) && ((unsigned char)a.at(7) == (unsigned char)0x61)
                 && ((unsigned char)a.at(8) == (unsigned char)0x6E) && ((unsigned char)a.at(9) == (unsigned char)0x73)
                 && ((unsigned char)a.at(10) == (unsigned char)0x66) && ((unsigned char)a.at(11) == (unsigned char)0x65)
                 && ((unsigned char)a.at(12) == (unsigned char)0x72) && ((unsigned char)a.at(13) == (unsigned char)0x5D)){
            sign[0] = 'I';
            sign[1] = 'D';
            sign[2] = 'E';
            sign[3] = 'N';
            qDebug() << "Microsoft Zone Identifier for URL Security Zones";
            return "Microsoft Zone Identifier for URL Security Zones";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x45) && ((unsigned char)a.at(1) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(2) == (unsigned char)0x58) && ((unsigned char)a.at(3) == (unsigned char)0x32)){
            sign[0] = 'E';
            sign[1] = 'Z';
            sign[2] = '2';
            qDebug() << "Emulator Emaxsynth samples";
            return "Emulator Emaxsynth samples";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x23) && ((unsigned char)a.at(1) == (unsigned char)0x21)){
            sign[0] = 'S';
            sign[1] = 'H';
            sign[2] = 'E';
            qDebug() << "Script or data to be passed to the program following the shebang (#!)";
            return "Script or data to be passed to the program following the shebang (#!)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x31) && ((unsigned char)a.at(1) == (unsigned char)0x0A)
                 && ((unsigned char)a.at(2) == (unsigned char)0x30) && ((unsigned char)a.at(3) == (unsigned char)0x30)){
            sign[0] = 'S';
            sign[1] = 'R';
            sign[2] = 'T';
            qDebug() << "SubRip File";
            return "SubRip File";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x3A) && ((unsigned char)a.at(1) == (unsigned char)0x29)
                 && ((unsigned char)a.at(2) == (unsigned char)0x0A)){
            sign[0] = 'S';
            sign[1] = 'M';
            sign[2] = 'I';
            sign[3] = 'L';
            qDebug() << "Smile file";
            return "Smile file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x20) && ((unsigned char)a.at(1) == (unsigned char)0x02)
                 && ((unsigned char)a.at(2) == (unsigned char)0x01) && ((unsigned char)a.at(3) == (unsigned char)0x62)
                 && ((unsigned char)a.at(4) == (unsigned char)0xA0) && ((unsigned char)a.at(5) == (unsigned char)0x1E)
                 && ((unsigned char)a.at(6) == (unsigned char)0xAB) && ((unsigned char)a.at(7) == (unsigned char)0x07)
                 && ((unsigned char)a.at(8) == (unsigned char)0x02) && ((unsigned char)a.at(9) == (unsigned char)0x00)
                 && ((unsigned char)a.at(10) == (unsigned char)0x00) && ((unsigned char)a.at(11) == (unsigned char)0x00)){
            sign[0] = 'T';
            sign[1] = 'B';
            sign[2] = 'L';
            sign[3] = 'D';
            qDebug() << "Tableau Datasource";
            return "Tableau Datasource";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x55) && ((unsigned char)a.at(1) == (unsigned char)0x55)
                 && ((unsigned char)a.at(2) == (unsigned char)0xAA) && ((unsigned char)a.at(3) == (unsigned char)0xAA)){
            sign[0] = 'P';
            sign[1] = 'H';
            sign[2] = 'C';
            sign[3] = 'P';
            qDebug() << "PhotoCap Vector";
            return "PhotoCap Vector";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x65) && ((unsigned char)a.at(1) == (unsigned char)0x87)
                 && ((unsigned char)a.at(2) == (unsigned char)0x78) && ((unsigned char)a.at(3) == (unsigned char)0x56)){
            sign[0] = 'P';
            sign[1] = 'H';
            sign[2] = 'C';
            sign[3] = 'T';
            qDebug() << "PhotoCap Object Templates";
            return "PhotoCap Object Templates";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4A) && ((unsigned char)a.at(1) == (unsigned char)0x6F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x79) && ((unsigned char)a.at(3) == (unsigned char)0x21)){
            sign[0] = 'J';
            sign[1] = 'O';
            sign[2] = 'Y';
            sign[3] = '!';
            qDebug() << "Preferred Executable Format";
            return "Preferred Executable Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x0A) && ((unsigned char)a.at(1) == (unsigned char)0x0D)
                 && ((unsigned char)a.at(2) == (unsigned char)0x0D) && ((unsigned char)a.at(3) == (unsigned char)0x0A)){
            sign[0] = 'P';
            sign[1] = 'C';
            sign[2] = 'A';
            sign[3] = 'P';
            qDebug() << "PCAP Next Generation Dump File Format";
            return "PCAP Next Generation Dump File Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x46) && ((unsigned char)a.at(9) == (unsigned char)0x41)
                 && ((unsigned char)a.at(10) == (unsigned char)0x58) && ((unsigned char)a.at(11) == (unsigned char)0x58)){
            sign[0] = 'F';
            sign[1] = 'O';
            sign[2] = 'R';
            sign[3] = 'M';
            qDebug() << "IFF Facsimile Image";
            return "IFF Facsimile Image";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x53) && ((unsigned char)a.at(1) == (unsigned char)0x44)
                 && ((unsigned char)a.at(2) == (unsigned char)0x50) && ((unsigned char)a.at(3) == (unsigned char)0x58)){
            sign[0] = 'D';
            sign[1] = 'X';
            sign[2] = 'P';
            qDebug() << "SMPTE DPX image (big-endian format)";
            return "SMPTE DPX image (big-endian format)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x58) && ((unsigned char)a.at(1) == (unsigned char)0x50)
                 && ((unsigned char)a.at(2) == (unsigned char)0x44) && ((unsigned char)a.at(3) == (unsigned char)0x53)){
            sign[0] = 'D';
            sign[1] = 'X';
            sign[2] = 'P';
            qDebug() << "SMPTE DPX image (little-endian format)";
            return "SMPTE DPX image (little-endian format)";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x78) && ((unsigned char)a.at(1) == (unsigned char)0x61)
                 && ((unsigned char)a.at(2) == (unsigned char)0x72) && ((unsigned char)a.at(3) == (unsigned char)0x21)){
            sign[0] = 'X';
            sign[1] = 'A';
            sign[2] = 'R';
            qDebug() << "eXtensible ARchive format";
            return "eXtensible ARchive format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x54) && ((unsigned char)a.at(1) == (unsigned char)0x41)
                 && ((unsigned char)a.at(2) == (unsigned char)0x50) && ((unsigned char)a.at(3) == (unsigned char)0x45)){
            sign[0] = 'T';
            sign[1] = 'A';
            sign[2] = 'P';
            sign[3] = 'E';
            qDebug() << "Microsoft Tape Format";
            return "Microsoft Tape Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x1A) && ((unsigned char)a.at(1) == (unsigned char)0x45)
                 && ((unsigned char)a.at(2) == (unsigned char)0xDF) && ((unsigned char)a.at(3) == (unsigned char)0xA3)){
            sign[0] = 'W';
            sign[1] = 'E';
            sign[2] = 'B';
            sign[3] = 'M';
            qDebug() << "Matroska media container, including WebM";
            return "Matroska media container, including WebM";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4C)
                 && ((unsigned char)a.at(2) == (unsigned char)0x49) && ((unsigned char)a.at(3) == (unsigned char)0x46)){
            sign[0] = 'F';
            sign[1] = 'L';
            sign[2] = 'I';
            sign[3] = 'F';
            qDebug() << "Free Lossless Image Format";
            return "Free Lossless Image Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4E) && ((unsigned char)a.at(1) == (unsigned char)0x45)
                 && ((unsigned char)a.at(2) == (unsigned char)0x53) && ((unsigned char)a.at(3) == (unsigned char)0x1A)){
            sign[0] = 'N';
            sign[1] = 'E';
            sign[2] = 'S';
            qDebug() << "Nintendo Entertainment System ROM file";
            return "Nintendo Entertainment System ROM file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x54) && ((unsigned char)a.at(1) == (unsigned char)0x52)
                 && ((unsigned char)a.at(2) == (unsigned char)0x53) && ((unsigned char)a.at(3) == (unsigned char)0x44)
                 && ((unsigned char)a.at(4) == (unsigned char)0x54)){
            sign[0] = 'T';
            sign[1] = 'R';
            sign[2] = 'S';
            sign[3] = 'D';
            qDebug() << "TRSDT - Trasdata Vehicle Reader";
            return "TRSDT - Trasdata Vehicle Reader";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x50) && ((unsigned char)a.at(1) == (unsigned char)0x43)){
            sign[0] = 'S';
            sign[1] = 'R';
            sign[2] = 'E';
            sign[3] = 'C';
            qDebug() << "S-REC Motorola S-Record";
            return "S-REC Motorola S-Record";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x41) && ((unsigned char)a.at(9) == (unsigned char)0x49)
                 && ((unsigned char)a.at(10) == (unsigned char)0x46) && ((unsigned char)a.at(11) == (unsigned char)0x46)){
            sign[0] = 'F';
            sign[1] = 'O';
            sign[2] = 'R';
            sign[3] = 'M';
            qDebug() << "Audio Interchange File Format";
            return "Audio Interchange File Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x38) && ((unsigned char)a.at(9) == (unsigned char)0x53)
                 && ((unsigned char)a.at(10) == (unsigned char)0x56) && ((unsigned char)a.at(11) == (unsigned char)0x58)){
            sign[0] = 'F';
            sign[1] = 'O';
            sign[2] = 'R';
            sign[3] = 'M';
            qDebug() << "IFF 8-Bit Sampled Voice";
            return "IFF 8-Bit Sampled Voice";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x46) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(8) == (unsigned char)0x49) && ((unsigned char)a.at(9) == (unsigned char)0x4C)
                 && ((unsigned char)a.at(10) == (unsigned char)0x42) && ((unsigned char)a.at(11) == (unsigned char)0x4D)){
            sign[0] = 'I';
            sign[1] = 'L';
            sign[2] = 'B';
            sign[3] = 'M';
            qDebug() << "IFF Interleaved Bitmap Image";
            return "IFF Interleaved Bitmap Image";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x49) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x2A) && ((unsigned char)a.at(3) == (unsigned char)0x00)
                 && ((unsigned char)a.at(4) == (unsigned char)0x10) && ((unsigned char)a.at(5) == (unsigned char)0x00)
                 && ((unsigned char)a.at(6) == (unsigned char)0x00) && ((unsigned char)a.at(7) == (unsigned char)0x00)
                 && ((unsigned char)a.at(8) == (unsigned char)0x43) && ((unsigned char)a.at(9) == (unsigned char)0x52)){
            sign[0] = 'I';
            sign[1] = 'I';
            sign[2] = 'C';
            sign[3] = 'R';
            qDebug() << "Canon RAW Format Version 2 or Canon's RAW format is based on TIFF.";
            return "Canon RAW Format Version 2 or Canon's RAW format is based on TIFF.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0xFF) && ((unsigned char)a.at(1) == (unsigned char)0xFE)
                 && ((unsigned char)a.at(2) == (unsigned char)0x00) && ((unsigned char)a.at(3) == (unsigned char)0x00)){
            sign[0] = 'M';
            sign[1] = 'K';
            sign[2] = 'T';
            sign[3] = 'X';
            qDebug() << "Byte-order mark for text file encoded in little-endian 32-bit Unicode Transfer Format.";
            return "Byte-order mark for text file encoded in little-endian 32-bit Unicode Transfer Format.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x46)
                 && ((unsigned char)a.at(8) == (unsigned char)0x57) && ((unsigned char)a.at(9) == (unsigned char)0x45)
                 && ((unsigned char)a.at(10) == (unsigned char)0x42) && ((unsigned char)a.at(11) == (unsigned char)0x50)){
            sign[0] = 'W';
            sign[1] = 'E';
            sign[2] = 'B';
            sign[3] = 'P';
            qDebug() << "Google WebP image file, where ?? ?? ?? ?? is the file size. More information on WebP File Header";
            return "Google WebP image file, where ?? ?? ?? ?? is the file size. More information on WebP File Header";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4B) && ((unsigned char)a.at(1) == (unsigned char)0x44)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4D)){
            sign[0] = 'K';
            sign[1] = 'D';
            sign[2] = 'M';
            qDebug() << "VMDK files";
            return "VMDK files";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x04) && ((unsigned char)a.at(1) == (unsigned char)0x22)
                 && ((unsigned char)a.at(2) == (unsigned char)0x4D) && ((unsigned char)a.at(3) == (unsigned char)0x18)){
            sign[0] = 'L';
            sign[1] = 'Z';
            sign[2] = '4';
            qDebug() << "LZ4 Frame Format";
            return "LZ4 Frame Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x00) && ((unsigned char)a.at(1) == (unsigned char)0x00)
                 && ((unsigned char)a.at(2) == (unsigned char)0x01) && ((unsigned char)a.at(3) == (unsigned char)0x00)){
            sign[0] = 'I';
            sign[1] = 'C';
            sign[2] = 'O';
            qDebug() << "Computer icon encoded in ICO file format";
            return "Computer icon encoded in ICO file format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x42) && ((unsigned char)a.at(1) == (unsigned char)0x5A)
                 && ((unsigned char)a.at(2) == (unsigned char)0x68)){
            sign[0] = 'B';
            sign[1] = 'Z';
            sign[2] = 'h';
            qDebug() << "Compressed file using Bzip2 algorithm";
            return "Compressed file using Bzip2 algorithm";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x42) && ((unsigned char)a.at(1) == (unsigned char)0x41)
                 && ((unsigned char)a.at(2) == (unsigned char)0x43) && ((unsigned char)a.at(3) == (unsigned char)0x4B)
                 && ((unsigned char)a.at(4) == (unsigned char)0x4D) && ((unsigned char)a.at(5) == (unsigned char)0x49)
                 && ((unsigned char)a.at(6) == (unsigned char)0x4B) && ((unsigned char)a.at(7) == (unsigned char)0x45)
                 && ((unsigned char)a.at(8) == (unsigned char)0x44) && ((unsigned char)a.at(9) == (unsigned char)0x49)
                 && ((unsigned char)a.at(10) == (unsigned char)0x53) && ((unsigned char)a.at(11) == (unsigned char)0x4B)){
            sign[0] = 'B';
            sign[1] = 'A';
            sign[2] = 'C';
            qDebug() << "File or tape containing a backup done with AmiBack on an Amiga.";
            return "File or tape containing a backup done with AmiBack on an Amiga.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x1F)){
            if(((unsigned char)a.at(1) == (unsigned char)0xA0)){
                sign[0] = 'T';
                sign[1] = 'A';
                sign[2] = 'R';
                qDebug() << "Compressed file (often tar zip) | using LZH algorithm";
                return "Compressed file (often tar zip) | using LZH algorithm";
            }else if(((unsigned char)a.at(1) == (unsigned char)0x9D)){
                sign[0] = 'T';
                sign[1] = 'A';
                sign[2] = 'R';
                qDebug() << "Compressed file (often tar zip) | using Lempel-Ziv-Welch algorithm";
                return "Compressed file (often tar zip) | using Lempel-Ziv-Welch algorithm";
            }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x66) && ((unsigned char)a.at(1) == (unsigned char)0x74)
                 && ((unsigned char)a.at(2) == (unsigned char)0x79) && ((unsigned char)a.at(3) == (unsigned char)0x70)
                 && ((unsigned char)a.at(4) == (unsigned char)0x33) && ((unsigned char)a.at(5) == (unsigned char)0x67)){
            sign[0] = '3';
            sign[1] = 'G';
            sign[2] = 'P';
            qDebug() << "3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files.";
            return "3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x30) && ((unsigned char)a.at(1) == (unsigned char)0x82)){
            sign[0] = 'D';
            sign[1] = 'E';
            sign[2] = 'R';
            qDebug() << "DER encoded X.509 certificate.";
            return "DER encoded X.509 certificate.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x62) && ((unsigned char)a.at(1) == (unsigned char)0x76)
                 && ((unsigned char)a.at(2) == (unsigned char)0x78) && ((unsigned char)a.at(3) == (unsigned char)0x32)){
            sign[0] = 'l';
            sign[1] = 'z';
            sign[2] = 'f';
            sign[3] = 's';
            qDebug() << "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple.";
            return "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x77) && ((unsigned char)a.at(1) == (unsigned char)0x4F)
                 && ((unsigned char)a.at(2) == (unsigned char)0x46)){
            if(((unsigned char)a.at(3) == (unsigned char)0x46)){
                sign[0] = 'W';
                sign[1] = 'O';
                sign[2] = 'F';
                sign[3] = 'F';
                qDebug() << "WOFF File Format 1.0";
                return "WOFF File Format 1.0";
            }else if(((unsigned char)a.at(3) == (unsigned char)0x32)){
                sign[0] = 'W';
                sign[1] = 'O';
                sign[2] = 'F';
                sign[3] = '2';
                qDebug() << "WOFF File Format 2.0";
                return "WOFF File Format 2.0";
            }
        }else if(((unsigned char)a.at(0) == (unsigned char)0x34) && ((unsigned char)a.at(1) == (unsigned char)0x12)
                 && ((unsigned char)a.at(2) == (unsigned char)0xAA) && ((unsigned char)a.at(3) == (unsigned char)0x55)){
            sign[0] = 'V';
            sign[1] = 'P';
            sign[2] = 'K';
            qDebug() << "VPK file, used to store game data for some Source Engine games";
            return "VPK file, used to store game data for some Source Engine games";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x52) && ((unsigned char)a.at(1) == (unsigned char)0x53)
                 && ((unsigned char)a.at(2) == (unsigned char)0x56) && ((unsigned char)a.at(3) == (unsigned char)0x4B)
                 && ((unsigned char)a.at(4) == (unsigned char)0x44) && ((unsigned char)a.at(5) == (unsigned char)0x41)
                 && ((unsigned char)a.at(6) == (unsigned char)0x54) && ((unsigned char)a.at(7) == (unsigned char)0x41)){
            sign[0] = 'R';
            sign[1] = 'S';
            sign[2] = 'V';
            qDebug() << "QuickZip rs compressed archive";
            return "QuickZip rs compressed archive";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x28) && ((unsigned char)a.at(1) == (unsigned char)0xB5)
                 && ((unsigned char)a.at(2) == (unsigned char)0x2F) && ((unsigned char)a.at(3) == (unsigned char)0xFD)){
            sign[0] = 'Z';
            sign[1] = 'S';
            sign[2] = 'T';
            qDebug() << "Zstandard compressed file";
            return "Zstandard compressed file";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x44) && ((unsigned char)a.at(1) == (unsigned char)0x49)
                 && ((unsigned char)a.at(2) == (unsigned char)0x43) && ((unsigned char)a.at(3) == (unsigned char)0x4D)){
            sign[0] = 'D';
            sign[1] = 'C';
            sign[2] = 'M';
            qDebug() << "DICOM Medical File Format";
            return "DICOM Medical File Format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x45) && ((unsigned char)a.at(1) == (unsigned char)0x4D)
                 && ((unsigned char)a.at(2) == (unsigned char)0x55) && ((unsigned char)a.at(3) == (unsigned char)0x33)){
            sign[0] = 'I';
            sign[1] = 'S';
            sign[2] = 'O';
            qDebug() << "Emulator III synth samples";
            return "Emulator III synth samples";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x50) && ((unsigned char)a.at(1) == (unsigned char)0x41)
                 && ((unsigned char)a.at(2) == (unsigned char)0x52) && ((unsigned char)a.at(3) == (unsigned char)0x31)){
            sign[0] = 'P';
            sign[1] = 'A';
            sign[2] = 'R';
            sign[3] = '1';
            qDebug() << "Apache Parquet columnar file format";
            return "Apache Parquet columnar file format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x78) && ((unsigned char)a.at(1) == (unsigned char)0x56)
                 && ((unsigned char)a.at(2) == (unsigned char)0x34)){
            sign[0] = 'P';
            sign[1] = 'B';
            sign[2] = 'T';
            qDebug() << "PhotoCap Template | pbt, pdt, pea, peb, pet, pgt, pict, pjt, pkt and pmt.";
            return "PhotoCap Template | pbt, pdt, pea, peb, pet, pgt, pict, pjt, pkt and pmt.";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x4F) && ((unsigned char)a.at(1) == (unsigned char)0x62)
                 && ((unsigned char)a.at(2) == (unsigned char)0x6A) && ((unsigned char)a.at(3) == (unsigned char)0x01)){
            sign[0] = 'A';
            sign[1] = 'V';
            sign[2] = 'R';
            sign[3] = 'O';
            qDebug() << "Apache Avro binary file format";
            return "Apache Avro binary file format";
        }else if(((unsigned char)a.at(0) == (unsigned char)0x53) && ((unsigned char)a.at(1) == (unsigned char)0x45)
                 && ((unsigned char)a.at(2) == (unsigned char)0x51) && ((unsigned char)a.at(3) == (unsigned char)0x36)){
            sign[0] = 'R';
            sign[1] = 'C';
            qDebug() << "RCFile columnar file format";
            return "RCFile columnar file format";
        }else{

        }
        return " ";
    }

};


#endif // FILESIGNATURE_H
