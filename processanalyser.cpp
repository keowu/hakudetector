#include "processanalyser.h"
#include "ui_processanalyser.h"

#include <qfiledialog.h>

#include <QFile>
#include <qdebug.h>

#include <QMessageBox>

QString pathA = NULL;
processanalyser::processanalyser(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::processanalyser)
{
    ui->setupUi(this);
}

processanalyser::~processanalyser()
{
    delete ui;
}

void processanalyser::on_pushButton_clicked()
{
   pathA = QFileDialog::getOpenFileName(this, tr("Escolha o arquivo"), "/", tr("*"));
}

QString protectorAssignature(QByteArray a){
    //qDebug() << "PROTECTORS";
    QString ret = NULL;
    int i = 0;
    if(!(a.size() > 3)){
        qDebug() << "Image size not is better than 3";
        return ret;
    }

    while(i < a.length()){
        if(((unsigned char)a.at(i) == (unsigned char)0x60)){
            //0  1            5  6  7          11
            //60 BE ?? ?? ?? 00 8D BE ?? ?? ?? FF
            // ?? = Variant byte
            // www.fluxuss.ga
            if(((unsigned char)a.at(i+1) == (unsigned char)0xBE) && ((unsigned char)a.at(i+5) == (unsigned char)0x00)
                && ((unsigned char)a.at(i+6) == (unsigned char)0x8D) && ((unsigned char)a.at(i+7) == (unsigned char)0xBE)
                && ((unsigned char)a.at(i+11) == (unsigned char)0xFF)){
                ret = "UPX of www.upx.sourceforge.net | IS EASY TO UNPACK, JUST FIND THE JMP";
            }
        }

        i++;
    }

    return ret;
}

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
    }else{

    }
    return " ";
}


void processanalyser::on_pushButton_2_clicked()
{
    QString sign[4] = {"N", "N", " ", " "};
    QString complete_sign = "";
    QString predict = NULL;
    ui->listWidget->clear();
    QFile file(pathA);
    QMessageBox::warning(this, "LET'S GO !", "Please be pattient while analise is doing....");
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::critical(this, "Erro", "File is READ ONLY ! try: give me Administrator acess !");
        return;
    }

    QByteArray a = file.readLine();
    complete_sign = fileSignature(a, sign);
    ui->label->setText("About Your file: " + sign[0] + sign[1] + sign[2] + sign[3]);
    ui->label_3->setText(complete_sign);

    if(file.size() > 15000){
        QMessageBox::warning(this, "BIG BIG DETECT", "This file is big, please wait for a seconds...");
    }

    QMessageBox::StandardButton resposta = QMessageBox::question(this, "DETECT PROTECTORS", "would you like to detect possible protectors in the file?");

    if(resposta==QMessageBox::Yes){
        while(!file.atEnd()){
            a = file.readLine();
            if(predict == NULL){
                //qDebug() << "Verificando";
                predict = protectorAssignature(a);
            }
            ui->listWidget->addItem(a.toHex());
        }

        if(predict == NULL){
            ui->label_2->setText("This file no has protector's, try to debbug with x96dbg and IDA :D");
        }else{
            ui->label_2->setText(predict);
        }
    }else{
        while(!file.atEnd()){
            a = file.readLine();
            ui->listWidget->addItem(a.toHex());
        }
        ui->label_2->setText("A scan was not performed if the file protectors");
    }


}
