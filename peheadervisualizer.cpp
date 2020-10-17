#include "peheadervisualizer.h"
#include "ui_peheadervisualizer.h"

//INCLUDE WIDGETS
#include <QTableWidgetItem>

#include <qdebug.h>

#include <qfiledialog.h>

#include <QTextCodec>

#include <QMessageBox>

QString pathB = NULL;


peheadervisualizer::peheadervisualizer(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::peheadervisualizer)
{
    ui->setupUi(this);
}

peheadervisualizer::~peheadervisualizer()
{
    delete ui;
}

QString getOptionalHeaderData(QStringList arr2, QChar w){
    int i = 0;
    if(w == 'M'){
        while(i++ < arr2.size()){
            if((arr2[i] == "0b") || (arr2[i+1] == "02")){
               return "PE64";
            }else if((arr2[i] == "0b")||(arr2[i+1] == "01")){
               return "PE32";
            }else if((arr2[i] == "07")||(arr2[i+1] == "01")){
                return "ROM";
            }
        }
        return "UKNOWN";
    }else{
        return "UKNOWN";
    }
}

void peheadervisualizer::openFileFromAnotherScreen(QString pathfromanother){
    pathB = pathfromanother;

    QFile file(pathB);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::warning(this, "Permission error", "Try execute as administrator !");
        return;
    }


    QByteArray header = file.readLine();
    /*
    qDebug() << "e_magic" << (unsigned char)header.at(0) << (unsigned char)header.at(1);
    qDebug() << "e_cblp" << (unsigned char)header.at(2) << (unsigned char)header.at(3);
    qDebug() << "e_cp" << (unsigned char)header.at(4) << (unsigned char)header.at(5);
    qDebug() << "e_crlc" << (unsigned char)header.at(6) << (unsigned char)header.at(7);
    qDebug() << "e_cparhdr" << (unsigned char)header.at(8) << (unsigned char)header.at(9);
    qDebug() << "e_minalloc" << (unsigned char)header.at(10) << (unsigned char)header.at(11);
    qDebug() << "e_maxalloc" << (unsigned char)header.at(12) << (unsigned char)header.at(13);
    qDebug() << "e_ss" << (unsigned char)header.at(14) << (unsigned char)header.at(15);
    qDebug() << "e_sp" << (unsigned char)header.at(16) << (unsigned char)header.at(17);
    qDebug() << "e_csum" << (unsigned char)header.at(18) << (unsigned char)header.at(19);
    qDebug() << "e_ip" << (unsigned char)header.at(20) << (unsigned char)header.at(21);
    qDebug() << "e_cs" << (unsigned char)header.at(22) << (unsigned char)header.at(23);
    qDebug() << "e_ifarlc" << (unsigned char)header.at(24) << (unsigned char)header.at(25);
    qDebug() << "e_ovno" << (unsigned char)header.at(26) << (unsigned char)header.at(27);
    qDebug() << "e_res" << (unsigned char)header.at(28) << (unsigned char)header.at(29);
    //print the full array buffer
    qDebug() << header.toHex();*/

    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec = QTextCodec::codecForName("KOI8-R");
    QString string = codec->toUnicode(header.toHex(' ')); //2 by 2 with spaces like BOBOCA -> B0 B0 CA
    QStringList dos_header = string.split(" "); //split and transform a string to a list like spaces xd

    //Populate the table
    // 0 0
    QTableWidgetItem *e_magic = new QTableWidgetItem(dos_header[0]+dos_header[1]); //YES, DO
    ui->tblshow->setItem(0, 0, e_magic);
    QTableWidgetItem *e_cblp = new QTableWidgetItem(dos_header[2]+dos_header[3]); //YES, DO
    ui->tblshow->setItem(0, 1, e_cblp);
    QTableWidgetItem *e_cp = new QTableWidgetItem(dos_header[4]+dos_header[5]); //YES, DO
    ui->tblshow->setItem(0, 2, e_cp);
    QTableWidgetItem *e_crlc = new QTableWidgetItem(dos_header[6]+dos_header[7]); //YES, DO
    ui->tblshow->setItem(0, 3, e_crlc);
    QTableWidgetItem *e_cparhdr = new QTableWidgetItem(dos_header[8]+dos_header[9]); //YES, DO
    ui->tblshow->setItem(0, 4, e_cparhdr);
    QTableWidgetItem *e_minalloc = new QTableWidgetItem(dos_header[10]+dos_header[11]); //YES, DO
    ui->tblshow->setItem(0, 5, e_minalloc);
    QTableWidgetItem *e_maxalloc = new QTableWidgetItem(dos_header[12]+dos_header[13]); //YES, DO
    ui->tblshow->setItem(0, 6, e_maxalloc);
    QTableWidgetItem *e_ss = new QTableWidgetItem(dos_header[14]+dos_header[15]); //YES, DO
    ui->tblshow->setItem(0, 7, e_ss);
    QTableWidgetItem *e_sp = new QTableWidgetItem(dos_header[16]+dos_header[17]); //YES, DO
    ui->tblshow->setItem(0, 8, e_sp);
    QTableWidgetItem *e_csum = new QTableWidgetItem(dos_header[18]+dos_header[19]); //YES, DO
    ui->tblshow->setItem(0, 9, e_csum);
    QTableWidgetItem *e_ip = new QTableWidgetItem(dos_header[20]+dos_header[21]); //YES, DO
    ui->tblshow->setItem(0, 10, e_ip);
    QTableWidgetItem *e_cs = new QTableWidgetItem(dos_header[22]+dos_header[23]); //YES, DO
    ui->tblshow->setItem(0, 11, e_cs);
    QTableWidgetItem *e_ifarlc = new QTableWidgetItem(dos_header[24]+dos_header[25]); //YES, DO
    ui->tblshow->setItem(0, 12, e_ifarlc);
    QTableWidgetItem *e_ovno = new QTableWidgetItem(dos_header[26]+dos_header[27]); //YES, DO
    ui->tblshow->setItem(0, 13, e_ovno);
    QTableWidgetItem *e_res = new QTableWidgetItem(dos_header[28]+dos_header[29]); //YES, DO
    ui->tblshow->setItem(0, 14, e_res);

    header = file.readLine();
    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec_op = QTextCodec::codecForName("KOI8-R");
    string = codec_op->toUnicode(header.toHex(' ')); //2 by 2 with spaces like BOBOCA -> B0 B0 CA
    QStringList optional_header = string.split(" "); //split and transform a string to a list like spaces xd

    //qDebug() << header.toHex();
    //QString magic_ref = getOptionalHeaderData(optional_header, 'M');
    //qDebug() << magic_ref;

    QTableWidgetItem *magic = new QTableWidgetItem(getOptionalHeaderData(optional_header, 'M')); //YES, DO
    ui->tblshow2->setItem(0, 0, magic);
}

void peheadervisualizer::on_pushButton_clicked()
{
    pathB = QFileDialog::getOpenFileName(this, tr("Choise a binary file: "), "/", tr("*"));
    QFile file(pathB);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::warning(this, "Permission error", "Try execute as administrator !");
        return;
    }


    QByteArray header = file.readLine();
    /*
    qDebug() << "e_magic" << (unsigned char)header.at(0) << (unsigned char)header.at(1);
    qDebug() << "e_cblp" << (unsigned char)header.at(2) << (unsigned char)header.at(3);
    qDebug() << "e_cp" << (unsigned char)header.at(4) << (unsigned char)header.at(5);
    qDebug() << "e_crlc" << (unsigned char)header.at(6) << (unsigned char)header.at(7);
    qDebug() << "e_cparhdr" << (unsigned char)header.at(8) << (unsigned char)header.at(9);
    qDebug() << "e_minalloc" << (unsigned char)header.at(10) << (unsigned char)header.at(11);
    qDebug() << "e_maxalloc" << (unsigned char)header.at(12) << (unsigned char)header.at(13);
    qDebug() << "e_ss" << (unsigned char)header.at(14) << (unsigned char)header.at(15);
    qDebug() << "e_sp" << (unsigned char)header.at(16) << (unsigned char)header.at(17);
    qDebug() << "e_csum" << (unsigned char)header.at(18) << (unsigned char)header.at(19);
    qDebug() << "e_ip" << (unsigned char)header.at(20) << (unsigned char)header.at(21);
    qDebug() << "e_cs" << (unsigned char)header.at(22) << (unsigned char)header.at(23);
    qDebug() << "e_ifarlc" << (unsigned char)header.at(24) << (unsigned char)header.at(25);
    qDebug() << "e_ovno" << (unsigned char)header.at(26) << (unsigned char)header.at(27);
    qDebug() << "e_res" << (unsigned char)header.at(28) << (unsigned char)header.at(29);
    //print the full array buffer
    qDebug() << header.toHex();*/

    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec = QTextCodec::codecForName("KOI8-R");
    QString string = codec->toUnicode(header.toHex(' ')); //2 by 2 with spaces like BOBOCA -> B0 B0 CA
    QStringList dos_header = string.split(" "); //split and transform a string to a list like spaces xd

    //Populate the table
    // 0 0
    QTableWidgetItem *e_magic = new QTableWidgetItem(dos_header[0]+dos_header[1]); //YES, DO
    ui->tblshow->setItem(0, 0, e_magic);
    QTableWidgetItem *e_cblp = new QTableWidgetItem(dos_header[2]+dos_header[3]); //YES, DO
    ui->tblshow->setItem(0, 1, e_cblp);
    QTableWidgetItem *e_cp = new QTableWidgetItem(dos_header[4]+dos_header[5]); //YES, DO
    ui->tblshow->setItem(0, 2, e_cp);
    QTableWidgetItem *e_crlc = new QTableWidgetItem(dos_header[6]+dos_header[7]); //YES, DO
    ui->tblshow->setItem(0, 3, e_crlc);
    QTableWidgetItem *e_cparhdr = new QTableWidgetItem(dos_header[8]+dos_header[9]); //YES, DO
    ui->tblshow->setItem(0, 4, e_cparhdr);
    QTableWidgetItem *e_minalloc = new QTableWidgetItem(dos_header[10]+dos_header[11]); //YES, DO
    ui->tblshow->setItem(0, 5, e_minalloc);
    QTableWidgetItem *e_maxalloc = new QTableWidgetItem(dos_header[12]+dos_header[13]); //YES, DO
    ui->tblshow->setItem(0, 6, e_maxalloc);
    QTableWidgetItem *e_ss = new QTableWidgetItem(dos_header[14]+dos_header[15]); //YES, DO
    ui->tblshow->setItem(0, 7, e_ss);
    QTableWidgetItem *e_sp = new QTableWidgetItem(dos_header[16]+dos_header[17]); //YES, DO
    ui->tblshow->setItem(0, 8, e_sp);
    QTableWidgetItem *e_csum = new QTableWidgetItem(dos_header[18]+dos_header[19]); //YES, DO
    ui->tblshow->setItem(0, 9, e_csum);
    QTableWidgetItem *e_ip = new QTableWidgetItem(dos_header[20]+dos_header[21]); //YES, DO
    ui->tblshow->setItem(0, 10, e_ip);
    QTableWidgetItem *e_cs = new QTableWidgetItem(dos_header[22]+dos_header[23]); //YES, DO
    ui->tblshow->setItem(0, 11, e_cs);
    QTableWidgetItem *e_ifarlc = new QTableWidgetItem(dos_header[24]+dos_header[25]); //YES, DO
    ui->tblshow->setItem(0, 12, e_ifarlc);
    QTableWidgetItem *e_ovno = new QTableWidgetItem(dos_header[26]+dos_header[27]); //YES, DO
    ui->tblshow->setItem(0, 13, e_ovno);
    QTableWidgetItem *e_res = new QTableWidgetItem(dos_header[28]+dos_header[29]); //YES, DO
    ui->tblshow->setItem(0, 14, e_res);

    header = file.readLine();
    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec_op = QTextCodec::codecForName("KOI8-R");
    string = codec_op->toUnicode(header.toHex(' ')); //2 by 2 with spaces like BOBOCA -> B0 B0 CA
    QStringList optional_header = string.split(" "); //split and transform a string to a list like spaces xd

    //qDebug() << header.toHex();
    //QString magic_ref = getOptionalHeaderData(optional_header, 'M');
    //qDebug() << magic_ref;

    QTableWidgetItem *magic = new QTableWidgetItem(getOptionalHeaderData(optional_header, 'M')); //YES, DO
    ui->tblshow2->setItem(0, 0, magic);

}
