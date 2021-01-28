/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2020 by Keowu                                           *
 *                                                                         *
 *   www.joaovitor.gq                                                      *
 *   www.github.com/keowu                                                  *
 *                                                                         *
 ***************************************************************************/
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

void peheadervisualizer::peheadervisualizer_go(){
    QFile file(pathB);
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::warning(this, "Permission error", "Try execute as administrator !");
        return;
    }


    QByteArray header = file.readLine();

    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec = QTextCodec::codecForName("KOI8-R");
    QString string = codec->toUnicode(header.toHex(' '));
    QStringList dos_header = string.split(" ");

    //Populate the table

    QTableWidgetItem *e_magic = new QTableWidgetItem(dos_header[0]+dos_header[1]);
    ui->tblshow->setItem(0, 0, e_magic);
    QTableWidgetItem *e_cblp = new QTableWidgetItem(dos_header[2]+dos_header[3]);
    ui->tblshow->setItem(0, 1, e_cblp);
    QTableWidgetItem *e_cp = new QTableWidgetItem(dos_header[4]+dos_header[5]);
    ui->tblshow->setItem(0, 2, e_cp);
    QTableWidgetItem *e_crlc = new QTableWidgetItem(dos_header[6]+dos_header[7]);
    ui->tblshow->setItem(0, 3, e_crlc);
    QTableWidgetItem *e_cparhdr = new QTableWidgetItem(dos_header[8]+dos_header[9]);
    ui->tblshow->setItem(0, 4, e_cparhdr);
    QTableWidgetItem *e_minalloc = new QTableWidgetItem(dos_header[10]+dos_header[11]);
    ui->tblshow->setItem(0, 5, e_minalloc);
    QTableWidgetItem *e_maxalloc = new QTableWidgetItem(dos_header[12]+dos_header[13]);
    ui->tblshow->setItem(0, 6, e_maxalloc);
    QTableWidgetItem *e_ss = new QTableWidgetItem(dos_header[14]+dos_header[15]);
    ui->tblshow->setItem(0, 7, e_ss);
    QTableWidgetItem *e_sp = new QTableWidgetItem(dos_header[16]+dos_header[17]);
    ui->tblshow->setItem(0, 8, e_sp);
    QTableWidgetItem *e_csum = new QTableWidgetItem(dos_header[18]+dos_header[19]);
    ui->tblshow->setItem(0, 9, e_csum);
    QTableWidgetItem *e_ip = new QTableWidgetItem(dos_header[20]+dos_header[21]);
    ui->tblshow->setItem(0, 10, e_ip);
    QTableWidgetItem *e_cs = new QTableWidgetItem(dos_header[22]+dos_header[23]);
    ui->tblshow->setItem(0, 11, e_cs);
    QTableWidgetItem *e_ifarlc = new QTableWidgetItem(dos_header[24]+dos_header[25]);
    ui->tblshow->setItem(0, 12, e_ifarlc);
    QTableWidgetItem *e_ovno = new QTableWidgetItem(dos_header[26]+dos_header[27]);
    ui->tblshow->setItem(0, 13, e_ovno);
    QTableWidgetItem *e_res = new QTableWidgetItem(dos_header[28]+dos_header[29]);
    ui->tblshow->setItem(0, 14, e_res);

    header = file.readLine();
    //CONVERT A BYTE TO QSTRING
    QTextCodec *codec_op = QTextCodec::codecForName("KOI8-R");
    string = codec_op->toUnicode(header.toHex(' '));
    QStringList optional_header = string.split(" ");

    QTableWidgetItem *magic = new QTableWidgetItem(getOptionalHeaderData(optional_header, 'M'));
    ui->tblshow2->setItem(0, 0, magic);
}

void peheadervisualizer::openFileFromAnotherScreen(QString pathfromanother){
    pathB = pathfromanother;
    peheadervisualizer_go();
}

void peheadervisualizer::on_pushButton_clicked()
{
    pathB = QFileDialog::getOpenFileName(this, tr("Choise a binary file: "), "/", tr("*"));
    peheadervisualizer_go();
}
