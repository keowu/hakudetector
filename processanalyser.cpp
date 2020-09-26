#include "processanalyser.h"
#include "ui_processanalyser.h"

#include <qfiledialog.h>

#include <QFile>
#include <qdebug.h>

#include <QMessageBox>

//https://doc.qt.io/qt-5/qfile.html
//

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
    //VM PROTECT FINDER
    for(int i = 0; i<a.length(); i++){
        //VM PROTECT 2.X
        //53 6A 01 68 00 00 40 00 E8 1D 0A FE FF E8
        //?? ?? ??
        //FF 6A 01 6A 00 68 00 00 40 00 E8 0A 0A FE FF C3
        //00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        if(((unsigned char)a.at(i) == (unsigned char)0x53) && ((unsigned char)a.at(i+1) == (unsigned char)0x6A)
                && ((unsigned char)a.at(i+2) == (unsigned char)0x01) && ((unsigned char)a.at(i+3) == (unsigned char)0x68)
                && ((unsigned char)a.at(i+4) == (unsigned char)0x00) && ((unsigned char)a.at(i+5) == (unsigned char)0x00) && ((unsigned char)a.at(i+6) == (unsigned char)0x40)
                && ((unsigned char)a.at(i+7) == (unsigned char)0x00) && ((unsigned char)a.at(i+8) == (unsigned char)0xE8) && ((unsigned char)a.at(i+9) == (unsigned char)0x1D)
                && ((unsigned char)a.at(i+10) == (unsigned char)0x0A) && ((unsigned char)a.at(i+11) == (unsigned char)0xFE) && ((unsigned char)a.at(i+12) == (unsigned char)0xFF)
                && ((unsigned char)a.at(i+13) == (unsigned char)0xE8) && ((unsigned char)a.at(i+17) == (unsigned char)0xFF) && ((unsigned char)a.at(i+18) == (unsigned char)0x6A)
                && ((unsigned char)a.at(i+19) == (unsigned char)0x01) && ((unsigned char)a.at(i+20) == (unsigned char)0x6A) && ((unsigned char)a.at(i+21) == (unsigned char)0x00)
                && ((unsigned char)a.at(i+22) == (unsigned char)0x68)){
                return "VM PROTECT 2.X";
        }
    }
    return "This file no has protector's, try to debbug with x96dbg and IDA :D";
}

void fileSignature(QByteArray a, QString* sign){
    if(!(a.size() > 3)){
        qDebug() << "Image size not is better than 3";
        return;
    }

    if(a.at(0) == 0x4D && a.at(1) == 0x5A){
        sign[0] = 'M';
        sign[1] = 'Z';
        qDebug() << "PE - MZ";
    }else if(a.at(0) == 0x50 && a.at(1) == 0x4B && a.at(2) == 0x03 && a.at(3) == 0x04){
        sign[0] = 'P';
        sign[1] = 'K';
        qDebug() << "ZIP, aar, apk, docx, epub, ipa, jar, kmz, maff, odp, ods, odt, pk3, pk4, pptx, usdz, vsdx, xlsx, xpi";
    }else if(((unsigned char)a.at(0) == (unsigned char)0xFF) && ((unsigned char)a.at(1) == (unsigned char)0xD8)
             && ((unsigned char)a.at(2) == (unsigned char)0xFF) && ((unsigned char)a.at(3) == (unsigned char)0xDB)){
        sign[0] = 'J';
        sign[1] = 'P';
        sign[2] = 'G';
        qDebug() << "JPG OR JPEG IMAGE FILE";
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
    }else if(((unsigned char)a.at(0) == (unsigned char)0x89) && ((unsigned char)a.at(1) == (unsigned char)0x50)
             && ((unsigned char)a.at(2) == (unsigned char)0x4e) && ((unsigned char)a.at(3) == (unsigned char)0x47)){
        sign[0] = 'P';
        sign[1] = 'N';
        sign[2] = 'G';
        qDebug() << "PNG IMAGE FILE";
    }else if(((unsigned char)a.at(0) == (unsigned char)0x47) && ((unsigned char)a.at(1) == (unsigned char)0x49)
             && ((unsigned char)a.at(2) == (unsigned char)0x46) && ((unsigned char)a.at(3) == (unsigned char)0x38)
             && ((unsigned char)a.at(5) == (unsigned char)0x61)){
        if(((unsigned char)a.at(4) == (unsigned char)0x37)){
            sign[0] = 'G';
            sign[1] = 'I';
            sign[2] = 'F';
            sign[3] = '1';
            qDebug() << "PNG IMAGE FILE 1º Generation";
        }else{
            //&& ((unsigned char)a.at(4) == (unsigned char)0x39)
            sign[0] = 'G';
            sign[1] = 'I';
            sign[2] = 'F';
            sign[3] = '2';
            qDebug() << "PNG IMAGE FILE 2º Generation";
        }
    }else if(((unsigned char)a.at(0) == (unsigned char)0x5A) && ((unsigned char)a.at(1) == (unsigned char)0x4D)){
          sign[0] = 'Z';
          sign[1] = 'M';
          qDebug() << "DOS ZM executable file format and its descendants (rare)";
    }else if(((unsigned char)a.at(0) == (unsigned char)0x7F) && ((unsigned char)a.at(1) == (unsigned char)0x45)
             && ((unsigned char)a.at(2) == (unsigned char)0x4C) && ((unsigned char)a.at(3) == (unsigned char)0x46)){
        sign[0] = '.';
        sign[1] = 'E';
        sign[2] = 'L';
        sign[3] = 'F';
        qDebug() << "Executable and Linkable Format";
    }else{

    }
}


void processanalyser::on_pushButton_2_clicked()
{
    QString sign[4] = {"N", "N", " ", " "};
    QString predict = "None";
    ui->listWidget->clear();
    QFile file(pathA);
    QMessageBox::warning(this, "LET'S GO !", "Please be pattient while analise is doing....");
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::critical(this, "Erro", "File is READ ONLY ! try: give me Administrator acess !");
        return;
    }

    QByteArray a = file.readLine();
    fileSignature(a, sign);
    ui->label->setText("About Your file: " + sign[0] + sign[1] + sign[2] + sign[3]);
    predict = protectorAssignature(a);
    ui->label_2->setText(predict);
    //qDebug() << a.toHex();

    while(!file.atEnd()){
        ui->listWidget->addItem(file.readLine().toHex());
    }
}
