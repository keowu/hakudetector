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
    //print the full array buffer
    qDebug() << header.toHex();*/

    //CONVERT A BYTE TO QSTRING :D
    QTextCodec *codec = QTextCodec::codecForName("KOI8-R");
    QString string = codec->toUnicode(header.toHex(' ')); //2 by 2 with spaces like BOBOCA -> BO BO CA
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

}




















