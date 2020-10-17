#include "petools.h"
#include "ui_petools.h"
#include <QTextCodec>
#include <qdebug.h>

QByteArray Memorymap = NULL;

petools::petools(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::petools)
{
    ui->setupUi(this);
}

petools::~petools()
{
    delete ui;
}

void petools::setMemoryFile(QByteArray memorymap){
    Memorymap = memorymap;
    QString dados = QString::fromStdString(Memorymap.toStdString());
    qDebug() << "Data in one line :D -> " << dados;
    QRegExp separator(" ");//broken on " "
    QStringList lista = dados.split(separator);
    ui->lstPETOOLSSTR->addItems(lista);
}
