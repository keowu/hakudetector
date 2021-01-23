/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2020 by Keowu                                           *
 *                                                                         *
 *   www.joaovitor.gq                                                      *
 *   www.github.com/keowu                                                  *
 *                                                                         *
 ***************************************************************************/
#include "processanalyser.h"
#include "ui_processanalyser.h"

#include <qfiledialog.h>

#include <QFile>
#include <qdebug.h>

#include <QMessageBox>
#include "petools.h"

#include "peheadervisualizer.h"

QByteArray memoryMAP = NULL;
QString pathA = NULL;
processanalyser::processanalyser(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::processanalyser)
{
    ui->setupUi(this);
    //permitir o drop de arquivos
    setAcceptDrops(true);
}

processanalyser::~processanalyser()
{
    delete ui;
}

void processanalyser::on_pushButton_clicked()
{
   pathA = QFileDialog::getOpenFileName(this, tr("Escolha o arquivo"), "/", tr("*"));
}

void processanalyser::on_pushButton_2_clicked()
{
    QString sign[4] = {"N", "N", " ", " "};
    QString complete_sign = "";
    QString predict = NULL;
    FileSignature *fileSignature = new FileSignature();
    ui->listWidget->clear();
    QFile file(pathA);
    QMessageBox::warning(this, "LET'S GO !", "Please be pattient while analise is doing....");
    if(!file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QMessageBox::critical(this, "Erro", "File is READ ONLY ! try: give me Administrator acess !");
        return;
    }

    QByteArray a = file.readLine();
    memoryMAP +=a;
    complete_sign = fileSignature->fileSignature(a, sign);
    ui->label->setText("About Your file: " + sign[0] + sign[1] + sign[2] + sign[3]);
    ui->label_3->setText(complete_sign);

    if(file.size() > 15000){
        QMessageBox::warning(this, "BIG BIG DETECT", "This file is big, please wait for a seconds...");
    }

    QMessageBox::StandardButton resposta = QMessageBox::question(this, "DETECT PROTECTORS", "would you like to detect possible protectors in the file?");

    PackerProtectDetect *packerProtectDetect = new PackerProtectDetect();

    if(resposta==QMessageBox::Yes){
        while(!file.atEnd()){
            a = file.readLine();
            if(predict == NULL){
                //qDebug() << "Verificando";
                predict = packerProtectDetect->protectorAssignature(a);
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
            memoryMAP +=a;
            ui->listWidget->addItem(a.toHex());
        }
        ui->label_2->setText("A scan was not performed if the file protectors");
    }
}

void processanalyser::on_pushButton_3_clicked()
{
   petools pet;
   pet.setWindowTitle("PE TOOLS");
   pet.setMemoryFile(memoryMAP);
   pet.exec();
}

void processanalyser::on_pushButton_4_clicked()
{
    peheadervisualizer pehv;
    pehv.openFileFromAnotherScreen(pathA);
    pehv.setWindowTitle("From another Process Analysis.");
    pehv.exec();
}

void processanalyser::dropEvent(QDropEvent *event){
    const QMimeData* mimeData=event->mimeData();

    if(mimeData->hasUrls())
    {
        QList<QUrl> urlList=mimeData->urls();

        if(urlList.count())
        {
            QString FileName=urlList.at(0).toLocalFile();

            QMessageBox::warning(this, "Detectado arquivo via drag'n drop", FileName);
            pathA = FileName;
            this->on_pushButton_2_clicked();
        }
    }
}

void processanalyser::dragEnterEvent(QDragEnterEvent *event)
{
    event->acceptProposedAction();
}
