/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2020 by Keowu                                           *
 *                                                                         *
 *   www.joaovitor.gq                                                      *
 *   www.github.com/keowu                                                  *
 *                                                                         *
 ***************************************************************************/

#include "injecttools.h"
#include "ui_injecttools.h"
#include <QLibrary>
#include <qmessagebox.h>

injecttools::injecttools(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::injecttools)
{
    ui->setupUi(this);
}

injecttools::~injecttools()
{
    delete ui;
}

QLibrary wannahaku("C:\\Users\\Joao\\Documents\\GitHub\\hakudetector\\WannaHakuLib\\x64\\Release\\WannaHakuLib.dll");

typedef void (*blockUserTask)(void);
typedef void (*BSOD_DEATH)(void);
typedef void (*helloworld)(void);

void blockUserTasks(){
    blockUserTask functionblock = (blockUserTask)wannahaku.resolve("blockUserTask");
    if (functionblock)
        functionblock();
}


void BSOD_DEATH_inv(){
    BSOD_DEATH functionbsod = (BSOD_DEATH)wannahaku.resolve("BSOD_DEATH");
    if(functionbsod)
        functionbsod();
}


void injecttools::isUSERANDMIN(bool op){
    if(op){
        ui->label->setText("Running on administrator mode !");
        ui->pushButton->setEnabled(true);
        ui->pushButton_2->setEnabled(true);
        ui->pushButton_3->setEnabled(true);
        ui->pushButton_4->setEnabled(true);
        ui->pushButton_5->setEnabled(true);
    }else{
        ui->label->setText("NOT IS ADMIN !");
    }
}

void injecttools::on_pushButton_5_clicked()
{
    helloworld helloworldfunct = (helloworld)wannahaku.resolve("helloworld");
    if(helloworldfunct){
        helloworldfunct();
    }
}

void injecttools::on_pushButton_clicked()
{
    BSOD_DEATH_inv();
}

void injecttools::on_pushButton_2_clicked()
{
    blockUserTasks();
}
