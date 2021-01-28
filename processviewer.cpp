/***************************************************************************
 *                                                                         *
 *   Copyright (C) 2020 by Keowu                                           *
 *                                                                         *
 *   www.joaovitor.gq                                                      *
 *   www.github.com/keowu                                                  *
 *                                                                         *
 ***************************************************************************/
#include "processviewer.h"
#include "ui_processviewer.h"

#include "stdio.h"
#include <windows.h>
#include <conio.h>
#include <dos.h>
#include <tlhelp32.h>
#include <stdio.h>

//qdebug
#include <qdebug.h>

HANDLE hProcessSnapP;
HANDLE hProcessP = NULL;
PROCESSENTRY32 pe32P;

ProcessViewer::ProcessViewer(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProcessViewer)
{
    ui->setupUi(this);
}

ProcessViewer::~ProcessViewer()
{
    delete ui;
}

void ProcessViewer::on_ProcessViewer_finished(int result)
{
    if(result == 0){
        qDebug() << "Process Viewer Closed";
    }
}


void ProcessViewer::on_pushButton_clicked()
{
    hProcessSnapP = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    pe32P.dwSize = sizeof( PROCESSENTRY32 );
    do{
            QString processo = "PROCESS NAME: " + QString::fromWCharArray(pe32P.szExeFile) + " | PID: " + QString::number(pe32P.th32ProcessID);

            if(processo == "svchost.exe"){
                ui->listWidget->addItem(processo);
                qDebug() << "SVC HOST FINDDED";
            }else{
                ui->listWidget->addItem(processo);
            }


        }
     while(Process32Next(hProcessSnapP, &pe32P));
}
