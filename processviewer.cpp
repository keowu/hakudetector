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

HANDLE hProcessSnapP;	// will store a snapshot of all processes
HANDLE hProcessP = NULL;	// we will use this one for the WarRock process
PROCESSENTRY32 pe32P;	// stores basic info of a process, using this one to read the ProcessID from

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
    //qDebug() << result;
    if(result == 0){
        qDebug() << "Process Viewer Closed";
    }
}


void ProcessViewer::on_pushButton_clicked()
{
    hProcessSnapP = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );	// Faz um snapshot do processo
    pe32P.dwSize = sizeof( PROCESSENTRY32 );		// Tamanho correto
    do	// loop até encontrar o processo
        {
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
